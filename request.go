package csocks

import (
	"bufio"
	"context"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"
)

var replayMap = newNonceReplayCache()

type negotiationRequest struct {
	net.Conn
	Method   byte
	Address  string
	Listener net.Listener
}

type sniffedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *sniffedConn) Read(p []byte) (int, error) {
	if c.reader != nil && c.reader.Buffered() > 0 {
		return c.reader.Read(p)
	}
	return c.Conn.Read(p)
}

type dummyAddr string

func (a dummyAddr) Network() string {
	return "h2"
}

func (a dummyAddr) String() string {
	return string(a)
}

type h2StreamConn struct {
	ctx     context.Context
	cancel  context.CancelFunc
	reader  io.Reader
	writer  io.Writer
	flusher http.Flusher
	remote  string
	writeMu sync.Mutex
}

func newH2StreamConn(
	ctx context.Context,
	reader io.Reader,
	writer io.Writer,
	flusher http.Flusher,
	remote string,
) *h2StreamConn {
	streamCtx, cancel := context.WithCancel(ctx)

	return &h2StreamConn{
		ctx:     streamCtx,
		cancel:  cancel,
		reader:  reader,
		writer:  writer,
		flusher: flusher,
		remote:  remote,
	}
}

func (c *h2StreamConn) Read(p []byte) (int, error) {
	select {
	case <-c.ctx.Done():
		return 0, c.ctx.Err()
	default:
		return c.reader.Read(p)
	}
}

func (c *h2StreamConn) Write(p []byte) (int, error) {
	select {
	case <-c.ctx.Done():
		return 0, c.ctx.Err()
	default:
	}

	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	n, err := c.writer.Write(p)
	if c.flusher != nil {
		c.flusher.Flush()
	}

	return n, err
}

func (c *h2StreamConn) Close() error {
	if c.cancel != nil {
		c.cancel()
	}
	return nil
}

func (c *h2StreamConn) LocalAddr() net.Addr {
	return dummyAddr("h2-local")
}

func (c *h2StreamConn) RemoteAddr() net.Addr {
	if c.remote == "" {
		return dummyAddr("h2-remote")
	}
	return dummyAddr(c.remote)
}

func (c *h2StreamConn) SetDeadline(time.Time) error {
	return nil
}

func (c *h2StreamConn) SetReadDeadline(time.Time) error {
	return nil
}

func (c *h2StreamConn) SetWriteDeadline(time.Time) error {
	return nil
}

type nonceReplayCache struct {
	mu    sync.Mutex
	items map[string]time.Time
}

func newNonceReplayCache() *nonceReplayCache {
	return &nonceReplayCache{
		items: make(map[string]time.Time),
	}
}

func (c *nonceReplayCache) SeenOrAdd(nonce string, ttl time.Duration) bool {
	now := time.Now()

	c.mu.Lock()
	defer c.mu.Unlock()

	for k, exp := range c.items {
		if now.After(exp) {
			delete(c.items, k)
		}
	}

	if exp, ok := c.items[nonce]; ok && now.Before(exp) {
		return true
	}

	c.items[nonce] = now.Add(ttl)
	return false
}

func newServerTLSConfig(serverCertFile, serverKeyFile, publicKeyFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(serverCertFile, serverKeyFile)
	if err != nil {
		return nil, err
	}

	if len(cert.Certificate) == 0 {
		return nil, errors.New("no certificates found")
	}

	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, err
	}

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(x509Cert.PublicKey)
	if err != nil {
		return nil, err
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	if strings.TrimSpace(publicKeyFile) == "" {
		publicKeyFile = "public.key"
	}

	if err := os.WriteFile(publicKeyFile, pemBytes, 0644); err != nil {
		return nil, err
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
		NextProtos:   []string{protoH2, protoHTTP1},
	}, nil
}

func proxy(ctx context.Context, listenConfig *ListenConfig) error {
	tlsCfg, err := newServerTLSConfig(
		listenConfig.ServerCertFile,
		listenConfig.ServerKeyFile,
		listenConfig.PublicKeyFile,
	)
	if err != nil {
		return err
	}

	ln, err := listen(listenConfig.ListenPort)
	if err != nil {
		return err
	}

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	if listenConfig.WithHttp {
		logger.Printf("[*] socks5/http proxy listen on: [%s]", listenConfig.ListenPort)
	} else {
		logger.Printf("[*] socks5 proxy listen on: [%s]", listenConfig.ListenPort)
	}

	for {
		conn0, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				logger.PrintfX("[*] proxy stopped\n")
				return nil
			}
			logger.Printf("[x] accept error [%s]\n", err.Error())
			continue
		}

		logger.PrintfX("[+] new client [%s] connected [%s]\n",
			conn0.RemoteAddr().String(),
			conn0.LocalAddr().String(),
		)

		go handleRequest(ctx, conn0, listenConfig, tlsCfg)
	}
}

func handleRequest(ctx context.Context, conn0 net.Conn, listenConfig *ListenConfig, tlsCfg *tls.Config) {
	defer conn0.Close()

	reader := bufio.NewReader(conn0)

	_ = conn0.SetReadDeadline(time.Now().Add(3 * time.Second))
	first, err := reader.Peek(1)
	_ = conn0.SetReadDeadline(time.Time{})

	if err != nil {
		logger.PrintfX("[x] sniff request failed from [%s]: [%s]\n",
			conn0.RemoteAddr().String(),
			err.Error(),
		)
		return
	}

	if isLikelyPlainHTTPFirstByte(first[0]) {
		handlePlainHTTPFallback(conn0, reader)
		return
	}

	if first[0] != 0x16 {
		logger.PrintfX("[x] unknown first byte from [%s]: [0x%02x]\n",
			conn0.RemoteAddr().String(),
			first[0],
		)
		return
	}

	tlsConn, err := tlsHandshake(&sniffedConn{
		Conn:   conn0,
		reader: reader,
	}, tlsCfg)
	if err != nil {
		logger.PrintfX("[x] failed to handshake: [%s]\n", err.Error())
		return
	}

	defer tlsConn.Close()

	state := tlsConn.ConnectionState()

	switch state.NegotiatedProtocol {
	case protoH2:
		handleH2Conn(ctx, tlsConn, listenConfig)

	case protoHTTP1, "":
		handleHTTP1Conn(ctx, tlsConn, listenConfig)

	default:
		logger.PrintfX("[x] unsupported ALPN protocol: [%s]\n", state.NegotiatedProtocol)
	}
}

func isLikelyPlainHTTPFirstByte(b byte) bool {
	switch b {
	case 'G', // GET
		'P', // POST / PUT / PATCH / PRI
		'H', // HEAD
		'O', // OPTIONS
		'D', // DELETE
		'T', // TRACE
		'C': // CONNECT
		return true
	default:
		return false
	}
}

func handlePlainHTTPFallback(conn net.Conn, reader *bufio.Reader) {
	_ = conn.SetReadDeadline(time.Now().Add(8 * time.Second))
	req, err := http.ReadRequest(reader)
	_ = conn.SetReadDeadline(time.Time{})

	if err != nil {
		logger.PrintfX("[x] plain http request read failed from [%s]: [%s]\n",
			conn.RemoteAddr().String(),
			err.Error(),
		)
		return
	}

	defer req.Body.Close()

	writeFallbackHTTP(conn, req)
}

func tlsHandshake(conn0 net.Conn, tlsCfg *tls.Config) (*tls.Conn, error) {
	tlsConn := tls.Server(conn0, tlsCfg)

	if err := tlsConn.SetDeadline(time.Now().Add(time.Duration(timeout) * time.Second)); err != nil {
		return nil, err
	}

	if err := tlsConn.Handshake(); err != nil {
		return nil, err
	}

	if err := tlsConn.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}

	state := tlsConn.ConnectionState()

	logger.PrintfX("[*] TLS version used: %d, ALPN: %s\n",
		state.Version,
		state.NegotiatedProtocol,
	)

	return tlsConn, nil
}

func handleHTTP1Conn(ctx context.Context, tlsConn *tls.Conn, listenConfig *ListenConfig) {
	done := make(chan struct{})

	go func() {
		select {
		case <-ctx.Done():
			_ = tlsConn.Close()
		case <-done:
		}
	}()

	defer close(done)

	reader, ok, err := authHTTP1Request(tlsConn, listenConfig)
	if err != nil {
		logger.PrintfX("[x] http1 auth/read failed from [%s]: [%s]\n",
			tlsConn.RemoteAddr().String(),
			err.Error(),
		)
		return
	}

	if !ok {
		return
	}

	negReq, err := parseRequest(tlsConn, reader, listenConfig.WithHttp)
	if err != nil {
		if err != io.EOF {
			logger.Printf("[x] parse request error [%s]\n", err.Error())
		}
		return
	}

	switch negReq.Method {
	case methodSocks5:
		handleSocks5(ctx, negReq)

	case methodHttp:
		handleHttpRequest(ctx, negReq)

	default:
		_ = negReq.Conn.Close()
	}
}

func authHTTP1Request(tlsConn *tls.Conn, listenConfig *ListenConfig) (*bufio.Reader, bool, error) {
	reader := bufio.NewReader(tlsConn)

	_ = tlsConn.SetReadDeadline(time.Now().Add(8 * time.Second))
	req, err := http.ReadRequest(reader)
	_ = tlsConn.SetReadDeadline(time.Time{})

	if err != nil {
		return reader, false, err
	}

	defer req.Body.Close()

	if !validateHTTP1TunnelRequest(req, listenConfig) {
		writeFallbackHTTP(tlsConn, req)
		return reader, false, nil
	}

	if _, err := tlsConn.Write([]byte(
		"HTTP/1.1 101 Switching Protocols\r\n" +
			"Connection: Upgrade\r\n" +
			"Upgrade: " + tunnelUpgradeToken + "\r\n" +
			"Cache-Control: no-store\r\n" +
			"\r\n",
	)); err != nil {
		return reader, false, err
	}

	return reader, true, nil
}

func handleH2Conn(ctx context.Context, tlsConn *tls.Conn, listenConfig *ListenConfig) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handleH2Request(ctx, listenConfig, w, r)
	})

	server := &http2.Server{
		MaxConcurrentStreams: maxClientH2Streams,

		// 不做运行时健康检查。空闲连接由 IdleTimeout 关闭。
		IdleTimeout: 30 * time.Second,

		MaxUploadBufferPerConnection: 1 << 20,
		MaxUploadBufferPerStream:     256 << 10,
	}

	server.ServeConn(tlsConn, &http2.ServeConnOpts{
		Handler: handler,
	})
}

func handleH2Request(
	ctx context.Context,
	listenConfig *ListenConfig,
	w http.ResponseWriter,
	r *http.Request,
) {
	if r.URL == nil || r.URL.Path != tunnelPath {
		writeFallbackHTTPResponse(w, r)
		return
	}

	if !validateH2TunnelRequest(r, listenConfig) {
		writeFallbackHTTPResponse(w, r)
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	streamCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	go func() {
		select {
		case <-r.Context().Done():
			cancel()
		case <-streamCtx.Done():
		}
	}()

	streamConn := newH2StreamConn(
		streamCtx,
		r.Body,
		w,
		flusher,
		r.RemoteAddr,
	)

	defer streamConn.Close()
	defer r.Body.Close()

	negReq, err := parseRequest(streamConn, bufio.NewReader(streamConn), listenConfig.WithHttp)
	if err != nil {
		if err != io.EOF {
			logger.PrintfX("[x] h2 parse request error: [%s]\n", err.Error())
		}
		return
	}

	switch negReq.Method {
	case methodSocks5:
		handleSocks5(streamCtx, negReq)

	case methodHttp:
		handleHttpRequest(streamCtx, negReq)

	default:
		_ = negReq.Conn.Close()
	}
}

func validateHTTP1TunnelRequest(req *http.Request, listenConfig *ListenConfig) bool {
	if req.Method != http.MethodGet {
		return false
	}

	if req.URL == nil || req.URL.Path != tunnelPath {
		return false
	}

	if !headerContainsToken(req.Header.Get("Connection"), "Upgrade") {
		return false
	}

	if !strings.EqualFold(req.Header.Get("Upgrade"), tunnelUpgradeToken) {
		return false
	}

	return validateTunnelSignature(req, listenConfig, protoHTTP1, true)
}

func validateH2TunnelRequest(req *http.Request, listenConfig *ListenConfig) bool {
	if req.ProtoMajor != 2 {
		return false
	}

	if req.Method != http.MethodPost {
		return false
	}

	if req.URL == nil || req.URL.Path != tunnelPath {
		return false
	}

	return validateTunnelSignature(req, listenConfig, protoH2, false)
}

func validateTunnelSignature(
	req *http.Request,
	listenConfig *ListenConfig,
	proto string,
	allowLegacy bool,
) bool {
	nonce := strings.TrimSpace(req.Header.Get(headerSessionID))
	if nonce == "" || len(nonce) > 128 {
		return false
	}

	tsText := strings.TrimSpace(req.Header.Get(headerRequestTime))
	ts, err := strconv.ParseInt(tsText, 10, 64)
	if err != nil {
		return false
	}

	now := time.Now().Unix()
	if ts < now-authClockSkewSeconds || ts > now+authClockSkewSeconds {
		return false
	}

	gotSig := strings.TrimSpace(req.Header.Get(headerRequestSignature))
	if gotSig == "" || len(gotSig) > 256 {
		return false
	}

	expectedV2 := makeTunnelAuthSignatureV2(
		listenConfig.Secret,
		req.Method,
		req.URL.Path,
		req.Host,
		nonce,
		ts,
		proto,
	)

	valid := subtle.ConstantTimeCompare([]byte(gotSig), []byte(expectedV2)) == 1

	if !valid && allowLegacy {
		expectedV1 := makeTunnelAuthSignature(
			listenConfig.Secret,
			req.URL.Path,
			req.Host,
			nonce,
			ts,
		)

		valid = subtle.ConstantTimeCompare([]byte(gotSig), []byte(expectedV1)) == 1
	}

	if !valid {
		return false
	}

	if replayMap.SeenOrAdd(nonce, time.Duration(authClockSkewSeconds)*time.Second) {
		return false
	}

	return true
}

func writeFallbackHTTP(conn net.Conn, req *http.Request) {
	path := "/"
	if req != nil && req.URL != nil {
		path = req.URL.Path
	}

	status := "200 OK"
	body := "<!doctype html><html><head><meta charset=\"utf-8\"><title>Welcome</title></head><body><h1>Welcome</h1></body></html>"

	if path == "/favicon.ico" {
		resp := "HTTP/1.1 204 No Content\r\n" +
			"Date: " + time.Now().UTC().Format(http.TimeFormat) + "\r\n" +
			"Cache-Control: public, max-age=86400\r\n" +
			"Connection: close\r\n" +
			"\r\n"

		_, _ = conn.Write([]byte(resp))
		return
	}

	if path != "/" && path != "/index.html" {
		status = "404 Not Found"
		body = "<!doctype html><html><head><meta charset=\"utf-8\"><title>Not Found</title></head><body><h1>404 Not Found</h1></body></html>"
	}

	resp := fmt.Sprintf(
		"HTTP/1.1 %s\r\n"+
			"Date: %s\r\n"+
			"Content-Type: text/html; charset=utf-8\r\n"+
			"Content-Length: %d\r\n"+
			"Cache-Control: no-cache\r\n"+
			"Connection: close\r\n"+
			"\r\n"+
			"%s",
		status,
		time.Now().UTC().Format(http.TimeFormat),
		len(body),
		body,
	)

	_, _ = conn.Write([]byte(resp))
}

func writeFallbackHTTPResponse(w http.ResponseWriter, req *http.Request) {
	path := "/"
	if req != nil && req.URL != nil {
		path = req.URL.Path
	}

	if path == "/favicon.ico" {
		w.Header().Set("Cache-Control", "public, max-age=86400")
		w.WriteHeader(http.StatusNoContent)
		return
	}

	body := "<!doctype html><html><head><meta charset=\"utf-8\"><title>Welcome</title></head><body><h1>Welcome</h1></body></html>"

	if path != "/" && path != "/index.html" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("<!doctype html><html><head><meta charset=\"utf-8\"><title>Not Found</title></head><body><h1>404 Not Found</h1></body></html>"))
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(body))
}

func parseRequest(c net.Conn, r *bufio.Reader, withHttp bool) (*negotiationRequest, error) {
	if r == nil {
		r = bufio.NewReader(c)
	}

	b0, err := r.Peek(1)
	if err != nil {
		return nil, err
	}

	if b0[0] == 0x05 {
		var hdr [2]byte

		if _, err := io.ReadFull(r, hdr[:]); err != nil {
			return nil, err
		}

		if hdr[0] != 0x05 {
			return nil, errors.New("invalid socks5 version")
		}

		nMethods := int(hdr[1])
		if nMethods <= 0 {
			return nil, errors.New("invalid socks5 nmethods")
		}

		methods := make([]byte, nMethods)

		if _, err := io.ReadFull(r, methods); err != nil {
			return nil, err
		}

		hasNoAuth := false

		for _, m := range methods {
			if m == 0x00 {
				hasNoAuth = true
				break
			}
		}

		if !hasNoAuth {
			_, _ = c.Write([]byte{0x05, 0xFF})
			return nil, errors.New("no acceptable auth method")
		}

		if _, err := c.Write([]byte{0x05, 0x00}); err != nil {
			return nil, err
		}

		var reqHdr [4]byte

		if _, err := io.ReadFull(r, reqHdr[:]); err != nil {
			return nil, err
		}

		if reqHdr[0] != 0x05 {
			return nil, errors.New("invalid socks5 request version")
		}

		if reqHdr[1] != 0x01 {
			writeSocks5Reply(c, 0x07)
			return nil, errors.New("unsupported socks5 command")
		}

		atyp := reqHdr[3]
		var host string

		switch atyp {
		case 0x01:
			var addr [4]byte

			if _, err := io.ReadFull(r, addr[:]); err != nil {
				return nil, err
			}

			host = net.IP(addr[:]).String()

		case 0x04:
			var addr [16]byte

			if _, err := io.ReadFull(r, addr[:]); err != nil {
				return nil, err
			}

			host = net.IP(addr[:]).String()

		case 0x03:
			lb, err := r.ReadByte()
			if err != nil {
				return nil, err
			}

			l := int(lb)
			if l <= 0 {
				return nil, errors.New("invalid domain length")
			}

			domain := make([]byte, l)

			if _, err := io.ReadFull(r, domain); err != nil {
				return nil, err
			}

			host = string(domain)

		default:
			writeSocks5Reply(c, 0x08)
			return nil, errors.New("unsupported socks5 address type")
		}

		var pb [2]byte

		if _, err := io.ReadFull(r, pb[:]); err != nil {
			return nil, err
		}

		port := int(binary.BigEndian.Uint16(pb[:]))

		return &negotiationRequest{
			Conn:    c,
			Method:  methodSocks5,
			Address: net.JoinHostPort(host, strconv.Itoa(port)),
		}, nil
	}

	if withHttp {
		return &negotiationRequest{
			Conn:     c,
			Method:   methodHttp,
			Listener: newConnListener(c, r),
		}, nil
	}

	return nil, errors.New("unsupported protocol")
}

func handleSocks5(ctx context.Context, negotiationRequest *negotiationRequest) {
	conn1, err := net.DialTimeout("tcp", negotiationRequest.Address, time.Duration(timeout)*time.Second)
	if err != nil {
		logger.PrintfX("[x] connect [%s] error [%s]\n",
			negotiationRequest.Address,
			err.Error(),
		)

		writeSocks5Reply(negotiationRequest.Conn, 0x05)
		return
	}

	logger.PrintfX("[+] connect to [%s] success\n", negotiationRequest.Address)

	writeSocks5Reply(negotiationRequest.Conn, 0x00)

	mutualCopyIO(ctx, negotiationRequest.Conn, conn1)

	logger.PrintfX("[-] client [%s] disconnected\n",
		negotiationRequest.Conn.RemoteAddr().String(),
	)
}

func writeSocks5Reply(conn net.Conn, rep byte) {
	_, _ = conn.Write([]byte{
		0x05,
		rep,
		0x00,
		0x01,
		0x00,
		0x00,
		0x00,
		0x00,
		0x00,
		0x00,
	})
}

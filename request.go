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
)

var (
	tlsConfig *tls.Config
	replayMap = newNonceReplayCache()
)

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

func setTLSConfig(serverCertFile, serverKeyFile, publicKeyFile string) error {
	cert, err := tls.LoadX509KeyPair(serverCertFile, serverKeyFile)
	if err != nil {
		return err
	}
	if len(cert.Certificate) == 0 {
		return errors.New("no certificates found")
	}

	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return err
	}

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(x509Cert.PublicKey)
	if err != nil {
		return err
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	if strings.TrimSpace(publicKeyFile) == "" {
		publicKeyFile = "public.key"
	}
	if err := os.WriteFile(publicKeyFile, pemBytes, 0644); err != nil {
		return err
	}

	tlsConfig = &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,

		// 第一阶段只走 HTTP/1.1 Upgrade。
		// 不要加 h2，否则客户端发 HTTP/1.1 文本时可能和 ALPN 协商结果不一致。
		NextProtos: []string{"http/1.1"},
	}

	return nil
}

func proxy(ctx context.Context, listenConfig *ListenConfig) error {
	if err := setTLSConfig(
		listenConfig.ServerCertFile,
		listenConfig.ServerKeyFile,
		listenConfig.PublicKeyFile,
	); err != nil {
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
		logger.Printf("[*] https/http fallback & socks5/http proxy listen on: [%s]", listenConfig.ListenPort)
	} else {
		logger.Printf("[*] https/http fallback & socks5 proxy listen on: [%s]", listenConfig.ListenPort)
	}

	for {
		logger.PrintfX("[*] waiting for client to connect [%s %s]\n",
			ln.Addr().Network(),
			ln.Addr().String(),
		)

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

		go handleRequest(ctx, conn0, listenConfig)
	}
}

func handleRequest(ctx context.Context, conn0 net.Conn, listenConfig *ListenConfig) {
	defer conn0.Close()

	reader := bufio.NewReader(conn0)

	// 同端口识别：
	// - TLS ClientHello 第一个字节通常是 0x16
	// - 明文 HTTP 第一个字节通常是 G/P/H/O/D/T/C
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
	})
	if err != nil {
		logger.PrintfX("[x] Failed to handshake: [%s]\n", err.Error())
		return
	}
	defer tlsConn.Close()

	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = tlsConn.Close()
		case <-done:
		}
	}()
	defer close(done)

	reader, ok, err := authRequest(tlsConn, listenConfig)
	if err != nil {
		logger.PrintfX("[x] auth/http request read failed from [%s]: [%s]\n",
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

func tlsHandshake(conn0 net.Conn) (*tls.Conn, error) {
	tlsConn := tls.Server(conn0, tlsConfig)

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
	logger.PrintfX("[*] TLS version used: %d\n", state.Version)

	return tlsConn, nil
}

func authRequest(tlsConn *tls.Conn, listenConfig *ListenConfig) (*bufio.Reader, bool, error) {
	reader := bufio.NewReader(tlsConn)

	_ = tlsConn.SetReadDeadline(time.Now().Add(8 * time.Second))
	req, err := http.ReadRequest(reader)
	_ = tlsConn.SetReadDeadline(time.Time{})

	if err != nil {
		return reader, false, err
	}
	defer req.Body.Close()

	if !validateTunnelRequest(req, listenConfig) {
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

func validateTunnelRequest(req *http.Request, listenConfig *ListenConfig) bool {
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

	if replayMap.SeenOrAdd(nonce, time.Duration(authClockSkewSeconds)*time.Second) {
		return false
	}

	gotSig := strings.TrimSpace(req.Header.Get(headerRequestSignature))
	if gotSig == "" || len(gotSig) > 256 {
		return false
	}

	expectedSig := makeTunnelAuthSignature(
		listenConfig.Secret,
		req.URL.Path,
		req.Host,
		nonce,
		ts,
	)

	return subtle.ConstantTimeCompare([]byte(gotSig), []byte(expectedSig)) == 1
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

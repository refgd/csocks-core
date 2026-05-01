package csocks

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"
)

type forwardProtocol byte

const (
	forwardProtocolUnknown forwardProtocol = iota
	forwardProtocolH2
	forwardProtocolHTTP1
)

type forwardRuntime struct {
	mu       sync.Mutex
	protocol forwardProtocol

	h2Client *http.Client
	h1TLSCfg *tls.Config

	streamSem chan struct{}
}

type uploadCountingWriter struct {
	w io.Writer
}

func (w uploadCountingWriter) Write(p []byte) (int, error) {
	n, err := w.w.Write(p)
	if n > 0 {
		recordBytesUp(uint64(n))
	}
	return n, err
}

type downloadCountingWriter struct {
	w io.Writer
}

func (w downloadCountingWriter) Write(p []byte) (int, error) {
	n, err := w.w.Write(p)
	if n > 0 {
		recordBytesDown(uint64(n))
	}
	return n, err
}

func forward(ctx context.Context, listenConfig *ListenConfig) error {
	knownPubKey, err := loadKnownPublicKey(listenConfig.PublicKeyFile)
	if err != nil {
		return err
	}

	sessionCache := tls.NewLRUClientSessionCache(128)

	h2TLSCfg := newForwardTLSClientConfig(
		knownPubKey,
		sessionCache,
		listenConfig.ServerAddress,
		[]string{protoH2, protoHTTP1},
	)

	h1TLSCfg := newForwardTLSClientConfig(
		knownPubKey,
		sessionCache,
		listenConfig.ServerAddress,
		[]string{protoHTTP1},
	)

	h2Client, err := newH2Client(h2TLSCfg)
	if err != nil {
		return err
	}

	runtime := &forwardRuntime{
		protocol:  forwardProtocolUnknown,
		h2Client:  h2Client,
		h1TLSCfg:  h1TLSCfg,
		streamSem: make(chan struct{}, maxClientH2Streams),
	}

	protocol, err := bootstrapStartupProtocol(ctx, listenConfig, runtime)
	if err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return err
	}

	runtime.protocol = protocol

	// bootstrap 只是启动前检查；检查成功后关闭 idle，后续真正使用代理时再连接服务器。
	closeH2IdleConnections(h2Client)

	ln, err := listen(listenConfig.ListenPort)
	if err != nil {
		return err
	}

	go func() {
		<-ctx.Done()
		_ = ln.Close()
		closeH2IdleConnections(h2Client)
	}()

	switch protocol {
	case forwardProtocolH2:
		logger.Printf("[*] selected forward protocol: HTTP/2 streaming tunnel\n")
	case forwardProtocolHTTP1:
		logger.Printf("[*] selected forward protocol: HTTP/1.1 upgrade fallback\n")
	}

	logger.Printf("[*] listen on: [%s %s] server on: [%s]\n",
		ln.Addr().Network(),
		ln.Addr().String(),
		listenConfig.ServerAddress,
	)

	for {
		conn0, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				logger.PrintfX("[*] forward stopped\n")
				return nil
			}
			logger.Printf("[x] accept error [%s]\n", err.Error())
			continue
		}

		logger.PrintfX("[+] new client [%s] connected [%s]\n",
			conn0.RemoteAddr().String(),
			conn0.LocalAddr().String(),
		)

		go handleForwardLazy(ctx, listenConfig, conn0, runtime)
	}
}

func bootstrapStartupProtocol(
	ctx context.Context,
	listenConfig *ListenConfig,
	runtime *forwardRuntime,
) (forwardProtocol, error) {
	protocol, err := detectForwardProtocol(
		ctx,
		listenConfig,
		runtime.h2Client,
		runtime.h1TLSCfg,
	)
	if err != nil {
		if ctx.Err() != nil {
			return forwardProtocolUnknown, ctx.Err()
		}
		return forwardProtocolUnknown, fmt.Errorf("server bootstrap check failed: %w", err)
	}

	return protocol, nil
}

func handleForwardLazy(
	ctx context.Context,
	listenConfig *ListenConfig,
	conn0 net.Conn,
	runtime *forwardRuntime,
) {
	protocol, err := runtime.ensureProtocol(ctx, listenConfig)
	if err != nil {
		logger.PrintfX("[x] protocol detect failed: [%s]\n", err.Error())
		_ = writeLocalProxyError(conn0)
		return
	}

	switch protocol {
	case forwardProtocolH2:
		if err := handleForwardH2Limited(ctx, listenConfig, conn0, runtime); err != nil {
			logger.PrintfX("[x] h2 stream failed: [%s]\n", err.Error())
			runtime.resetProtocolIfCurrent(forwardProtocolH2)
		}

	case forwardProtocolHTTP1:
		if err := handleForwardHTTP1(ctx, listenConfig, conn0, runtime.h1TLSCfg); err != nil {
			logger.PrintfX("[x] http1 tunnel failed: [%s]\n", err.Error())
			runtime.resetProtocolIfCurrent(forwardProtocolHTTP1)
		}

	default:
		_ = writeLocalProxyError(conn0)
	}
}

func (r *forwardRuntime) ensureProtocol(
	ctx context.Context,
	listenConfig *ListenConfig,
) (forwardProtocol, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.protocol != forwardProtocolUnknown {
		return r.protocol, nil
	}

	protocol, err := detectForwardProtocol(ctx, listenConfig, r.h2Client, r.h1TLSCfg)
	if err != nil {
		return forwardProtocolUnknown, err
	}

	r.protocol = protocol

	switch protocol {
	case forwardProtocolH2:
		logger.Printf("[*] selected forward protocol: HTTP/2 streaming tunnel\n")
	case forwardProtocolHTTP1:
		logger.Printf("[*] selected forward protocol: HTTP/1.1 upgrade fallback\n")
	}

	return protocol, nil
}

func (r *forwardRuntime) resetProtocolIfCurrent(protocol forwardProtocol) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.protocol == protocol {
		r.protocol = forwardProtocolUnknown
		closeH2IdleConnections(r.h2Client)
	}
}

func detectForwardProtocol(
	ctx context.Context,
	listenConfig *ListenConfig,
	h2Client *http.Client,
	h1TLSCfg *tls.Config,
) (forwardProtocol, error) {
	if err := probeH2TunnelSession(ctx, listenConfig, h2Client); err == nil {
		return forwardProtocolH2, nil
	} else {
		logger.PrintfX("[x] h2 probe failed: [%s]\n", err.Error())
	}

	if err := probeHTTP1TunnelSession(ctx, listenConfig, h1TLSCfg); err == nil {
		return forwardProtocolHTTP1, nil
	} else {
		return forwardProtocolUnknown, fmt.Errorf("server probe failed: %w", err)
	}
}

func loadKnownPublicKey(publicKeyFile string) ([]byte, error) {
	pemBytes, err := loadPublicKey(publicKeyFile)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("failed to parse public key")
	}

	if _, err := x509.ParsePKIXPublicKey(block.Bytes); err != nil {
		return nil, errors.New("invalid public key file")
	}

	return block.Bytes, nil
}

func newForwardTLSClientConfig(
	knownPubKey []byte,
	sessionCache tls.ClientSessionCache,
	serverAddress string,
	nextProtos []string,
) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,

		// 这里使用 SPKI pinning，所以跳过系统 CA 链校验。
		InsecureSkipVerify: true,

		NextProtos:         nextProtos,
		ServerName:         serverNameFromAddress(serverAddress),
		ClientSessionCache: sessionCache,

		// VerifyConnection 会在 resumed TLS session 上继续执行；
		// 不要用 VerifyPeerCertificate 做 pinning。
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 {
				return errors.New("no server certificate")
			}

			serverPubKeyBytes, err := x509.MarshalPKIXPublicKey(state.PeerCertificates[0].PublicKey)
			if err != nil {
				return err
			}

			if !bytes.Equal(serverPubKeyBytes, knownPubKey) {
				return errors.New("server public key mismatch")
			}

			return nil
		},
	}
}

func newH2Client(tlsCfg *tls.Config) (*http.Client, error) {
	tr := &http.Transport{
		TLSClientConfig: tlsCfg,

		ForceAttemptHTTP2: true,

		// 一个 host 尽量只保留一个 h2 连接，通过多 stream 承载并发。
		MaxConnsPerHost:     1,
		MaxIdleConns:        8,
		MaxIdleConnsPerHost: 1,

		// 不做运行时健康检查；空闲一段时间自动关闭。
		IdleConnTimeout: 20 * time.Second,
	}

	if err := http2.ConfigureTransport(tr); err != nil {
		return nil, err
	}

	return &http.Client{
		Transport: tr,
		Timeout:   0,
	}, nil
}

func closeH2IdleConnections(client *http.Client) {
	if client == nil || client.Transport == nil {
		return
	}

	if tr, ok := client.Transport.(*http.Transport); ok {
		tr.CloseIdleConnections()
	}
}

func probeH2TunnelSession(
	ctx context.Context,
	listenConfig *ListenConfig,
	client *http.Client,
) error {
	probeCtx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
	defer cancel()

	req, err := newH2TunnelRequest(probeCtx, listenConfig, strings.NewReader(""))
	if err != nil {
		return err
	}
	req.ContentLength = 0

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.ProtoMajor != 2 {
		return fmt.Errorf("server did not negotiate h2: %s", resp.Proto)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("h2 tunnel rejected: %s", resp.Status)
	}

	_, _ = io.Copy(io.Discard, resp.Body)

	return nil
}

func handleForwardH2Limited(
	ctx context.Context,
	listenConfig *ListenConfig,
	conn0 net.Conn,
	runtime *forwardRuntime,
) error {
	select {
	case runtime.streamSem <- struct{}{}:
		defer func() { <-runtime.streamSem }()

	case <-ctx.Done():
		_ = conn0.Close()
		return ctx.Err()

	default:
		recordStreamFail()
		_ = writeLocalProxyError(conn0)
		return errors.New("too many active h2 streams")
	}

	return handleForwardH2(ctx, listenConfig, conn0, runtime.h2Client)
}

func handleForwardH2(
	ctx context.Context,
	listenConfig *ListenConfig,
	conn0 net.Conn,
	client *http.Client,
) error {
	defer conn0.Close()

	recordStreamStart()
	defer recordStreamEnd()

	streamCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	pr, pw := io.Pipe()

	req, err := newH2TunnelRequest(streamCtx, listenConfig, pr)
	if err != nil {
		recordStreamFail()
		_ = pw.CloseWithError(err)
		_ = writeLocalProxyError(conn0)
		return err
	}

	local := newDeadlineConn(conn0, 60*time.Second)

	uploadDone := make(chan struct{})

	go func() {
		defer close(uploadDone)

		_, copyErr := io.Copy(uploadCountingWriter{w: pw}, local)
		_ = pw.CloseWithError(copyErr)
	}()

	resp, err := client.Do(req)
	if err != nil {
		recordStreamFail()
		cancel()
		_ = pr.CloseWithError(err)
		_ = pw.CloseWithError(err)
		_ = conn0.Close()
		<-uploadDone
		return err
	}

	defer resp.Body.Close()

	if resp.ProtoMajor != 2 {
		recordStreamFail()
		cancel()
		_ = conn0.Close()
		<-uploadDone
		return fmt.Errorf("unexpected response protocol: %s", resp.Proto)
	}

	if resp.StatusCode != http.StatusOK {
		recordStreamFail()
		cancel()
		_ = conn0.Close()
		<-uploadDone
		return fmt.Errorf("h2 tunnel rejected: %s", resp.Status)
	}

	_, _ = io.Copy(downloadCountingWriter{w: local}, resp.Body)

	cancel()
	_ = conn0.Close()
	<-uploadDone

	logger.PrintfX("[-] client [%s] disconnected\n", conn0.RemoteAddr().String())

	return nil
}

func newH2TunnelRequest(
	ctx context.Context,
	listenConfig *ListenConfig,
	body io.Reader,
) (*http.Request, error) {
	host := hostHeaderFromAddress(listenConfig.ServerAddress)
	url := "https://" + host + tunnelPath

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, body)
	if err != nil {
		return nil, err
	}

	nonce, err := randomNonce()
	if err != nil {
		return nil, err
	}

	ts := time.Now().Unix()

	signature := makeTunnelAuthSignatureV2(
		listenConfig.Secret,
		http.MethodPost,
		tunnelPath,
		host,
		nonce,
		ts,
		protoH2,
	)

	req.Host = host
	req.ContentLength = -1

	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Pragma", "no-cache")
	req.Header.Set(headerSessionID, nonce)
	req.Header.Set(headerRequestTime, strconv.FormatInt(ts, 10))
	req.Header.Set(headerRequestSignature, signature)

	return req, nil
}

func handleForwardHTTP1(
	ctx context.Context,
	listenConfig *ListenConfig,
	conn0 net.Conn,
	tlsCfg *tls.Config,
) error {
	defer conn0.Close()

	done := make(chan struct{})

	go func() {
		select {
		case <-ctx.Done():
			_ = conn0.Close()
		case <-done:
		}
	}()

	defer close(done)

	conn1, err := dialTLSConn(ctx, listenConfig.ServerAddress, tlsCfg)
	if err != nil {
		logger.Printf("[x] connect [%s] error [%s]\n",
			listenConfig.ServerAddress,
			err.Error(),
		)
		_ = writeLocalProxyError(conn0)
		return err
	}

	defer conn1.Close()

	go func() {
		select {
		case <-ctx.Done():
			_ = conn1.Close()
		case <-done:
		}
	}()

	if err := writeTunnelUpgradeRequest(conn1, listenConfig); err != nil {
		logger.Printf("[x] tunnel upgrade request failed: [%s]\n", err.Error())
		return err
	}

	if err := readTunnelUpgradeResponse(conn1); err != nil {
		logger.PrintfX("[x] tunnel upgrade response error: [%s]\n", err.Error())
		return err
	}

	mutualCopyIO(ctx, conn0, conn1)

	logger.PrintfX("[-] client [%s] disconnected\n", conn0.RemoteAddr().String())

	return nil
}

func dialTLSConn(ctx context.Context, address string, tlsCfg *tls.Config) (*tls.Conn, error) {
	dialer := &net.Dialer{
		Timeout: time.Duration(timeout) * time.Second,
	}

	rawConn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}

	conn := tls.Client(rawConn, tlsCfg)

	if err := conn.SetDeadline(time.Now().Add(time.Duration(timeout) * time.Second)); err != nil {
		_ = rawConn.Close()
		return nil, err
	}

	if err := conn.Handshake(); err != nil {
		_ = rawConn.Close()
		return nil, err
	}

	if err := conn.SetDeadline(time.Time{}); err != nil {
		_ = conn.Close()
		return nil, err
	}

	return conn, nil
}

func probeHTTP1TunnelSession(
	ctx context.Context,
	listenConfig *ListenConfig,
	tlsCfg *tls.Config,
) error {
	probeCtx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
	defer cancel()

	conn1, err := dialTLSConn(probeCtx, listenConfig.ServerAddress, tlsCfg)
	if err != nil {
		return err
	}

	defer conn1.Close()

	if err := writeTunnelUpgradeRequest(conn1, listenConfig); err != nil {
		return err
	}

	if err := readTunnelUpgradeResponse(conn1); err != nil {
		return err
	}

	primeTLSSessionTicket(conn1)

	return nil
}

func primeTLSSessionTicket(conn net.Conn) {
	_ = conn.SetReadDeadline(time.Now().Add(150 * time.Millisecond))

	var b [1]byte
	_, _ = conn.Read(b[:])

	_ = conn.SetReadDeadline(time.Time{})
}

func writeTunnelUpgradeRequest(conn net.Conn, listenConfig *ListenConfig) error {
	nonce, err := randomNonce()
	if err != nil {
		return err
	}

	ts := time.Now().Unix()
	host := hostHeaderFromAddress(listenConfig.ServerAddress)

	signature := makeTunnelAuthSignatureV2(
		listenConfig.Secret,
		http.MethodGet,
		tunnelPath,
		host,
		nonce,
		ts,
		protoHTTP1,
	)

	req := fmt.Sprintf(
		"GET %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36\r\n"+
			"Accept: */*\r\n"+
			"Accept-Language: en-US,en;q=0.9\r\n"+
			"Cache-Control: no-cache\r\n"+
			"Pragma: no-cache\r\n"+
			"Connection: Upgrade\r\n"+
			"Upgrade: %s\r\n"+
			"%s: %s\r\n"+
			"%s: %d\r\n"+
			"%s: %s\r\n"+
			"Content-Length: 0\r\n"+
			"\r\n",
		tunnelPath,
		host,
		tunnelUpgradeToken,
		headerSessionID,
		nonce,
		headerRequestTime,
		ts,
		headerRequestSignature,
		signature,
	)

	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, err = conn.Write([]byte(req))
	_ = conn.SetWriteDeadline(time.Time{})

	return err
}

func readTunnelUpgradeResponse(conn net.Conn) error {
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	defer func() { _ = conn.SetReadDeadline(time.Time{}) }()

	br := bufio.NewReader(conn)

	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusSwitchingProtocols {
		return errors.New("tunnel upgrade rejected")
	}

	if !headerContainsToken(resp.Header.Get("Connection"), "Upgrade") {
		return errors.New("invalid upgrade response")
	}

	if !bytes.EqualFold([]byte(resp.Header.Get("Upgrade")), []byte(tunnelUpgradeToken)) {
		return errors.New("invalid upgrade token")
	}

	return nil
}

func randomNonce() (string, error) {
	var b [16]byte

	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// 不再固定写 SOCKS5 错误字节，避免 HTTP 本地代理客户端收到乱码。
// 这里统一关闭连接，最安全。
func writeLocalProxyError(conn net.Conn) error {
	if conn == nil {
		return nil
	}
	return conn.Close()
}

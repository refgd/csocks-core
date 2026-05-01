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
	"time"

	"golang.org/x/net/http2"
)

type forwardProtocol byte

const (
	forwardProtocolH2 forwardProtocol = iota + 1
	forwardProtocolHTTP1
)

type forwardRuntime struct {
	protocol forwardProtocol
	h2Client *http.Client
	h1TLSCfg *tls.Config
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

	runtime, err := bootstrapForwardRuntime(ctx, listenConfig, h2TLSCfg, h1TLSCfg)
	if err != nil {
		if ctx.Err() != nil {
			return nil
		}
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

	switch runtime.protocol {
	case forwardProtocolH2:
		logger.Printf("[*] forward protocol: HTTP/2 streaming tunnel\n")
	case forwardProtocolHTTP1:
		logger.Printf("[*] forward protocol: HTTP/1.1 upgrade fallback\n")
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

		switch runtime.protocol {
		case forwardProtocolH2:
			go handleForwardH2(ctx, listenConfig, conn0, runtime.h2Client)

		case forwardProtocolHTTP1:
			go handleForwardHTTP1(ctx, listenConfig, conn0, runtime.h1TLSCfg)

		default:
			_ = conn0.Close()
		}
	}
}

func bootstrapForwardRuntime(
	ctx context.Context,
	listenConfig *ListenConfig,
	h2TLSCfg *tls.Config,
	h1TLSCfg *tls.Config,
) (*forwardRuntime, error) {
	h2Client, err := newH2Client(h2TLSCfg)
	if err == nil {
		if err := bootstrapH2TunnelSession(ctx, listenConfig, h2Client); err == nil {
			return &forwardRuntime{
				protocol: forwardProtocolH2,
				h2Client: h2Client,
				h1TLSCfg: h1TLSCfg,
			}, nil
		} else {
			logger.PrintfX("[x] h2 bootstrap failed: [%s]\n", err.Error())
		}
	} else {
		logger.PrintfX("[x] h2 client init failed: [%s]\n", err.Error())
	}

	if err := bootstrapHTTP1TunnelSession(ctx, listenConfig, h1TLSCfg); err != nil {
		if ctx.Err() != nil {
			return nil, nil
		}
		return nil, fmt.Errorf("server bootstrap check failed: %w", err)
	}

	return &forwardRuntime{
		protocol: forwardProtocolHTTP1,
		h2Client: h2Client,
		h1TLSCfg: h1TLSCfg,
	}, nil
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

		InsecureSkipVerify: true,

		NextProtos:         nextProtos,
		ServerName:         serverNameFromAddress(serverAddress),
		ClientSessionCache: sessionCache,

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
		TLSClientConfig:     tlsCfg,
		ForceAttemptHTTP2:   true,
		MaxIdleConns:        128,
		MaxIdleConnsPerHost: 128,
		IdleConnTimeout:     90 * time.Second,
	}

	if err := http2.ConfigureTransport(tr); err != nil {
		return nil, err
	}

	return &http.Client{
		Transport: tr,
		Timeout:   0,
	}, nil
}

func bootstrapH2TunnelSession(
	ctx context.Context,
	listenConfig *ListenConfig,
	client *http.Client,
) error {
	bootstrapCtx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
	defer cancel()

	req, err := newH2TunnelRequest(bootstrapCtx, listenConfig, strings.NewReader(""))
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

func handleForwardH2(
	ctx context.Context,
	listenConfig *ListenConfig,
	conn0 net.Conn,
	client *http.Client,
) {
	defer conn0.Close()

	streamCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	pr, pw := io.Pipe()

	req, err := newH2TunnelRequest(streamCtx, listenConfig, pr)
	if err != nil {
		_ = pw.CloseWithError(err)
		_ = writeLocalProxyError(conn0)
		return
	}

	local := newDeadlineConn(conn0, 60*time.Second)

	uploadDone := make(chan struct{})

	go func() {
		defer close(uploadDone)
		_, copyErr := io.Copy(pw, local)
		_ = pw.CloseWithError(copyErr)
	}()

	resp, err := client.Do(req)
	if err != nil {
		cancel()
		_ = pr.CloseWithError(err)
		_ = pw.CloseWithError(err)
		_ = writeLocalProxyError(conn0)
		return
	}
	defer resp.Body.Close()

	if resp.ProtoMajor != 2 {
		cancel()
		_ = writeLocalProxyError(conn0)
		return
	}

	if resp.StatusCode != http.StatusOK {
		cancel()
		_ = writeLocalProxyError(conn0)
		return
	}

	_, _ = io.Copy(local, resp.Body)

	cancel()
	_ = conn0.Close()
	<-uploadDone

	logger.PrintfX("[-] client [%s] disconnected\n", conn0.RemoteAddr().String())
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
) {
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
		return
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
		return
	}

	if err := readTunnelUpgradeResponse(conn1); err != nil {
		logger.PrintfX("[x] tunnel upgrade response error: [%s]\n", err.Error())
		return
	}

	mutualCopyIO(ctx, conn0, conn1)

	logger.PrintfX("[-] client [%s] disconnected\n", conn0.RemoteAddr().String())
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

func bootstrapHTTP1TunnelSession(
	ctx context.Context,
	listenConfig *ListenConfig,
	tlsCfg *tls.Config,
) error {
	conn1, err := dialTLSConn(ctx, listenConfig.ServerAddress, tlsCfg)
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

func writeLocalProxyError(conn net.Conn) error {
	_, err := conn.Write([]byte{0x05, 0x01})
	return err
}

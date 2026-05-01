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
	"net"
	"net/http"
	"time"
)

func forward(ctx context.Context, listenConfig *ListenConfig) error {
	knownPubKey, err := loadKnownPublicKey(listenConfig.PublicKeyFile)
	if err != nil {
		return err
	}

	sessionCache := tls.NewLRUClientSessionCache(128)
	tlsCfg := newForwardTLSClientConfig(
		knownPubKey,
		sessionCache,
		listenConfig.ServerAddress,
	)

	// Optional warm-up: make one authenticated tunnel handshake first,
	// so later connections have a better chance to use TLS session resumption.
	if err := bootstrapTunnelSession(ctx, listenConfig, tlsCfg); err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return fmt.Errorf("bootstrap tunnel session failed: %w", err)
	}

	ln, err := listen(listenConfig.ListenPort)
	if err != nil {
		return err
	}

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	logger.Printf("[*] listen on: [%s %s] server on: [%s]\n",
		ln.Addr().Network(),
		ln.Addr().String(),
		listenConfig.ServerAddress,
	)

	for {
		logger.PrintfX("[*] waiting for client to connect [%s %s]\n",
			ln.Addr().Network(),
			ln.Addr().String(),
		)

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

		go handleForward(ctx, listenConfig, conn0, tlsCfg)
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
) *tls.Config {
	return &tls.Config{
		// TLS 1.2 + 1.3 looks more normal than TLS 1.3-only.
		// If you only want TLS 1.3, change MinVersion to tls.VersionTLS13.
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,

		// We do SPKI pinning ourselves in VerifyConnection.
		InsecureSkipVerify: true,

		// First stage uses HTTP/1.1 Upgrade, so do not advertise h2 here.
		NextProtos: []string{"http/1.1"},

		ServerName:         serverNameFromAddress(serverAddress),
		ClientSessionCache: sessionCache,

		// Important:
		// VerifyPeerCertificate is not called on resumed TLS sessions.
		// VerifyConnection is called on all connections, including resumption.
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

func handleForward(
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

func bootstrapTunnelSession(
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

	// TLS 1.3 session tickets can arrive after the handshake.
	// Do a tiny best-effort read to give crypto/tls a chance to process them.
	// Timeout is ignored because the server is not expected to send app data here.
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

	signature := makeTunnelAuthSignature(
		listenConfig.Secret,
		tunnelPath,
		host,
		nonce,
		ts,
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

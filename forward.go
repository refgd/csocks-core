package csocks

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"time"
)

func forward(ctx context.Context, listenConfig *ListenConfig) error {
	knownPubKey, err := loadKnownPublicKey(listenConfig.PublicKeyFile)
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

	logger.Printf("[*] listen on: [%s %s] server on: [%s]\n", ln.Addr().Network(), ln.Addr().String(), listenConfig.ServerAddress)

	for {
		logger.PrintfX("[*] waiting for client to connect [%s %s]\n", ln.Addr().Network(), ln.Addr().String())
		conn0, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				logger.PrintfX("[*] forward stopped\n")
				return nil
			}
			logger.Printf("[x] accept error [%s]\n", err.Error())
			continue
		}
		logger.PrintfX("[+] new client [%s] connected [%s]\n", conn0.RemoteAddr().String(), conn0.LocalAddr().String())
		go handleForward(ctx, listenConfig, conn0, knownPubKey)
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

	// Validate bytes are a real PKIX public key
	if _, err := x509.ParsePKIXPublicKey(block.Bytes); err != nil {
		return nil, errors.New("invalid public key file")
	}

	return block.Bytes, nil
}

func handleForward(ctx context.Context, listenConfig *ListenConfig, conn0 net.Conn, knownPubKey []byte) {
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

	dialer := &net.Dialer{Timeout: time.Duration(timeout) * time.Second}
	rawConn, err := dialer.DialContext(ctx, "tcp", listenConfig.ServerAddress)
	if err != nil {
		logger.Printf("[x] connect [%s] error [%s]\n", listenConfig.ServerAddress, err.Error())
		_, _ = conn0.Write([]byte(err.Error()))
		return
	}
	defer rawConn.Close()

	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,

		InsecureSkipVerify: true,

		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("no server certificate")
			}
			cert, err := x509.ParseCertificate(rawCerts[0]) // leaf
			if err != nil {
				return err
			}
			serverPubKeyBytes, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
			if err != nil {
				return err
			}
			if !bytes.Equal(serverPubKeyBytes, knownPubKey) {
				return errors.New("server public key mismatch")
			}
			return nil
		},
	}

	conn1 := tls.Client(rawConn, tlsCfg)
	defer conn1.Close()

	go func() {
		select {
		case <-ctx.Done():
			_ = conn1.Close()
		case <-done:
		}
	}()

	_ = conn1.SetDeadline(time.Now().Add(time.Duration(timeout) * time.Second))
	if err := conn1.Handshake(); err != nil {
		logger.Printf("[x] handshake failed: [%s]\n", err.Error())
		return
	}
	_ = conn1.SetDeadline(time.Time{})

	// Send secret
	if _, err := conn1.Write([]byte(listenConfig.Secret + "\n")); err != nil {
		logger.Printf("[x] failed to send secret: [%s]\n", err.Error())
		return
	}

	if err := readAuthReply(conn1, 5*time.Second); err != nil {
		logger.PrintfX("[x] authentication reply error: [%s]\n", err.Error())
		return
	}

	mutualCopyIO(ctx, conn0, conn1)

	logger.PrintfX("[-] client [%s] disconnected\n", conn0.RemoteAddr().String())
}

func readAuthReply(c net.Conn, timeout time.Duration) error {
	if err := c.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}
	defer func() { _ = c.SetReadDeadline(time.Time{}) }()

	var b [1]byte
	if _, err := io.ReadFull(c, b[:]); err != nil {
		return err
	}
	if b[0] != replySuccess {
		return errors.New("authentication failed")
	}
	return nil
}

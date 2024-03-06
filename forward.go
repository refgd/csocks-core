package csocks

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"os"
	"time"
)

func forward(listenConfig *ListenConfig) error {
	pemBytes, err := os.ReadFile("public.key")
	if err != nil {
		return err
	}

	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "PUBLIC KEY" {
		return errors.New("failed to parse public key")
	}

	ln, err := listen(listenConfig.ListenPort)
	if err != nil {
		return err
	}

	logger.Printf("[*] listen on: [%s %s] server on: [%s]\n", ln.Addr().Network(), ln.Addr().String(), listenConfig.ServerAddress)
	for {
		logger.PrintfX("[*] waiting for client to connect [%s %s]\n", ln.Addr().Network(), ln.Addr().String())
		conn0, err := ln.Accept()
		if err != nil {
			logger.Printf("[x] accept error [%s]\n", err.Error())
			continue
		}
		logger.PrintfX("[+] new client [%s] connected [%s]\n", conn0.RemoteAddr().String(), conn0.LocalAddr().String())

		go handleForward(listenConfig, conn0, block.Bytes)
	}
}

func handleForward(listenConfig *ListenConfig, conn0 net.Conn, publicKey []byte) {
	dialer := &net.Dialer{Timeout: time.Duration(timeout) * time.Second}
	conn, err := dialer.Dial("tcp", listenConfig.ServerAddress)
	if err != nil {
		logger.Printf("[x] connect [%s] error [%s]\n", listenConfig.ServerAddress, err.Error())
		_, _ = conn0.Write([]byte(err.Error()))
		return
	}

	conn1 := tls.Client(conn, &tls.Config{
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			for _, rawCert := range rawCerts {
				cert, err := x509.ParseCertificate(rawCert)
				if err != nil {
					return err
				}

				serverPubKeyBytes, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
				if err != nil {
					return err
				}

				// Compare the byte slices of the public keys
				if bytes.Equal(serverPubKeyBytes, publicKey) {
					return nil // Public key matches, so the certificate is trusted for this connection.
				}
			}

			return errors.New("server's certificate does not match the known public key")
		},
	})

	err = conn1.Handshake()
	if err != nil {
		logger.Printf("[x] handshake failed: [%s]\n", err.Error())
		return
	}

	_, err = conn1.Write([]byte(listenConfig.Secret + "\n"))
	if err != nil {
		logger.Printf("[x] Failed to send data: [%s]\n", err.Error())
		return
	}

	// Set a deadline for the read operation
	deadline := time.Now().Add(5 * time.Second) // 5 seconds from now
	err = conn1.SetReadDeadline(deadline)
	if err != nil {
		logger.Printf("[x] Failed to set read deadline: [%s]\n", err.Error())
		return
	}

	buf := make([]byte, 1)
	_, err = conn1.Read(buf)
	if err != nil {
		if err == io.EOF {
			logger.PrintfX("[x] Connection closed by server\n")
		} else if nErr, ok := err.(net.Error); ok && nErr.Timeout() {
			logger.PrintfX("[x] Read timed out: no response from server\n")
		} else {
			logger.PrintfX("[x] Error reading from server: [%s]\n", err.Error())
		}
		return
	}

	if buf[0] != replySuccess {
		logger.Printf("[x] Authentication failed.\n")
		return
	}

	// Reset the deadline (if further operations are expected)
	err = conn1.SetReadDeadline(time.Time{}) // Zero value disables the deadline
	if err != nil {
		logger.PrintfX("[x] Failed to clear read deadline: [%s]\n", err.Error())
		return
	}

	mutualCopyIO(conn0, conn1)

	logger.PrintfX("[-] client [%s] disconnected\n", conn0.RemoteAddr().String())
}

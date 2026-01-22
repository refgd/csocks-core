package csocks

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

var (
	tlsConfig *tls.Config
)

type negotiationRequest struct {
	net.Conn
	Method   byte
	Address  string
	Listener net.Listener
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

	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicKeyBytes})

	if strings.TrimSpace(publicKeyFile) == "" {
		publicKeyFile = "public.key"
	}
	if err := os.WriteFile(publicKeyFile, pemBytes, 0644); err != nil {
		return err
	}

	tlsConfig = &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
	}
	return nil
}

func proxy(ctx context.Context, listenConfig *ListenConfig) error {
	if err := setTLSConfig(listenConfig.ServerCertFile, listenConfig.ServerKeyFile, listenConfig.PublicKeyFile); err != nil {
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
		logger.Printf("[*] http & socks5 listen on: [%s]", listenConfig.ListenPort)
	} else {
		logger.Printf("[*] socks5 listen on: [%s]", listenConfig.ListenPort)
	}

	for {
		logger.PrintfX("[*] waiting for client to connect [%s %s]\n", ln.Addr().Network(), ln.Addr().String())
		conn0, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				logger.PrintfX("[*] proxy stopped\n")
				return nil
			}
			logger.Printf("[x] accept error [%s]\n", err.Error())
			continue
		}
		logger.PrintfX("[+] new client [%s] connected [%s]\n", conn0.RemoteAddr().String(), conn0.LocalAddr().String())
		go handleRequest(ctx, conn0, listenConfig)
	}
}

func parseRequest(c net.Conn, withHttp bool) (*negotiationRequest, error) {
	r := bufio.NewReader(c)

	b0, err := r.Peek(1)
	if err != nil {
		return nil, err
	}

	// SOCKS5
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

		// Read METHODS and make sure client supports 0x00 (no auth)
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

		atyp := reqHdr[3]
		var host string

		switch atyp {
		case 0x01: // IPv4
			var addr [4]byte
			if _, err := io.ReadFull(r, addr[:]); err != nil {
				return nil, err
			}
			host = net.IP(addr[:]).String()

		case 0x04: // IPv6
			var addr [16]byte
			if _, err := io.ReadFull(r, addr[:]); err != nil {
				return nil, err
			}
			host = net.IP(addr[:]).String()

		case 0x03: // Domain
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
	logger.PrintfX("TLS version used: %d", state.Version)

	return tlsConn, nil
}

func authRequest(tlsConn *tls.Conn, listenConfig *ListenConfig) error {
	reader := bufio.NewReader(tlsConn)
	authData, err := reader.ReadString('\n')
	if err != nil {
		return err
	}

	if strings.TrimSpace(authData) != listenConfig.Secret {
		return errors.New("secret not match")
	}

	_, err = tlsConn.Write([]byte{replySuccess})
	return err
}

func handleRequest(ctx context.Context, conn0 net.Conn, listenConfig *ListenConfig) {
	tlsConn, err := tlsHandshake(conn0)
	if err != nil {
		logger.PrintfX("[x] Failed to handshake: [%s]\n", err.Error())
		_ = conn0.Close()
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

	if err := authRequest(tlsConn, listenConfig); err != nil {
		logger.PrintfX("[x] Authentication failed for [%s]: [%s]\n", tlsConn.RemoteAddr().String(), err.Error())
		return
	}

	negReq, err := parseRequest(tlsConn, listenConfig.WithHttp)
	if err != nil {
		if err != io.EOF {
			logger.Printf("[x] parse request error [%s]\n", err.Error())
			_, _ = tlsConn.Write([]byte(err.Error()))
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

func handleSocks5(ctx context.Context, negotiationRequest *negotiationRequest) {
	conn1, err := net.DialTimeout("tcp", negotiationRequest.Address, time.Duration(timeout)*time.Second)
	if err != nil {
		logger.PrintfX("[x] connect [%s] error [%s]\n", negotiationRequest.Address, err.Error())
		_, _ = negotiationRequest.Conn.Write([]byte(err.Error()))
		return
	}

	logger.PrintfX("[+] connect to [%s] success\n", negotiationRequest.Address)

	_, _ = negotiationRequest.Conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

	mutualCopyIO(ctx, negotiationRequest.Conn, conn1)

	logger.PrintfX("[-] client [%s] disconnected\n", negotiationRequest.Conn.RemoteAddr().String())
}

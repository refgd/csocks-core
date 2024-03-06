package csocks

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
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

func setTLSConfig(serverCertFile, serverKeyFile string) error {
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

	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}
	pemBytes := pem.EncodeToMemory(pemBlock)

	publicKeyFile := "public.key"
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

func proxy(listenConfig *ListenConfig) error {
	err := setTLSConfig(listenConfig.ServerCertFile, listenConfig.ServerKeyFile)
	if err != nil {
		return err
	}

	ln, err := listen(listenConfig.ListenPort)
	if err != nil {
		return err
	}

	if listenConfig.WithHttp {
		logger.Printf("[*] http & socks5 listen on: [%s]", listenConfig.ListenPort)
	} else {
		logger.Printf("[*] socks5 listen on: [%s]", listenConfig.ListenPort)
	}

	for {
		logger.PrintfX("[*] waiting for client to connect [%s %s]\n", ln.Addr().Network(), ln.Addr().String())
		conn0, err := ln.Accept()
		if err != nil {
			logger.Printf("[x] accept error [%s]\n", err.Error())
			continue
		}
		logger.PrintfX("[+] new client [%s] connected [%s]\n", conn0.RemoteAddr().String(), conn0.LocalAddr().String())

		go handleRequest(conn0, listenConfig)
	}
}

func parseRequest(c net.Conn, withHttp bool) (*negotiationRequest, error) {
	bufReader := bufio.NewReader(c)
	firstByte, err := bufReader.Peek(1)
	if err != nil {
		return nil, err
	}

	if firstByte[0] == 0x05 {
		_, _ = c.Write([]byte{0x05, 0x00})

		var buf [1024]byte
		n, err := c.Read(buf[:])
		if err != nil {
			return nil, err
		}

		var host, port string
		switch buf[3] {
		case 0x01:
			host = net.IPv4(buf[4], buf[5], buf[6], buf[7]).String()
		case 0x03:
			host = string(buf[5 : n-2])
		case 0x04:
			host = net.IP{buf[4], buf[5], buf[6], buf[7], buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15], buf[16], buf[17], buf[18], buf[19]}.String()
		}
		port = strconv.Itoa(int(buf[n-2])<<8 | int(buf[n-1]))

		targetAddress := net.JoinHostPort(host, port)
		return &negotiationRequest{
			Conn:    c,
			Method:  methodSocks5,
			Address: targetAddress,
		}, nil
	} else if withHttp { // if not socks5 all proxy as http proxy
		return &negotiationRequest{
			Conn:     c,
			Method:   methodHttp,
			Listener: newConnListener(c, *bufReader),
		}, nil
	}
	return nil, errors.New("unsupported protocol")
}

func tlsHandshake(conn0 net.Conn) (*tls.Conn, error) {
	tlsConn := tls.Server(conn0, tlsConfig)

	err := tlsConn.SetDeadline(time.Now().Add(time.Duration(timeout) * time.Second))
	if err != nil {
		return nil, err
	}

	err = tlsConn.Handshake()
	if err != nil {
		return nil, err
	}

	err = tlsConn.SetDeadline(time.Time{})
	if err != nil {
		return nil, err
	}

	state := tlsConn.ConnectionState()
	logger.Printf("TLS version used: %d", state.Version)

	return tlsConn, nil
}

func authRequest(tlsConn *tls.Conn, listenConfig *ListenConfig) error {
	// Read and validate authentication data
	reader := bufio.NewReader(tlsConn)
	authData, err := reader.ReadString('\n')
	if err != nil {
		return err
	}

	authData = strings.TrimSpace(authData)
	if authData != listenConfig.Secret {
		return errors.New("secret not match")
	}

	_, err = tlsConn.Write([]byte{replySuccess}) // Send a single byte
	if err != nil {
		return err
	}

	return nil
}

func handleRequest(conn0 net.Conn, listenConfig *ListenConfig) {
	tlsConn, err := tlsHandshake(conn0)
	if err != nil {
		logger.PrintfX("[x] Failed to handshake: [%s]\n", err.Error())
		conn0.Close()
		return
	}

	err = authRequest(tlsConn, listenConfig)
	if err != nil {
		logger.PrintfX("[x] Authentication failed for [%s]: [%s]\n", tlsConn.RemoteAddr().String(), err.Error())
		tlsConn.Close()
		return
	}

	negotiationRequest, err := parseRequest(tlsConn, listenConfig.WithHttp)
	if err != nil {
		if err != io.EOF {
			logger.Printf("[x] parse request error [%s]\n", err.Error())
			_, _ = tlsConn.Write([]byte(err.Error()))
		}

		tlsConn.Close()
		return
	}

	if negotiationRequest.Method == methodSocks5 {
		handleSocks5(negotiationRequest)
	} else if negotiationRequest.Method == methodHttp {
		handleHttpRequest(negotiationRequest)
	}
}

func handleSocks5(negotiationRequest *negotiationRequest) {
	conn1, err := net.DialTimeout("tcp", negotiationRequest.Address, time.Duration(timeout)*time.Second)
	if err != nil {
		logger.PrintfX("[x] connect [%s] error [%s]\n", negotiationRequest.Address, err.Error())
		_, _ = negotiationRequest.Conn.Write([]byte(err.Error()))
		return
	}
	logger.PrintfX("[+] connect to [%s] success\n", negotiationRequest.Address)

	_, _ = negotiationRequest.Conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})

	mutualCopyIO(negotiationRequest.Conn, conn1)

	logger.PrintfX("[-] client [%s] disconnected\n", negotiationRequest.Conn.RemoteAddr().String())
}

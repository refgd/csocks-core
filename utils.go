package csocks

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	methodSocks5 byte = 0x00
	methodHttp   byte = 0x01

	replySuccess byte = 0x09

	timeout int = 10
	Version     = "v0.0.1"
)

type deadlineConn struct {
	net.Conn
	idleTimeout time.Duration
}

func (c *deadlineConn) Read(b []byte) (n int, err error) {
	if err := c.resetDeadline(); err != nil {
		return 0, err
	}
	return c.Conn.Read(b)
}

func (c *deadlineConn) Write(b []byte) (n int, err error) {
	if err := c.resetDeadline(); err != nil {
		return 0, err
	}
	return c.Conn.Write(b)
}

func (c *deadlineConn) resetDeadline() error {
	if c.idleTimeout <= 0 {
		return nil
	}
	return c.Conn.SetDeadline(time.Now().Add(c.idleTimeout))
}

func newDeadlineConn(conn net.Conn, idleTimeout time.Duration) *deadlineConn {
	return &deadlineConn{Conn: conn, idleTimeout: idleTimeout}
}

type closeWriter interface{ CloseWrite() error }

func tryCloseWrite(conn net.Conn) {
	if cw, ok := conn.(closeWriter); ok {
		_ = cw.CloseWrite()
		return
	}
	_ = conn.Close()
}

func mutualCopyIO(ctx context.Context, conn0, conn1 net.Conn) {
	w0 := newDeadlineConn(conn0, 60*time.Second)
	w1 := newDeadlineConn(conn1, 60*time.Second)

	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = conn0.Close()
			_ = conn1.Close()
		case <-done:
		}
	}()
	defer close(done)

	var wg sync.WaitGroup
	wg.Add(2)

	// conn1 -> conn0
	go func() {
		defer wg.Done()
		_, _ = io.Copy(w0, w1)
		tryCloseWrite(conn0)
	}()

	// conn0 -> conn1
	go func() {
		defer wg.Done()
		_, _ = io.Copy(w1, w0)
		tryCloseWrite(conn1)
	}()

	wg.Wait()

	_ = conn0.Close()
	_ = conn1.Close()
}

func listen(listenPort string) (net.Listener, error) {
	if !strings.Contains(listenPort, ":") {
		listenPort = "0.0.0.0:" + listenPort
	}
	return net.Listen("tcp", listenPort)
}

func loadPublicKey(s string) ([]byte, error) {
	// inline: prefix => treat as literal key text
	if after, ok := strings.CutPrefix(s, "inline:"); ok {
		key := strings.TrimSpace(after)
		if key == "" {
			return nil, errors.New("inline public key is empty")
		}
		return []byte(key), nil
	}

	if strings.TrimSpace(s) == "" {
		s = "public.key"
	}

	data, err := os.ReadFile(s)
	if err != nil {
		return nil, err
	}

	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return nil, errors.New("public key file is empty")
	}
	return data, nil
}

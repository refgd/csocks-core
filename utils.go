package csocks

import (
	"io"
	"net"
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
	err = c.resetDeadline()
	if err != nil {
		return 0, err
	}
	return c.Conn.Read(b)
}

func (c *deadlineConn) Write(b []byte) (n int, err error) {
	err = c.resetDeadline()
	if err != nil {
		return 0, err
	}
	return c.Conn.Write(b)
}

func (c *deadlineConn) resetDeadline() error {
	if c.idleTimeout > 0 {
		deadline := time.Now().Add(c.idleTimeout)
		if err := c.Conn.SetDeadline(deadline); err != nil {
			return err
		}
	}
	return nil
}

func newDeadlineConn(conn net.Conn, idleTimeout time.Duration) *deadlineConn {
	return &deadlineConn{
		Conn:        conn,
		idleTimeout: idleTimeout,
	}
}

func copyIO(src, dest net.Conn, wg *sync.WaitGroup) {
	defer src.Close()
	_, _ = io.Copy(src, dest)
	wg.Done()
}

func mutualCopyIO(conn0, conn1 net.Conn) {
	wrappedConn0 := newDeadlineConn(conn0, 60*time.Second)
	wrappedConn1 := newDeadlineConn(conn1, 60*time.Second)

	wg := sync.WaitGroup{}
	wg.Add(2)
	go copyIO(wrappedConn0, wrappedConn1, &wg)
	go copyIO(wrappedConn1, wrappedConn0, &wg)
	wg.Wait()
}

func listen(listenPort string) (net.Listener, error) {
	if !strings.Contains(listenPort, ":") {
		listenPort = "0.0.0.0:" + listenPort
	}
	ln, err := net.Listen("tcp", listenPort)
	if err != nil {
		return nil, err
	}
	return ln, nil
}

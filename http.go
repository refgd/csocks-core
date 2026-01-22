package csocks

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

type connListener struct {
	addr net.Addr
	ch   chan net.Conn
	once sync.Once
}

func newConnListener(conn net.Conn, reader *bufio.Reader) net.Listener {
	ch := make(chan net.Conn, 1)
	ch <- &readConn{Conn: conn, reader: reader}
	return &connListener{addr: conn.LocalAddr(), ch: ch}
}

func (l *connListener) Accept() (net.Conn, error) {
	conn, ok := <-l.ch
	if !ok || conn == nil {
		return nil, io.EOF
	}
	return &connCloser{l: l, Conn: conn}, nil
}

func (l *connListener) shutdown() { l.once.Do(func() { close(l.ch) }) }

func (l *connListener) Close() error {
	l.shutdown()
	return nil
}

func (l *connListener) Addr() net.Addr { return l.addr }

type connCloser struct {
	l *connListener
	net.Conn
}

func (c *connCloser) Close() error {
	c.l.shutdown()
	return c.Conn.Close()
}

type readConn struct {
	net.Conn
	reader   *bufio.Reader
	readOnce bool
}

func (c *readConn) Read(b []byte) (int, error) {
	if c.readOnce {
		return c.Conn.Read(b)
	}
	c.readOnce = true
	return c.reader.Read(b)
}

func handleHttpRequest(ctx context.Context, negotiationRequest *negotiationRequest) {
	defer negotiationRequest.Conn.Close()

	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = negotiationRequest.Listener.Close()
		case <-done:
		}
	}()
	defer close(done)

	err := http.Serve(negotiationRequest.Listener, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			handleTunneling(ctx, w, r)
			return
		}
		handleHttp(ctx, w, r)
	}))

	if err != nil && err != io.EOF {
		logger.Printf("[x] http error [%s]\n", err.Error())
	}
}

func handleTunneling(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	remoteConn, err := net.DialTimeout("tcp", r.Host, time.Duration(timeout)*time.Second)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		_ = remoteConn.Close()
		http.Error(w, "hijack not supported", http.StatusInternalServerError)
		return
	}

	centralConn, _, err := hijacker.Hijack()
	if err != nil {
		_ = remoteConn.Close()
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	_, _ = centralConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	mutualCopyIO(ctx, centralConn, remoteConn)
}

func handleHttp(ctx context.Context, w http.ResponseWriter, req *http.Request) {
	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()

	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

package csocks

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

func handleHttpRequest(ctx context.Context, negotiationRequest *negotiationRequest) {
	defer negotiationRequest.Conn.Close()

	reader := negotiationRequest.Reader
	if reader == nil {
		reader = bufio.NewReader(negotiationRequest.Conn)
	}

	req, err := http.ReadRequest(reader)
	if err != nil {
		if err != io.EOF {
			logger.PrintfX("[x] http read request error: [%s]\n", err.Error())
		}
		return
	}
	defer req.Body.Close()

	logger.PrintfX("[http] method=%s host=%s url=%s requestURI=%s\n",
		req.Method,
		req.Host,
		req.URL.String(),
		req.RequestURI,
	)

	if req.Method == http.MethodConnect {
		handleHttpConnectDirect(ctx, negotiationRequest.Conn, reader, req)
		return
	}

	handleHttpForwardDirect(ctx, negotiationRequest.Conn, req)
}

func handleHttpConnectDirect(
	ctx context.Context,
	clientConn net.Conn,
	reader *bufio.Reader,
	req *http.Request,
) {
	host := strings.TrimSpace(req.Host)
	if host == "" && req.URL != nil {
		host = strings.TrimSpace(req.URL.Host)
	}

	if host == "" {
		writeHTTPProxyError(clientConn, http.StatusBadRequest)
		return
	}

	dialer := &net.Dialer{
		Timeout: time.Duration(timeout) * time.Second,
	}

	remoteConn, err := dialer.DialContext(ctx, "tcp", host)
	if err != nil {
		logger.PrintfX("[x] CONNECT dial failed host=%s err=%s\n", host, err.Error())
		writeHTTPProxyError(clientConn, http.StatusServiceUnavailable)
		return
	}

	if _, err := io.WriteString(clientConn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		logger.PrintfX("[x] CONNECT write 200 failed host=%s err=%s\n", host, err.Error())
		_ = remoteConn.Close()
		return
	}

	if reader != nil && reader.Buffered() > 0 {
		n := reader.Buffered()

		if _, err := io.CopyN(remoteConn, reader, int64(n)); err != nil {
			logger.PrintfX("[x] CONNECT flush buffered bytes failed host=%s n=%d err=%s\n",
				host,
				n,
				err.Error(),
			)
			_ = remoteConn.Close()
			return
		}
	}

	logger.PrintfX("[+] CONNECT established host=%s\n", host)

	mutualCopyIO(ctx, clientConn, remoteConn)

	logger.PrintfX("[-] CONNECT closed host=%s\n", host)
}

func handleHttpForwardDirect(
	ctx context.Context,
	clientConn net.Conn,
	req *http.Request,
) {
	outReq := req.Clone(ctx)
	outReq.RequestURI = ""

	if outReq.URL == nil {
		writeHTTPProxyError(clientConn, http.StatusBadRequest)
		return
	}

	if outReq.URL.Scheme == "" {
		outReq.URL.Scheme = "http"
	}

	if outReq.URL.Host == "" {
		outReq.URL.Host = outReq.Host
	}

	if outReq.URL.Host == "" {
		writeHTTPProxyError(clientConn, http.StatusBadRequest)
		return
	}

	cleanProxyHeaders(outReq.Header)

	resp, err := http.DefaultTransport.RoundTrip(outReq)
	if err != nil {
		logger.PrintfX("[x] HTTP roundtrip failed host=%s url=%s err=%s\n",
			outReq.Host,
			outReq.URL.String(),
			err.Error(),
		)
		writeHTTPProxyError(clientConn, http.StatusServiceUnavailable)
		return
	}

	defer resp.Body.Close()

	cleanProxyHeaders(resp.Header)

	resp.Close = true
	resp.Header.Set("Connection", "close")

	if err := resp.Write(clientConn); err != nil {
		logger.PrintfX("[x] HTTP response write failed err=%s\n", err.Error())
		return
	}
}

func writeHTTPProxyError(conn net.Conn, code int) {
	if conn == nil {
		return
	}

	text := http.StatusText(code)
	if text == "" {
		text = "Error"
	}

	body := text + "\n"

	_, _ = fmt.Fprintf(
		conn,
		"HTTP/1.1 %d %s\r\n"+
			"Content-Type: text/plain; charset=utf-8\r\n"+
			"Content-Length: %d\r\n"+
			"Connection: close\r\n"+
			"\r\n"+
			"%s",
		code,
		text,
		len(body),
		body,
	)
}

func cleanProxyHeaders(h http.Header) {
	h.Del("Proxy-Connection")
	h.Del("Connection")
	h.Del("Keep-Alive")
	h.Del("Proxy-Authenticate")
	h.Del("Proxy-Authorization")
	h.Del("TE")
	h.Del("Trailer")
	h.Del("Transfer-Encoding")
	h.Del("Upgrade")
}

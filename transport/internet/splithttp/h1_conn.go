package splithttp

import (
	"bufio"
	"net"
	"time"
)

type H1Conn struct {
	RespBufReader *bufio.Reader
	net.Conn
}

func NewH1Conn(conn net.Conn) *H1Conn {
	return &H1Conn{
		RespBufReader: bufio.NewReader(h1ResponseReader{conn}),
		Conn:          conn,
	}
}

type h1ResponseReader struct{ net.Conn }

func (r h1ResponseReader) Read(p []byte) (int, error) {
	if err := r.SetReadDeadline(time.Now().Add(h1ResponseIdleTimeout)); err != nil {
		return 0, err
	}
	return r.Conn.Read(p)
}

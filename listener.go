package main

import (
	"net"
	"sync"

	"github.com/pkg/errors"
)

type (
	oneShotListener struct {
		c  net.Conn
		mu sync.Mutex
		ch chan struct{}
	}
	onCloseConn struct {
		net.Conn
		f func()
	}
)

func NewOneShotListener(c net.Conn) *oneShotListener {
	ch := make(chan struct{})
	conn := &onCloseConn{
		Conn: c,
		f: func() {
			close(ch)
		},
	}
	return &oneShotListener{
		c:  conn,
		ch: ch,
	}
}

func (l *oneShotListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.c == nil {
		return nil, errors.New("listener used up")
	}
	c := l.c
	l.c = nil
	return c, nil
}
func (l *oneShotListener) ConnCloseCh() <-chan struct{} {
	return l.ch
}
func (l *oneShotListener) Close() error {
	return nil
}
func (l *oneShotListener) Addr() net.Addr {
	return l.c.LocalAddr()
}
func (c *onCloseConn) Close() error {
	if c.f != nil {
		c.f()
		c.f = nil
	}
	return c.Conn.Close()
}

package pool

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

// Pool is a generic connection pool.
type Pool interface {
	Get() (net.Conn, error)
	Put(net.Conn)
	Close()
	Len() int
}

// channelPool implements the Pool interface.
type channelPool struct {
	conns   chan net.Conn
	factory func() (net.Conn, error)
	mu      sync.Mutex
}

// NewChannelPool creates a new connection pool.
func NewChannelPool(initialCap, maxCap int, factory func() (net.Conn, error)) (Pool, error) {
	if initialCap < 0 || maxCap <= 0 || initialCap > maxCap {
		return nil, errors.New("invalid capacity settings")
	}

	p := &channelPool{
		conns:   make(chan net.Conn, maxCap),
		factory: factory,
	}

	for i := 0; i < initialCap; i++ {
		conn, err := factory()
		if err != nil {
			p.Close()
			return nil, fmt.Errorf("factory is not able to fill the pool: %s", err)
		}
		p.conns <- conn
	}

	return p, nil
}

func (p *channelPool) Get() (net.Conn, error) {
	select {
	case conn := <-p.conns:
		if conn == nil {
			return nil, errors.New("pool is closed")
		}
		// Check if the connection is still alive
		if conn.SetReadDeadline(time.Now().Add(1 * time.Millisecond)); err != nil {
			return p.factory()
		}
		var oneByte []byte
		if _, err := conn.Read(oneByte); err != nil {
			return p.factory()
		}
		if conn.SetReadDeadline(time.Time{}); err != nil {
			return p.factory()
		}
		return conn, nil
	default:
		return p.factory()
	}
}

func (p *channelPool) Put(conn net.Conn) {
	if conn == nil {
		return
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if p.conns == nil {
		conn.Close()
		return
	}

	select {
	case p.conns <- conn:
		return
	default:
		conn.Close()
	}
}

func (p *channelPool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.conns == nil {
		return
	}

	close(p.conns)
	for conn := range p.conns {
		conn.Close()
	}
	p.conns = nil
}

func (p *channelPool) Len() int {
	return len(p.conns)
}

package pool

import (
	"net"
	"sync"
	"time"
)

const maxIdleTime = 2 * time.Minute

// ConnPool manages a pool of network connections.
type ConnPool struct {
	mu      sync.Mutex
	conns   map[string][]*idleConn
	maxSize int
}

type idleConn struct {
	conn    net.Conn
	addedAt time.Time
}

// NewConnPool creates a new connection pool.
func NewConnPool(maxSize int) *ConnPool {
	return &ConnPool{
		conns:   make(map[string][]*idleConn),
		maxSize: maxSize,
	}
}

// Get retrieves a connection from the pool or creates a new one.
func (p *ConnPool) Get(addr string) (net.Conn, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.conns[addr] != nil && len(p.conns[addr]) > 0 {
		ic := p.conns[addr][0]
		p.conns[addr] = p.conns[addr][1:]

		// Check if the connection is still valid
		if err := connCheck(ic.conn); err == nil {
			return ic.conn, nil
		}
	}

	// No valid connection in pool, create a new one
	return net.DialTimeout("tcp", addr, 5*time.Second)
}

// Put adds a connection back to the pool.
func (p *ConnPool) Put(conn net.Conn) {
	p.mu.Lock()
	defer p.mu.Unlock()

	addr := conn.RemoteAddr().String()
	if p.conns[addr] == nil {
		p.conns[addr] = make([]*idleConn, 0, p.maxSize)
	}

	if len(p.conns[addr]) >= p.maxSize {
		conn.Close() // Pool is full
		return
	}

	p.conns[addr] = append(p.conns[addr], &idleConn{conn: conn, addedAt: time.Now()})
}

// connCheck performs a lightweight check to see if a connection is still alive.
func connCheck(conn net.Conn) error {
	if err := conn.SetReadDeadline(time.Now().Add(1 * time.Millisecond)); err != nil {
		return err
	}
	var one []byte
	if _, err := conn.Read(one); err == net.ErrClosed || err == io.EOF {
		return err
	}
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		return err
	}
	return nil
}

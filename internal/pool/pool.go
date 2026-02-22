package pool

import (
	"fmt"
	"net"
	"sync"
	"time"
)

const maxConnectionsPerHost = 10

// ConnectionPool manages a pool of reusable network connections.
type ConnectionPool struct {
	pools map[string]chan net.Conn
	mu    sync.Mutex
}

// New creates a new ConnectionPool.
func New() *ConnectionPool {
	return &ConnectionPool{
		pools: make(map[string]chan net.Conn),
	}
}

// Get retrieves a connection from the pool for the given address.
// If the pool is empty, it creates a new connection.
func (p *ConnectionPool) Get(addr string) (net.Conn, error) {
	p.mu.Lock()
	pool, ok := p.pools[addr]
	if !ok {
		pool = make(chan net.Conn, maxConnectionsPerHost)
		p.pools[addr] = pool
	}
	p.mu.Unlock()

	select {
	case conn := <-pool:
		// Check if the connection is still alive
		conn.SetReadDeadline(time.Now().Add(1 * time.Millisecond))
		var oneByte []byte
		if _, err := conn.Read(oneByte); err != nil {
			conn.Close() // Close the dead connection
			return p.dial(addr) // Dial a new one
		}
		conn.SetReadDeadline(time.Time{}) // Reset deadline
		return conn, nil
	default:
		return p.dial(addr)
	}
}

// Put returns a connection to the pool.
func (p *ConnectionPool) Put(conn net.Conn) {
	if conn == nil {
		return
	}
	addr := conn.RemoteAddr().String()

	p.mu.Lock()
	pool, ok := p.pools[addr]
	if !ok {
		p.mu.Unlock()
		conn.Close() // This address is not pooled, just close it
		return
	}
	p.mu.Unlock()

	select {
	case pool <- conn:
		// Connection returned to pool
	default:
		// Pool is full, close the connection
		conn.Close()
	}
}

// dial creates a new network connection.
func (p *ConnectionPool) dial(addr string) (net.Conn, error) {
	return net.DialTimeout("tcp", addr, 10*time.Second)
}

// Close closes all connections in the pool.
func (p *ConnectionPool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()

	for addr, pool := range p.pools {
		close(pool)
		for conn := range pool {
			conn.Close()
		}
		delete(p.pools, addr)
	}
}

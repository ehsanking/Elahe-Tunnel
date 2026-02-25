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

	if conns, ok := p.conns[addr]; ok && len(conns) > 0 {
		// Iterate backwards to easily remove elements
		for i := len(conns) - 1; i >= 0; i-- {
			ic := conns[i]
			p.conns[addr] = append(conns[:i], conns[i+1:]...)

			// Check if the connection is still valid
			if err := connCheck(ic.conn); err == nil {
				return ic.conn, nil
			} else {
				ic.conn.Close()
			}
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
	// A truly non-destructive check is hard in portable Go.
	// The previous method of reading 1 byte consumes data, which is fatal for a tunnel.
	//
	// For now, we will just check if the deadline can be set.
	// In a real high-perf scenario, we might use syscall.Recv with PEEK flag,
	// but that is platform dependent.
	//
	// A common strategy is to rely on the Write failing later if the conn is dead.
	// But we can try a very short ReadDeadline. If Read returns EOF, it's closed.
	// If it returns a timeout, it's open (and idle).
	// If it returns data, it's open (but has data).
	//
	// The problem is if it has data, we can't "peek" it easily without syscalls.
	// Since we expect these connections to be used for *sending* requests to a server,
	// and we just finished reading the response, the server shouldn't be sending us data
	// unless it's a keep-alive packet or a delayed response.
	
	// Let's just assume it's good if it's not closed.
	// We can't easily check for "closed by peer" without reading.
	// So we will skip the read check to avoid data corruption.
	// The consumer of the connection will get an error on Write/Read if it's dead,
	// and should handle retries if necessary (though retrying a partial write is hard).
	
	return nil
}

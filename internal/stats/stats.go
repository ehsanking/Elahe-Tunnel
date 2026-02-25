package stats

import (
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

// Global atomic counters for tunnel metrics.
var (
	// TCP Stats
	tcpActiveConnections int64
	tcpBytesIn           uint64
	tcpBytesOut          uint64

	// UDP Stats
	udpBytesIn  uint64
	udpBytesOut uint64

	// Connection Health
	lastSuccessfulPing int64 // Unix timestamp

	// DNS Stats
	dnsQueries uint64
	dnsErrors  uint64
	
	// Active Connections Tracking
	activeConnections = make(map[string]*ConnectionInfo)
	connsMu           sync.RWMutex
)

type ConnectionInfo struct {
	ID        string
	Src       string
	Dst       string
	StartTime time.Time
	Protocol  string
}

// TCP Functions
func AddTcpActiveConnection()    { atomic.AddInt64(&tcpActiveConnections, 1) }
func RemoveTcpActiveConnection() { atomic.AddInt64(&tcpActiveConnections, -1) }
func GetTcpActiveConnections() int64 { return atomic.LoadInt64(&tcpActiveConnections) }

func RegisterConnection(id, src, dst, protocol string) {
	connsMu.Lock()
	defer connsMu.Unlock()
	activeConnections[id] = &ConnectionInfo{
		ID:        id,
		Src:       src,
		Dst:       dst,
		StartTime: time.Now(),
		Protocol:  protocol,
	}
	if protocol == "TCP" {
		AddTcpActiveConnection()
	}
}

func UnregisterConnection(id string) {
	connsMu.Lock()
	defer connsMu.Unlock()
	if conn, exists := activeConnections[id]; exists {
		if conn.Protocol == "TCP" {
			RemoveTcpActiveConnection()
		}
		delete(activeConnections, id)
	}
}

func GetActiveConnectionsList() []ConnectionInfo {
	connsMu.RLock()
	defer connsMu.RUnlock()
	list := make([]ConnectionInfo, 0, len(activeConnections))
	for _, conn := range activeConnections {
		list = append(list, *conn)
	}
	return list
}

// DNS Functions
func AddDnsQuery() { atomic.AddUint64(&dnsQueries, 1) }
func AddDnsError() { atomic.AddUint64(&dnsErrors, 1) }
func GetDnsQueries() uint64 { return atomic.LoadUint64(&dnsQueries) }
func GetDnsErrors() uint64  { return atomic.LoadUint64(&dnsErrors) }

func AddTcpBytesIn(n uint64)  { atomic.AddUint64(&tcpBytesIn, n) }
func AddTcpBytesOut(n uint64) { atomic.AddUint64(&tcpBytesOut, n) }
func GetTcpBytesIn() uint64   { return atomic.LoadUint64(&tcpBytesIn) }
func GetTcpBytesOut() uint64  { return atomic.LoadUint64(&tcpBytesOut) }

// UDP Functions
func AddUdpBytesIn(n uint64)  { atomic.AddUint64(&udpBytesIn, n) }
func AddUdpBytesOut(n uint64) { atomic.AddUint64(&udpBytesOut, n) }
func GetUdpBytesIn() uint64   { return atomic.LoadUint64(&udpBytesIn) }
func GetUdpBytesOut() uint64  { return atomic.LoadUint64(&udpBytesOut) }

// Health Functions
func SetLastSuccessfulPing(t int64) { atomic.StoreInt64(&lastSuccessfulPing, t) }
func GetLastSuccessfulPing() int64  { return atomic.LoadInt64(&lastSuccessfulPing) }

// Status struct for JSON marshalling
type Status struct {
	TcpActiveConnections int64  `json:"TcpActiveConnections"`
	TcpBytesIn           uint64 `json:"TcpBytesIn"`
	TcpBytesOut          uint64 `json:"TcpBytesOut"`
	UdpBytesIn           uint64 `json:"UdpBytesIn"`
	UdpBytesOut          uint64 `json:"UdpBytesOut"`
	DnsQueries           uint64 `json:"DnsQueries"`
	DnsErrors            uint64 `json:"DnsErrors"`
	LastSuccessfulPing   int64  `json:"LastSuccessfulPing"`
	ConnectionHealth     string `json:"ConnectionHealth"`
	SystemMemoryUsage    uint64 `json:"SystemMemoryUsage"`
	NumGoroutines        int    `json:"NumGoroutines"`
}

// GetStatus gathers all current stats and returns a Status object.
func GetStatus() Status {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	status := Status{
		TcpActiveConnections: GetTcpActiveConnections(),
		TcpBytesIn:           GetTcpBytesIn(),
		TcpBytesOut:          GetTcpBytesOut(),
		UdpBytesIn:           GetUdpBytesIn(),
		UdpBytesOut:          GetUdpBytesOut(),
		DnsQueries:           GetDnsQueries(),
		DnsErrors:            GetDnsErrors(),
		LastSuccessfulPing:   GetLastSuccessfulPing(),
		SystemMemoryUsage:    m.Alloc,
		NumGoroutines:        runtime.NumGoroutine(),
	}

	if time.Now().Unix()-status.LastSuccessfulPing < 90 {
		status.ConnectionHealth = "Connected"
	} else {
		status.ConnectionHealth = "Disconnected"
	}
	return status
}

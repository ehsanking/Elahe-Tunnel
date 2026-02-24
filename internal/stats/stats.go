package stats

import (
	"runtime"
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
)

// TCP Functions
func AddTcpActiveConnection()    { atomic.AddInt64(&tcpActiveConnections, 1) }
func RemoveTcpActiveConnection() { atomic.AddInt64(&tcpActiveConnections, -1) }
func GetTcpActiveConnections() int64 { return atomic.LoadInt64(&tcpActiveConnections) }

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

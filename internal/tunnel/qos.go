package tunnel

import (
	"net/http"
)

// QoSTransport implements Quality of Service by limiting the concurrency of
// general TCP traffic while allowing high-priority traffic (like DNS) to bypass the limit.
type QoSTransport struct {
	Transport        http.RoundTripper
	tcpSemaphore     chan struct{}
}

// NewQoSTransport creates a new QoSTransport with the specified maximum concurrent TCP requests.
func NewQoSTransport(t http.RoundTripper, maxConcurrentTcp int) *QoSTransport {
	if t == nil {
		t = http.DefaultTransport
	}
	return &QoSTransport{
		Transport:    t,
		tcpSemaphore: make(chan struct{}, maxConcurrentTcp),
	}
}

// RoundTrip executes a single HTTP transaction, applying QoS rules.
func (qt *QoSTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// High priority traffic (e.g., DNS or Ping) bypasses the semaphore
	if req.Header.Get("X-Tunnel-Type") == "dns" || req.URL.Path == "/favicon.ico" {
		return qt.Transport.RoundTrip(req)
	}

	// Low priority traffic (e.g., general TCP) must acquire a semaphore token
	qt.tcpSemaphore <- struct{}{}
	defer func() { <-qt.tcpSemaphore }()

	return qt.Transport.RoundTrip(req)
}

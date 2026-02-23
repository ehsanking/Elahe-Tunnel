package tunnel

import (
	"fmt"

	"github.com/miekg/dns"
)

// DnsQueryFunc is a function that can perform a DNS query over a tunnel.
type DnsQueryFunc func(query []byte) ([]byte, error)

// RunDnsProxy starts a local DNS server that proxies requests over the tunnel.
func RunDnsProxy(localPort int, tunnelQuery DnsQueryFunc) {
	server := &dns.Server{Addr: fmt.Sprintf(":%d", localPort), Net: "udp"}
	server.Handler = &dnsProxyHandler{tunnelQuery: tunnelQuery}

	fmt.Printf("DNS proxy listening on port %d\n", localPort)
	if err := server.ListenAndServe(); err != nil {
		fmt.Printf("Failed to start DNS proxy: %s\n", err.Error())
	}
}

type dnsProxyHandler struct {
	tunnelQuery DnsQueryFunc
}

func (h *dnsProxyHandler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	query, err := r.Pack()
	if err != nil {
		fmt.Printf("Failed to pack DNS query: %v\n", err)
		dns.HandleFailed(w, r)
		return
	}

	respBytes, err := h.tunnelQuery(query)
	if err != nil {
		fmt.Printf("DNS tunnel query failed: %v\n", err)
		dns.HandleFailed(w, r)
		return
	}

	respMsg := new(dns.Msg)
	if err := respMsg.Unpack(respBytes); err != nil {
		fmt.Printf("Failed to unpack DNS response: %v\n", err)
		dns.HandleFailed(w, r)
		return
	}

	respMsg.Id = r.Id
	w.WriteMsg(respMsg)
}

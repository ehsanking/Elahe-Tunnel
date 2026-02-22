package tunnel

import (
	"fmt"
	"net"

	"github.com/miekg/dns"
)

// RunDnsProxy starts a local DNS server to intercept and tunnel DNS queries.
func RunDnsProxy(dnsPort int, tunnelQuery func([]byte) ([]byte, error)) {
	addr := fmt.Sprintf("127.0.0.1:%d", dnsPort)
	fmt.Printf("Starting DNS proxy on %s\n", addr)

	server := &dns.Server{Addr: addr, Net: "udp"}
	server.Handler = dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		msg := new(dns.Msg)
		msg.SetReply(r)
		msg.Authoritative = true

		// For now, we just handle a single question
		if len(r.Question) > 0 {
			q := r.Question[0]
			packed, err := r.Pack()
			if err != nil {
				fmt.Printf("DNS pack error: %v\n", err)
				msg.SetRcode(r, dns.RcodeServerFailure)
				w.WriteMsg(msg)
				return
			}

			fmt.Printf("Tunneling DNS query for: %s\n", q.Name)
			respPacked, err := tunnelQuery(packed)
			if err != nil {
				fmt.Printf("DNS tunnel query error: %v\n", err)
				msg.SetRcode(r, dns.RcodeServerFailure)
				w.WriteMsg(msg)
				return
			}

			respMsg := new(dns.Msg)
			if err := respMsg.Unpack(respPacked); err != nil {
				fmt.Printf("DNS unpack error: %v\n", err)
				msg.SetRcode(r, dns.RcodeServerFailure)
				w.WriteMsg(msg)
				return
			}

			w.WriteMsg(respMsg)
			return
		}

		// Default failure case
		msg.SetRcode(r, dns.RcodeServerFailure)
		w.WriteMsg(msg)
	})

	if err := server.ListenAndServe(); err != nil {
		fmt.Printf("Failed to start DNS proxy: %s\n", err.Error())
	}
}

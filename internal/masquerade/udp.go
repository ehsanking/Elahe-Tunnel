package masquerade

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

const masqueradeDomain = "dns-updater.com."

// WrapInDnsQuery takes encrypted data and wraps it into a fake DNS TXT query.
func WrapInDnsQuery(data []byte) ([]byte, error) {
	encodedData := base64.URLEncoding.EncodeToString(data)
	qname := fmt.Sprintf("%s.%s", encodedData, masqueradeDomain)

	msg := new(dns.Msg)
	msg.SetQuestion(qname, dns.TypeTXT)
	msg.Id = dns.Id()
	msg.RecursionDesired = true

	return msg.Pack()
}

// UnwrapFromDnsQuery extracts data from a fake DNS TXT query.
func UnwrapFromDnsQuery(data []byte) ([]byte, error) {
	msg := new(dns.Msg)
	if err := msg.Unpack(data); err != nil {
		return nil, fmt.Errorf("failed to unpack DNS message: %w", err)
	}

	if len(msg.Question) == 0 {
		return nil, fmt.Errorf("DNS message has no questions")
	}

	qname := msg.Question[0].Name
	if !strings.HasSuffix(qname, masqueradeDomain) {
		return nil, fmt.Errorf("qname '%s' does not have expected suffix", qname)
	}

	encodedData := strings.TrimSuffix(qname, masqueradeDomain)
	// Trim the trailing dot
	if len(encodedData) > 0 {
		encodedData = encodedData[:len(encodedData)-1]
	}

	return base64.URLEncoding.DecodeString(encodedData)
}

// WrapInDnsResponse takes an encrypted payload and wraps it in a DNS TXT response.
func WrapInDnsResponse(query *dns.Msg, payload []byte) ([]byte, error) {
	resp := new(dns.Msg)
	resp.SetReply(query)

	txtRecord := &dns.TXT{
		Hdr: dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
		Txt: []string{base64.URLEncoding.EncodeToString(payload)},
	}
	resp.Answer = append(resp.Answer, txtRecord)

	return resp.Pack()
}

// UnwrapFromDnsResponse extracts a payload from a DNS TXT response.
func UnwrapFromDnsResponse(data []byte) ([]byte, error) {
	msg := new(dns.Msg)
	if err := msg.Unpack(data); err != nil {
		return nil, fmt.Errorf("failed to unpack DNS response: %w", err)
	}

	if len(msg.Answer) == 0 {
		return nil, fmt.Errorf("DNS response has no answers")
	}

	txt, ok := msg.Answer[0].(*dns.TXT)
	if !ok || len(txt.Txt) == 0 {
		return nil, fmt.Errorf("answer is not a TXT record or is empty")
	}

	return base64.URLEncoding.DecodeString(txt.Txt[0])
}

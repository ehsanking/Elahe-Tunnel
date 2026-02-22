package tunnel

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/ehsanking/search-tunnel/internal/config"
	"github.com/ehsanking/search-tunnel/internal/crypto"
	"github.com/ehsanking/search-tunnel/internal/logger"
	"github.com/ehsanking/search-tunnel/internal/masquerade"
	"github.com/ehsanking/search-tunnel/internal/pool"
	"github.com/miekg/dns"
)

var connPool = pool.New()

// RunServer starts the external node as an HTTP server.
func RunServer(cfg *config.Config) error {
	key, err := crypto.DecodeBase64Key(cfg.ConnectionKey)
	if err != nil {
		return fmt.Errorf("invalid connection key: %w", err)
	}

	limiter := NewIPRateLimiter(5, 10) // 5 requests per second, burst of 10

	searchHandler := http.HandlerFunc(handleSearchRequest(key))
	pingHandler := http.HandlerFunc(handlePingRequest(key))
	dnsHandler := http.HandlerFunc(handleDnsRequest(key))
	udpHandler := http.HandlerFunc(handleUdpRequest(key))

	http.Handle("/search", limiter.Limit(searchHandler))
	http.Handle("/favicon.ico", limiter.Limit(pingHandler)) // Also rate-limit pings
	http.Handle("/dns-query", limiter.Limit(dnsHandler))   // Endpoint for DNS
	http.Handle("/udp-query", limiter.Limit(udpHandler))   // Endpoint for UDP

	// Start HTTPS server in a goroutine
	go func() {
		logger.Info.Println("External HTTPS server listening on :443 with rate limiting enabled")
		if err := http.ListenAndServeTLS(":443", "cert.pem", "key.pem", nil); err != nil {
			logger.Error.Fatalf("HTTPS server failed: %v", err)
		}
	}()

	// Start UDP DNS server
	udpAddr, err := net.ResolveUDPAddr("udp", ":53")
	if err != nil {
		return fmt.Errorf("failed to resolve UDP address: %w", err)
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on UDP port 53: %w", err)
	}
	defer udpConn.Close()

	logger.Info.Println("External UDP server listening on :53")

	for {
		buf := make([]byte, 512) // DNS packets are typically small
		n, remoteAddr, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			logger.Error.Printf("Failed to read from UDP conn: %v", err)
			continue
		}
		go handleRawUdpPacket(udpConn, remoteAddr, buf[:n], key)
	}

}

func handleSearchRequest(key []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		clientAddr := r.RemoteAddr

		encryptedData, err := masquerade.UnwrapFromHttpRequest(r)
		if err != nil {
			msg := fmt.Sprintf("[%s] Invalid request format: %v", clientAddr, err)
			http.Error(w, msg, http.StatusBadRequest)
			logger.Error.Println(msg)
			return
		}

		decryptedData, err := crypto.Decrypt(encryptedData, key)
		if err != nil {
			msg := fmt.Sprintf("[%s] Decryption failed: %v", clientAddr, err)
			http.Error(w, "Forbidden", http.StatusForbidden)
			logger.Error.Println(msg)
			return
		}

		// Parse the destination address from the payload
		parts := bytes.SplitN(decryptedData, []byte("\n"), 2)
		if len(parts) != 2 {
			msg := fmt.Sprintf("[%s] Invalid payload format", clientAddr)
			http.Error(w, msg, http.StatusBadRequest)
			logger.Error.Println(msg)
			return
		}
		destination := string(parts[0])
		payload := parts[1]

		logger.Info.Printf("[%s] Tunneling to %s", clientAddr, destination)

		targetConn, err := connPool.Get(destination)
		if err != nil {
			msg := fmt.Sprintf("[%s] Failed to get connection for target service %s: %v", clientAddr, destination, err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			logger.Error.Println(msg)
			return
		}
		defer connPool.Put(targetConn)

		_, err = targetConn.Write(payload)
		if err != nil {
			msg := fmt.Sprintf("[%s] Failed to write to target service: %v", clientAddr, err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			logger.Error.Println(msg)
			return
		}

		respData, err := io.ReadAll(targetConn)
		if err != nil {
			msg := fmt.Sprintf("[%s] Failed to read from target service: %v", clientAddr, err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			logger.Error.Println(msg)
			return
		}

		encryptedResp, err := crypto.Encrypt(respData, key)
		if err != nil {
			msg := fmt.Sprintf("[%s] Encryption failed: %v", clientAddr, err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			logger.Error.Println(msg)
			return
		}

		response := masquerade.WrapInRandomHttpResponse(encryptedResp)
		logger.Info.Printf("[%s] Responded to search request with %s", clientAddr, response.Header.Get("Content-Type"))
		response.Header.Write(w)
		io.Copy(w, response.Body)
	}
}

func handlePingRequest(key []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		clientAddr := r.RemoteAddr

		encryptedPing, err := masquerade.UnwrapFromHttpRequest(r)
		if err != nil {
			msg := fmt.Sprintf("[%s] Invalid ping request: %v", clientAddr, err)
			http.Error(w, msg, http.StatusBadRequest)
			logger.Error.Println(msg)
			return
		}

		ping, err := crypto.Decrypt(encryptedPing, key)
		if err != nil || string(ping) != "SEARCH_TUNNEL_PING" {
			msg := fmt.Sprintf("[%s] Ping authentication failed", clientAddr)
			http.Error(w, "Forbidden", http.StatusForbidden)
			logger.Error.Println(msg)
			return
		}

		pong, _ := crypto.Encrypt([]byte("SEARCH_TUNNEL_PONG"), key)
		response := masquerade.WrapInRandomHttpResponse(pong)
		logger.Info.Printf("[%s] Responded to ping request with %s", clientAddr, response.Header.Get("Content-Type"))
		response.Header.Write(w)
		io.Copy(w, response.Body)
	}
}

func handleDnsRequest(key []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		clientAddr := r.RemoteAddr

		encryptedData, err := masquerade.UnwrapFromHttpRequest(r)
		if err != nil {
			msg := fmt.Sprintf("[%s] Invalid DNS request format: %v", clientAddr, err)
			http.Error(w, msg, http.StatusBadRequest)
			logger.Error.Println(msg)
			return
		}

		decryptedData, err := crypto.Decrypt(encryptedData, key)
		if err != nil {
			msg := fmt.Sprintf("[%s] DNS decryption failed: %v", clientAddr, err)
			http.Error(w, "Forbidden", http.StatusForbidden)
			logger.Error.Println(msg)
			return
		}

		dnsClient := new(dns.Client)
		originalMsg := new(dns.Msg)
		if err := originalMsg.Unpack(decryptedData); err != nil {
			msg := fmt.Sprintf("[%s] DNS unpack failed: %v", clientAddr, err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			logger.Error.Println(msg)
			return
		}

		respMsg, _, err := dnsClient.Exchange(originalMsg, "8.8.8.8:53")
		if err != nil {
			msg := fmt.Sprintf("[%s] Failed to query public DNS: %v", clientAddr, err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			logger.Error.Println(msg)
			return
		}

		packedResp, err := respMsg.Pack()
		if err != nil {
			msg := fmt.Sprintf("[%s] Failed to pack DNS response: %v", clientAddr, err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			logger.Error.Println(msg)
			return
		}

		encryptedResp, err := crypto.Encrypt(packedResp, key)
		if err != nil {
			msg := fmt.Sprintf("[%s] DNS encryption failed: %v", clientAddr, err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			logger.Error.Println(msg)
			return
		}

		response := masquerade.WrapInRandomHttpResponse(encryptedResp)
		logger.Info.Printf("[%s] Responded to DNS request with %s", clientAddr, response.Header.Get("Content-Type"))
		response.Header.Write(w)
		io.Copy(w, response.Body)
	}
}

func handleUdpRequest(key []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		clientAddr := r.RemoteAddr

		encryptedData, err := masquerade.UnwrapFromHttpRequest(r)
		if err != nil {
			msg := fmt.Sprintf("[%s] Invalid UDP request format: %v", clientAddr, err)
			http.Error(w, msg, http.StatusBadRequest)
			logger.Error.Println(msg)
			return
		}

		decryptedData, err := crypto.Decrypt(encryptedData, key)
		if err != nil {
			msg := fmt.Sprintf("[%s] UDP decryption failed: %v", clientAddr, err)
			http.Error(w, "Forbidden", http.StatusForbidden)
			logger.Error.Println(msg)
			return
		}

		parts := bytes.SplitN(decryptedData, []byte("\n"), 2)
		if len(parts) != 2 {
			msg := fmt.Sprintf("[%s] Invalid UDP payload format", clientAddr)
			http.Error(w, msg, http.StatusBadRequest)
			logger.Error.Println(msg)
			return
		}
		destination := string(parts[0])
		payload := parts[1]

		logger.Info.Printf("[%s] UDP Tunneling to %s", clientAddr, destination)

		conn, err := net.Dial("udp", destination)
		if err != nil {
			msg := fmt.Sprintf("[%s] Failed to connect to UDP target %s: %v", clientAddr, destination, err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			logger.Error.Println(msg)
			return
		}
		defer conn.Close()

		conn.SetReadDeadline(time.Now().Add(5 * time.Second)) // 5 second timeout for UDP response

		_, err = conn.Write(payload)
		if err != nil {
			msg := fmt.Sprintf("[%s] Failed to write to UDP target: %v", clientAddr, err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			logger.Error.Println(msg)
			return
		}

		respData := make([]byte, 4096) // Allocate buffer for response
		n, err := conn.Read(respData)
		if err != nil {
			msg := fmt.Sprintf("[%s] Failed to read from UDP target: %v", clientAddr, err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			logger.Error.Println(msg)
			return
		}

		encryptedResp, err := crypto.Encrypt(respData[:n], key)
		if err != nil {
			msg := fmt.Sprintf("[%s] UDP encryption failed: %v", clientAddr, err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			logger.Error.Println(msg)
			return
		}

		response := masquerade.WrapInRandomHttpResponse(encryptedResp)
		logger.Info.Printf("[%s] Responded to UDP request with %s", clientAddr, response.Header.Get("Content-Type"))
		response.Header.Write(w)
		io.Copy(w, response.Body)
	}
}

func handleRawUdpPacket(conn *net.UDPConn, remoteAddr *net.UDPAddr, data []byte, key []byte) {
	// First, try to unwrap it as our custom protocol
	encryptedPayload, err := masquerade.UnwrapFromDnsQuery(data)
	if err == nil {
		// If successful, it's a tunneled packet. Decrypt it.
		decryptedData, err := crypto.Decrypt(encryptedPayload, key)
		if err != nil {
			logger.Error.Printf("[%s] Raw UDP decryption failed: %v", remoteAddr, err)
			return
		}

		// Parse the session ID and destination address
		headerAndPayload := bytes.SplitN(decryptedData, []byte("\n"), 2)
		if len(headerAndPayload) != 2 {
			logger.Error.Printf("[%s] Invalid multi-dest UDP payload format (no newline)", remoteAddr)
			return
		}
		header := headerAndPayload[0]
		payload := headerAndPayload[1]

		sessionAndDest := bytes.SplitN(header, []byte(":"), 2)
		if len(sessionAndDest) != 2 {
			logger.Error.Printf("[%s] Invalid multi-dest UDP header format (no colon)", remoteAddr)
			return
		}
		sessionID := string(sessionAndDest[0])
		destination := string(sessionAndDest[1])

		logger.Info.Printf("[%s] Raw UDP Tunneling for session %s to %s", remoteAddr, sessionID, destination)

		// Connect to the target destination
		targetConn, err := net.Dial("udp", destination)
		if err != nil {
			logger.Error.Printf("[%s] Failed to connect to UDP target %s: %v", remoteAddr, destination, err)
			return
		}
		defer targetConn.Close()

		targetConn.SetReadDeadline(time.Now().Add(5 * time.Second))

		_, err = targetConn.Write(payload)
		if err != nil {
			logger.Error.Printf("[%s] Failed to write to UDP target: %v", remoteAddr, err)
			return
		}

		// Read the response from the target
		respData := make([]byte, 4096)
		n, err := targetConn.Read(respData)
		if err != nil {
			// Don't log an error if it's just a timeout, which is common for UDP
			if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
				logger.Error.Printf("[%s] Failed to read from UDP target: %v", remoteAddr, err)
			}
			return
		}

		// Prepend the session ID to the response and encrypt
		clientResponsePayload := append([]byte(sessionID+":"), respData[:n]...)
		encryptedResp, err := crypto.Encrypt(clientResponsePayload, key)
		if err != nil {
			logger.Error.Printf("[%s] Raw UDP response encryption failed: %v", remoteAddr, err)
			return
		}

		// We need the original query to formulate a valid DNS response
		queryMsg := new(dns.Msg)
		_ = queryMsg.Unpack(data) // We already know this will succeed

		dnsResp, err := masquerade.WrapInDnsResponse(queryMsg, encryptedResp)
		if err != nil {
			logger.Error.Printf("[%s] Failed to wrap DNS response: %v", remoteAddr, err)
			return
		}

		conn.WriteToUDP(dnsResp, remoteAddr)
		return
	}

	// If unwrapping fails, treat it as a legitimate DNS query and forward it
	logger.Info.Printf("[%s] Forwarding legitimate DNS query", remoteAddr)
	dnsClient := new(dns.Client)
	originalMsg := new(dns.Msg)
	if err := originalMsg.Unpack(data); err != nil {
		logger.Error.Printf("[%s] Failed to unpack legitimate DNS query: %v", remoteAddr, err)
		return
	}

	respMsg, _, err := dnsClient.Exchange(originalMsg, "8.8.8.8:53")
	if err != nil {
		logger.Error.Printf("[%s] Failed to forward DNS query: %v", remoteAddr, err)
		return
	}

	packedResp, err := respMsg.Pack()
	if err != nil {
		logger.Error.Printf("[%s] Failed to pack forwarded DNS response: %v", remoteAddr, err)
		return
	}

	conn.WriteToUDP(packedResp, remoteAddr)
}

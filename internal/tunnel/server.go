package tunnel

import (
	"fmt"
	"io"
	"net"
	"net/http"

	"github.com/ehsanking/search-tunnel/internal/config"
	"github.com/ehsanking/search-tunnel/internal/crypto"
	"github.com/ehsanking/search-tunnel/internal/masquerade"
	"github.com/miekg/dns"
)

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

	http.Handle("/search", limiter.Limit(searchHandler))
	http.Handle("/favicon.ico", limiter.Limit(pingHandler)) // Also rate-limit pings
	http.Handle("/dns-query", limiter.Limit(dnsHandler))   // Endpoint for DNS

	fmt.Println("External HTTPS server listening on :443 with rate limiting enabled")
	return http.ListenAndServeTLS(":443", "cert.pem", "key.pem", nil)
}

func handleSearchRequest(key []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		clientAddr := r.RemoteAddr

		encryptedData, err := masquerade.UnwrapFromHttpRequest(r)
		if err != nil {
			msg := fmt.Sprintf("[%s] Invalid request format: %v", clientAddr, err)
			http.Error(w, msg, http.StatusBadRequest)
			fmt.Println(msg)
			return
		}

		decryptedData, err := crypto.Decrypt(encryptedData, key)
		if err != nil {
			msg := fmt.Sprintf("[%s] Decryption failed: %v", clientAddr, err)
			http.Error(w, "Forbidden", http.StatusForbidden)
			fmt.Println(msg)
			return
		}

		targetConn, err := net.Dial("tcp", "tcpbin.com:4242")
		if err != nil {
			msg := fmt.Sprintf("[%s] Failed to connect to target service: %v", clientAddr, err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			fmt.Println(msg)
			return
		}
		defer targetConn.Close()

		_, err = targetConn.Write(decryptedData)
		if err != nil {
			msg := fmt.Sprintf("[%s] Failed to write to target service: %v", clientAddr, err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			fmt.Println(msg)
			return
		}

		respData, err := io.ReadAll(targetConn)
		if err != nil {
			msg := fmt.Sprintf("[%s] Failed to read from target service: %v", clientAddr, err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			fmt.Println(msg)
			return
		}

		encryptedResp, err := crypto.Encrypt(respData, key)
		if err != nil {
			msg := fmt.Sprintf("[%s] Encryption failed: %v", clientAddr, err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			fmt.Println(msg)
			return
		}

		response := masquerade.WrapInRandomHttpResponse(encryptedResp)
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
			fmt.Println(msg)
			return
		}

		ping, err := crypto.Decrypt(encryptedPing, key)
		if err != nil || string(ping) != "SEARCH_TUNNEL_PING" {
			msg := fmt.Sprintf("[%s] Ping authentication failed", clientAddr)
			http.Error(w, "Forbidden", http.StatusForbidden)
			fmt.Println(msg)
			return
		}

		pong, _ := crypto.Encrypt([]byte("SEARCH_TUNNEL_PONG"), key)
		response := masquerade.WrapInRandomHttpResponse(pong)
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
			fmt.Println(msg)
			return
		}

		decryptedData, err := crypto.Decrypt(encryptedData, key)
		if err != nil {
			msg := fmt.Sprintf("[%s] DNS decryption failed: %v", clientAddr, err)
			http.Error(w, "Forbidden", http.StatusForbidden)
			fmt.Println(msg)
			return
		}

		dnsClient := new(dns.Client)
		originalMsg := new(dns.Msg)
		if err := originalMsg.Unpack(decryptedData); err != nil {
			msg := fmt.Sprintf("[%s] DNS unpack failed: %v", clientAddr, err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			fmt.Println(msg)
			return
		}

		respMsg, _, err := dnsClient.Exchange(originalMsg, "8.8.8.8:53")
		if err != nil {
			msg := fmt.Sprintf("[%s] Failed to query public DNS: %v", clientAddr, err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			fmt.Println(msg)
			return
		}

		packedResp, err := respMsg.Pack()
		if err != nil {
			msg := fmt.Sprintf("[%s] Failed to pack DNS response: %v", clientAddr, err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			fmt.Println(msg)
			return
		}

		encryptedResp, err := crypto.Encrypt(packedResp, key)
		if err != nil {
			msg := fmt.Sprintf("[%s] DNS encryption failed: %v", clientAddr, err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			fmt.Println(msg)
			return
		}

		response := masquerade.WrapInRandomHttpResponse(encryptedResp)
		response.Header.Write(w)
		io.Copy(w, response.Body)
	}
}

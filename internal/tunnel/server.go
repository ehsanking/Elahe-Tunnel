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
	"context"
	"crypto/tls"
	"github.com/pion/dtls/v2"
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

	// Start DTLS server
	cert, err := tls.LoadX509KeyPair("cert.pem", "key.pem")
	if err != nil {
		return fmt.Errorf("failed to load TLS keypair: %w", err)
	}

	udpAddr, err := net.ResolveUDPAddr("udp", ":443") // DTLS standard port
	if err != nil {
		return fmt.Errorf("failed to resolve UDP address: %w", err)
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on UDP port 443: %w", err)
	}

	dtlsListener, err := dtls.NewListener(udpConn, &dtls.Config{
		Certificates: []tls.Certificate{cert},
	})
	if err != nil {
		return fmt.Errorf("failed to create DTLS listener: %w", err)
	}
	defer dtlsListener.Close()

	logger.Info.Println("External DTLS server listening on :443")

	for {
		dtlsConn, err := dtlsListener.Accept()
		if err != nil {
			logger.Error.Printf("Failed to accept DTLS connection: %v", err)
			continue
		}
		go handleDtlsConnection(dtlsConn)
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

		targetConn, err := pool.Get(destination)
		if err != nil {
			msg := fmt.Sprintf("[%s] Failed to get connection for target service %s: %v", clientAddr, destination, err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			logger.Error.Println(msg)
			return
		}
		defer pool.Put(targetConn)

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

func handleDtlsConnection(conn net.Conn) {
	defer conn.Close()
	clientAddr := conn.RemoteAddr()
	logger.Info.Printf("[%s] Accepted DTLS connection", clientAddr)

	// Each DTLS connection can handle multiple UDP destinations.
	// We'll use a map to keep track of the outbound connections.
	udpConns := make(map[string]net.Conn)
	defer func() {
		for _, c := range udpConns {
			c.Close()
		}
	}()

	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			logger.Error.Printf("[%s] DTLS read error: %v", clientAddr, err)
			return
		}

		// The client sends the destination address prepended to the payload.
		parts := bytes.SplitN(buf[:n], []byte("\n"), 2)
		if len(parts) != 2 {
			logger.Error.Printf("[%s] Invalid DTLS payload format", clientAddr)
			continue
		}
		destination := string(parts[0])
		payload := parts[1]

		// Get or create the outbound UDP connection for this destination.
		outboundConn, ok := udpConns[destination]
		if !ok {
			logger.Info.Printf("[%s] Creating new UDP connection to %s", clientAddr, destination)
			outboundConn, err = net.Dial("udp", destination)
			if err != nil {
				logger.Error.Printf("[%s] Failed to connect to UDP target %s: %v", clientAddr, destination, err)
				continue
			}
			udpConns[destination] = outboundConn

			// Start a goroutine to read responses from this new connection.
			go func(dest string, c net.Conn) {
				respBuf := make([]byte, 4096)
				for {
					n, err := c.Read(respBuf)
					if err != nil {
						return // Connection is likely closed.
					}
					// Prepend the original destination to the response and send it back.
					response := append([]byte(dest+"\n"), respBuf[:n]...)
					if _, err := conn.Write(response); err != nil {
						logger.Error.Printf("[%s] DTLS write error: %v", clientAddr, err)
						return
					}
				}
			}(destination, outboundConn)
		}

		// Forward the payload to the destination.
		_, err = outboundConn.Write(payload)
		if err != nil {
			logger.Error.Printf("[%s] Failed to write to UDP target: %v", clientAddr, err)
		}
	}
}

package tunnel

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/ehsanking/elahe-tunnel/internal/crypto"
	"github.com/ehsanking/elahe-tunnel/internal/logger"
	"github.com/ehsanking/elahe-tunnel/internal/masquerade"
	"github.com/ehsanking/elahe-tunnel/internal/stats"
	"github.com/pion/dtls/v2"
	"golang.org/x/time/rate"
)

// RunServer starts the external node server.
func RunServer(key []byte) error {
	limiter := rate.NewLimiter(rate.Limit(10), 50) // Allow 10 requests per second, with a burst of 50

	pingHandler := http.HandlerFunc(handlePingRequest(key))
	http.Handle("/favicon.ico", limitMiddleware(limiter, pingHandler))

	tunnelHandler := http.HandlerFunc(handleTunnelRequest(key))
	http.Handle("/", limitMiddleware(limiter, tunnelHandler))

	// Start the DTLS server in a separate goroutine.
	go runDtlsServer(key)

	logger.Info.Println("External server listening on :443")
	return http.ListenAndServeTLS(":443", "cert.pem", "key.pem", nil)
}

func limitMiddleware(limiter *rate.Limiter, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !limiter.Allow() {
			http.Error(w, http.StatusText(http.StatusTooManyRequests), http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func runDtlsServer(key []byte) {
	udpAddr, err := net.ResolveUDPAddr("udp", ":443")
	if err != nil {
		logger.Error.Fatalf("Failed to resolve UDP address: %v", err)
	}

	cert, err := tls.LoadX509KeyPair("cert.pem", "key.pem")
	if err != nil {
		logger.Error.Fatalf("Failed to load TLS cert for DTLS: %v", err)
	}

	dtlsListener, err := dtls.Listen("udp", udpAddr, &dtls.Config{
		Certificates:         []tls.Certificate{cert},
		InsecureSkipVerify:   true, // Not needed for server, but good practice
		ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
	})
	if err != nil {
		logger.Error.Fatalf("DTLS server failed to start: %v", err)
	}

	logger.Info.Println("DTLS server listening on :443")

	for {
		conn, err := dtlsListener.Accept()
		if err != nil {
			logger.Error.Printf("DTLS accept error: %v", err)
			continue
		}
		go handleDtlsConnection(conn, key)
	}
}

func handleDtlsConnection(conn net.Conn, key []byte) {
	defer conn.Close()
	buf := make([]byte, 4096)

	// Map to cache UDP connections: destination -> net.Conn
	udpConns := make(map[string]net.Conn)
	defer func() {
		for _, c := range udpConns {
			c.Close()
		}
	}()

	for {
		n, err := conn.Read(buf)
		if err != nil {
			if err != io.EOF {
				logger.Error.Printf("DTLS read error: %v", err)
			}
			return
		}

		parts := bytes.SplitN(buf[:n], []byte("\n"), 2)
		if len(parts) != 2 {
			logger.Error.Println("Invalid DTLS request format")
			continue
		}
		destination := string(parts[0])
		payload := parts[1]
		stats.AddUdpBytesIn(uint64(len(payload)))

		targetConn, ok := udpConns[destination]
		if !ok {
			targetConn, err = net.DialTimeout("udp", destination, 5*time.Second)
			if err != nil {
				logger.Error.Printf("Failed to connect to UDP destination %s: %v", destination, err)
				continue
			}
			udpConns[destination] = targetConn

			// Start a goroutine to read from this UDP connection and forward back to DTLS
			go func(dest string, c net.Conn) {
				respBuf := make([]byte, 4096)
				for {
					c.SetReadDeadline(time.Now().Add(30 * time.Second))
					rn, rerr := c.Read(respBuf)
					if rerr != nil {
						// If error, we might want to close and remove from map, 
						// but for simplicity in this loop we just stop reading.
						// The main loop will eventually close it when DTLS closes.
						return
					}
					
					// Prepend destination for client-side routing and send back
					// We need to synchronize writes to conn if it's not thread safe?
					// net.Conn is thread safe.
					response := append([]byte(dest+"\n"), respBuf[:rn]...)
					_, werr := conn.Write(response)
					if werr != nil {
						return
					}
					stats.AddUdpBytesOut(uint64(len(response)))
				}
			}(destination, targetConn)
		}

		_, err = targetConn.Write(payload)
		if err != nil {
			logger.Error.Printf("Failed to write to UDP destination: %v", err)
		}
	}
}

func handleTunnelRequest(key []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		encrypted, err := masquerade.UnwrapFromHttpRequest(r)
		if err != nil {
			http.Error(w, "Invalid request format", http.StatusBadRequest)
			return
		}

		decrypted, err := crypto.Decrypt(encrypted, key)
		if err != nil {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		if r.Header.Get("X-Tunnel-Type") == "dns" {
			handleDnsRequest(w, decrypted, key)
			return
		}

		stats.AddTcpBytesIn(uint64(len(decrypted)))

		parts := bytes.SplitN(decrypted, []byte("\n"), 2)
		if len(parts) != 2 {
			http.Error(w, "Invalid payload format", http.StatusBadRequest)
			return
		}
		destination := string(parts[0])
		payload := parts[1]

		targetConn, err := net.DialTimeout("tcp", destination, 5*time.Second)
		if err != nil {
			msg := fmt.Sprintf("Failed to connect to destination: %v", err)
			http.Error(w, msg, http.StatusServiceUnavailable)
			return
		}
		defer targetConn.Close()

		_, err = targetConn.Write(payload)
		if err != nil {
			http.Error(w, "Failed to write to destination", http.StatusServiceUnavailable)
			return
		}

		respData, err := io.ReadAll(targetConn)
		if err != nil {
			http.Error(w, "Failed to read from destination", http.StatusServiceUnavailable)
			return
		}

		encryptedResp, err := crypto.Encrypt(respData, key)
		stats.AddTcpBytesOut(uint64(len(encryptedResp)))
		if err != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		masquerade.WrapInRandomHttpResponse(encryptedResp).Write(w)
	}
}

func handleDnsRequest(w http.ResponseWriter, query []byte, key []byte) {
	stats.AddDnsQuery()
	// Forward to a real DNS server
	dnsServer := "8.8.8.8:53"
	conn, err := net.Dial("udp", dnsServer)
	if err != nil {
		stats.AddDnsError()
		http.Error(w, "DNS server unreachable", http.StatusServiceUnavailable)
		return
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))
	_, err = conn.Write(query)
	if err != nil {
		stats.AddDnsError()
		http.Error(w, "Failed to write to DNS server", http.StatusServiceUnavailable)
		return
	}

	resp := make([]byte, 512)
	n, err := conn.Read(resp)
	if err != nil {
		stats.AddDnsError()
		http.Error(w, "Failed to read from DNS server", http.StatusServiceUnavailable)
		return
	}

	encryptedResp, err := crypto.Encrypt(resp[:n], key)
	if err != nil {
		http.Error(w, "Internal encryption error", http.StatusInternalServerError)
		return
	}
	masquerade.WrapInRandomHttpResponse(encryptedResp).Write(w)
}

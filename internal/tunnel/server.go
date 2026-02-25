package tunnel

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/ehsanking/elahe-tunnel/internal/config"
	"github.com/ehsanking/elahe-tunnel/internal/crypto"
	"github.com/ehsanking/elahe-tunnel/internal/logger"
	"github.com/ehsanking/elahe-tunnel/internal/masquerade"
	"github.com/ehsanking/elahe-tunnel/internal/stats"
	"github.com/pion/dtls/v2"
	"golang.org/x/time/rate"
)

// RunServer starts the external node server.
func RunServer(cfg *config.Config) error {
	key, err := crypto.DecodeBase64Key(cfg.ConnectionKey)
	if err != nil {
		return fmt.Errorf("failed to decode key: %w", err)
	}

	port := cfg.TunnelPort
	if port == 0 {
		port = 443
	}

	limiter := rate.NewLimiter(rate.Limit(10), 50) // Allow 10 requests per second, with a burst of 50

	pingHandler := http.HandlerFunc(handlePingRequest(key))
	http.Handle("/favicon.ico", limitMiddleware(limiter, pingHandler))

	tunnelHandler := http.HandlerFunc(handleTunnelRequest(key))
	http.Handle("/", limitMiddleware(limiter, tunnelHandler))

	// Start the DTLS server in a separate goroutine.
	go runDtlsServer(key, port)

	addr := fmt.Sprintf(":%d", port)
	logger.Info.Printf("External server listening on %s\n", addr)
	err = http.ListenAndServeTLS(addr, "cert.pem", "key.pem", nil)
	if err != nil {
		return fmt.Errorf("server failed: %w. Check if port %d is free and you have root privileges", err, port)
	}
	return nil
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

func runDtlsServer(key []byte, port int) {
	udpAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", port))
	if err != nil {
		logger.Error.Printf("Failed to resolve UDP address: %v", err)
		return
	}

	// DTLS with PSK does not require certificates.
	// Providing certificates with PSK-only cipher suites causes an error.
	dtlsListener, err := dtls.Listen("udp", udpAddr, &dtls.Config{
		PSK: func(hint []byte) ([]byte, error) {
			return key, nil
		},
		PSKIdentityHint: []byte("elahe-tunnel"),
		CipherSuites: []dtls.CipherSuiteID{
			dtls.TLS_PSK_WITH_AES_128_GCM_SHA256,
			dtls.TLS_PSK_WITH_AES_128_CCM_8,
		},
		ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
	})
	if err != nil {
		logger.Error.Printf("DTLS server failed to start: %v", err)
		return
	}

	logger.Info.Printf("DTLS server listening on :%d\n", port)

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

var (
	// Session map: SessionID -> net.Conn
	sessionMap  sync.Map
	// Mutex to ensure we don't dial multiple times for the same session concurrently
	sessionLocks sync.Map
	// Last activity time for each session
	sessionActivity sync.Map
)

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

		// Expected format: SessionID|Destination|Payload
		parts := bytes.SplitN(decrypted, []byte("|"), 3)
		if len(parts) != 3 {
			// Fallback for backward compatibility or simple checks: Destination|Payload
			// But for efficiency we really need sessions.
			// Let's assume the old format is NOT supported for the efficient version.
			http.Error(w, "Invalid payload format (v2 required)", http.StatusBadRequest)
			return
		}

		sessionID := string(parts[0])
		destination := string(parts[1])
		payload := parts[2]

		var targetConn net.Conn
		
		// Check if session exists
		if val, ok := sessionMap.Load(sessionID); ok {
			targetConn = val.(net.Conn)
		} else {
			// Lock for this session to avoid race conditions during dial
			lock, _ := sessionLocks.LoadOrStore(sessionID, &sync.Mutex{})
			mu := lock.(*sync.Mutex)
			mu.Lock()
			
			// Double check
			if val, ok := sessionMap.Load(sessionID); ok {
				targetConn = val.(net.Conn)
				mu.Unlock()
			} else {
				// Dial new connection
				// Use a longer timeout for the connection itself
				d := net.Dialer{Timeout: 10 * time.Second}
				conn, err := d.Dial("tcp", destination)
				if err != nil {
					mu.Unlock()
					msg := fmt.Sprintf("Failed to connect to destination: %v", err)
					http.Error(w, msg, http.StatusServiceUnavailable)
					return
				}
				targetConn = conn
				sessionMap.Store(sessionID, targetConn)
				mu.Unlock()
				
				// Start a cleanup routine for this session with idle timeout
				go func(sid string, c net.Conn) {
					ticker := time.NewTicker(1 * time.Minute)
					defer ticker.Stop()
					
					for {
						select {
						case <-ticker.C:
							// Check if session is still in map (might have been deleted on error)
							if _, ok := sessionMap.Load(sid); !ok {
								return
							}
							
							// If idle for more than 10 minutes, close it
							last, ok := sessionActivity.Load(sid)
							if !ok || time.Now().Unix()-last.(int64) > 600 {
								c.Close()
								sessionMap.Delete(sid)
								sessionLocks.Delete(sid)
								sessionActivity.Delete(sid)
								return
							}
						}
					}
				}(sessionID, targetConn)
			}
		}

		// Update activity time
		sessionActivity.Store(sessionID, time.Now().Unix())

		// Write payload to target
		if len(payload) > 0 {
			targetConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			_, err = targetConn.Write(payload)
			if err != nil {
				// Connection broken
				targetConn.Close()
				sessionMap.Delete(sessionID)
				http.Error(w, "Failed to write to destination", http.StatusServiceUnavailable)
				return
			}
		}

		// Read response from target
		// If payload was empty, this is a polling request, so we can wait longer
		readTimeout := 2 * time.Second
		if len(payload) == 0 {
			readTimeout = 10 * time.Second
		}
		targetConn.SetReadDeadline(time.Now().Add(readTimeout))
		
		// Use a buffer from a pool ideally, but for now 32KB is fine
		readBuf := make([]byte, 32*1024) 
		n, err := targetConn.Read(readBuf)
		if err != nil {
			if err != io.EOF && !os.IsTimeout(err) {
				// Real error
				targetConn.Close()
				sessionMap.Delete(sessionID)
				// If we read 0 bytes and got error, return error.
				// If we read > 0 bytes, we should return them.
			}
			// If timeout, it just means no more data right now, which is fine.
		}

		if n > 0 {
			encryptedResp, err := crypto.Encrypt(readBuf[:n], key)
			if err != nil {
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}
			stats.AddTcpBytesOut(uint64(len(encryptedResp)))
			masquerade.WrapInRandomHttpResponse(encryptedResp).Write(w)
		} else {
			// No data read (timeout or EOF with 0 bytes)
			// Send empty success response
			// We must send something so the client knows the request succeeded
			encryptedResp, _ := crypto.Encrypt([]byte{}, key)
			masquerade.WrapInRandomHttpResponse(encryptedResp).Write(w)
		}
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

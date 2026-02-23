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
	http.Handle("/favicon.ico", limiter.Limit(pingHandler))

	tunnelHandler := http.HandlerFunc(handleTunnelRequest(key))
	http.Handle("/", limiter.Limit(tunnelHandler))

	// Start the DTLS server in a separate goroutine.
	go runDtlsServer(key)

	logger.Info.Println("External server listening on :443")
	return http.ListenAndServeTLS(":443", "cert.pem", "key.pem", nil)
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
	n, err := conn.Read(buf)
	if err != nil {
		logger.Error.Printf("DTLS read error: %v", err)
		return
	}

	parts := bytes.SplitN(buf[:n], []byte("\n"), 2)
	if len(parts) != 2 {
		logger.Error.Println("Invalid DTLS request format")
		return
	}
	destination := string(parts[0])
	payload := parts[1]
	stats.AddUdpBytesIn(uint64(len(payload)))

	targetConn, err := net.DialTimeout("udp", destination, 5*time.Second)
	if err != nil {
		logger.Error.Printf("Failed to connect to UDP destination %s: %v", destination, err)
		return
	}
	defer targetConn.Close()

	_, err = targetConn.Write(payload)
	if err != nil {
		logger.Error.Printf("Failed to write to UDP destination: %v", err)
		return
	}

	respBuf := make([]byte, 4096)
	n, err = targetConn.Read(respBuf)
	if err != nil {
		logger.Error.Printf("Failed to read from UDP destination: %v", err)
		return
	}

	// Prepend destination for client-side routing and send back
	response := append([]byte(destination+"\n"), respBuf[:n]...)
	bytesWritten, err := conn.Write(response)
	stats.AddUdpBytesOut(uint64(bytesWritten))
	if err != nil {
		logger.Error.Printf("DTLS write error: %v", err)
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
		stats.AddTcpBytesIn(uint64(len(decrypted)))
		if err != nil {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

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

		masquerade.WrapInRandomHttpResponse(w, encryptedResp)
	}
}

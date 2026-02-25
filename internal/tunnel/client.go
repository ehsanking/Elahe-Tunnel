package tunnel

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/ehsanking/elahe-tunnel/internal/config"
	"github.com/ehsanking/elahe-tunnel/internal/crypto"
	"github.com/ehsanking/elahe-tunnel/internal/logger"
	"github.com/ehsanking/elahe-tunnel/internal/masquerade"
	"github.com/ehsanking/elahe-tunnel/internal/stats"
	"github.com/ehsanking/elahe-tunnel/internal/web"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"sync/atomic"
	"github.com/pion/dtls/v2"
)

// RunClient starts the internal node client.
func RunClient(cfg *config.Config) error {
	// Start the status server
	go runStatusServer(cfg)

	if cfg.WebPanelEnabled {
		go web.StartServer(cfg)
	}

	// If listen address is provided, start the proxy server
	if cfg.TunnelListenAddr != "" {
		go runProxyServer(cfg)
	}

	key, err := crypto.DecodeBase64Key(cfg.ConnectionKey)
	if err != nil {
		return fmt.Errorf("invalid connection key: %w", err)
	}

	port := cfg.TunnelPort
	if port == 0 {
		port = 443
	}

	// Create a custom dialer to resolve the remote host through the tunnel itself
	netDialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	// Create a shared HTTP client with a custom transport and QoS
	tr := &http.Transport{
		// We still need to skip verification for the self-signed cert
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		// Use our custom dialer
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// If we're dialing the remote host, we need to resolve it securely
			targetAddr := fmt.Sprintf("%s:%d", cfg.RemoteHost, port)
			if addr == targetAddr {
				return netDialer.DialContext(ctx, network, addr)
			}
			// For all other addresses, use the default dialer
			return netDialer.DialContext(ctx, network, addr)
		},
	}
	
	// Wrap the transport with QoS, allowing 50 concurrent TCP requests
	qosTr := NewQoSTransport(tr, 50)
	httpClient := &http.Client{Transport: qosTr, Timeout: 15 * time.Second}

	// Perform an initial, insecure DNS lookup for the remote host
	ips, err := net.LookupIP(cfg.RemoteHost)
	if err != nil || len(ips) == 0 {
		return fmt.Errorf("could not resolve remote host: %w", err)
	}
	remoteIP := ips[0].String()
	fmt.Printf("Resolved remote host %s to %s\n", cfg.RemoteHost, remoteIP)

	// Start the connection manager in the background
	go manageConnection(httpClient, cfg.RemoteHost, remoteIP, key, port)

	// If enabled, start the DNS proxy
	if cfg.DnsProxyEnabled {
		go RunDnsProxy(53, func(query []byte) ([]byte, error) {
			return forwardDnsQuery(query, cfg, httpClient, key)
		})
	}

	// If enabled, start the UDP proxy
	if cfg.UdpProxyEnabled {
		go RunUdpProxy(9091, httpClient, cfg.RemoteHost, remoteIP, key, cfg)
	}

	// Start Tunnel Listener
	if cfg.LocalPort > 0 {
		go func() {
			addr := fmt.Sprintf("0.0.0.0:%d", cfg.LocalPort)
			fmt.Printf("Internal tunnel listening on %s -> %s\n", addr, cfg.DestinationHost)
			localListener, err := net.Listen("tcp", addr)
			if err != nil {
				fmt.Printf("Failed to listen on local port %d: %v\n", cfg.LocalPort, err)
				return
			}
			defer localListener.Close()

			for {
				localConn, err := localListener.Accept()
				if err != nil {
					fmt.Printf("Failed to accept local connection: %v\n", err)
					continue
				}
				go handleClientConnection(localConn, httpClient, remoteIP, key, cfg, cfg.DestinationHost)
			}
		}()
	}

	// Block main goroutine
	select {}
}

const socketPath = "/tmp/elahe-tunnel.sock"

// runStatusServer starts a server on a Unix domain socket to provide status updates.
func runStatusServer(cfg *config.Config) {
	// Ensure the socket doesn't already exist
	_ = os.Remove(socketPath)

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		logger.Error.Printf("Failed to create status socket: %v", err)
		return
	}
	defer listener.Close()

	logger.Info.Printf("Status server listening on %s", socketPath)

	for {
		conn, err := listener.Accept()
		if err != nil {
			logger.Error.Printf("Failed to accept status connection: %v", err)
			continue
		}
		go handleStatusRequest(conn, cfg)
	}
}

// handleStatusRequest handles a single status request from the 'status' command.
func handleStatusRequest(conn net.Conn, cfg *config.Config) {
	defer conn.Close()

	status := struct {
		UdpEnabled         bool   `json:"udp_enabled"`
		UdpDestination     string `json:"udp_destination"`
		UdpPacketsIn       uint64 `json:"udp_packets_in"`
		UdpPacketsOut      uint64 `json:"udp_packets_out"`
		UdpBytesIn         uint64 `json:"udp_bytes_in"`
		UdpBytesOut        uint64 `json:"udp_bytes_out"`
		CurrentUdpPayloadSize uint64 `json:"current_udp_payload_size"`
	}{
		UdpEnabled:     cfg.UdpProxyEnabled,
		UdpDestination: cfg.DestinationUdpHost,
		UdpPacketsIn:   atomic.LoadUint64(&udpPacketsIn),
		UdpPacketsOut:  atomic.LoadUint64(&udpPacketsOut),
		UdpBytesIn:     atomic.LoadUint64(&udpBytesIn),
		UdpBytesOut:    atomic.LoadUint64(&udpBytesOut),
		CurrentUdpPayloadSize: atomic.LoadUint64(&currentUdpPayloadSize),
	}

	jsonData, err := json.Marshal(status)
	if err != nil {
		logger.Error.Printf("Failed to marshal status data: %v", err)
		return
	}

	_, err = conn.Write(jsonData)
	if err != nil {
		logger.Error.Printf("Failed to write status data: %v", err)
	}
}

const (
	minUdpPayloadSize = 256
	maxUdpPayloadSize = 1200 // A safe value to avoid IP fragmentation
	udpSizeStep       = 32
)

var (
	udpSessionMap   = make(map[string]*net.UDPAddr)
	udpSessionMutex = &sync.Mutex{}

	// Statistics counters
	udpPacketsIn  uint64
	udpPacketsOut uint64
	udpBytesIn    uint64
	udpBytesOut   uint64

	// Dynamic payload size
	currentUdpPayloadSize uint64 = minUdpPayloadSize
)

// RunUdpProxy starts a local UDP proxy to intercept and tunnel UDP packets over DTLS.
func RunUdpProxy(localPort int, httpClient *http.Client, remoteHost, remoteIP string, key []byte, cfg *config.Config) {
	port := cfg.TunnelPort
	if port == 0 {
		port = 443
	}
	// Establish a single DTLS connection to the server.
	serverAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", remoteIP, port))
	if err != nil {
		logger.Error.Printf("Failed to resolve remote DTLS address: %v", err)
		return
	}

	dtlsConn, err := dtls.Dial("udp", serverAddr, &dtls.Config{
		PSK: func(hint []byte) ([]byte, error) {
			return key, nil
		},
		PSKIdentityHint: []byte("elahe-tunnel"),
		CipherSuites: []dtls.CipherSuiteID{
			dtls.TLS_PSK_WITH_AES_128_GCM_SHA256,
			dtls.TLS_PSK_WITH_AES_128_CCM_8,
		},
		InsecureSkipVerify: true,
	})
	if err != nil {
		logger.Error.Printf("Failed to establish DTLS connection: %v", err)
		return
	}
	defer dtlsConn.Close()

	logger.Info.Println("Established DTLS connection to server")

	// Listen for local UDP packets.
	localAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("127.0.0.1:%d", localPort))
	if err != nil {
		logger.Error.Printf("Failed to resolve local UDP address: %v", err)
		return
	}

	localConn, err := net.ListenUDP("udp", localAddr)
	if err != nil {
		logger.Error.Printf("Failed to listen on local UDP port %d: %v", localPort, err)
		return
	}
	defer localConn.Close()

	logger.Info.Printf("Internal UDP proxy listening on 127.0.0.1:%d", localPort)

	// Goroutine to handle forwarding responses from the DTLS tunnel back to local applications.
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := dtlsConn.Read(buf)
			if err != nil {
				logger.Error.Printf("DTLS read error: %v", err)
				return
			}

			// The server prepends the original destination to the response.
			parts := bytes.SplitN(buf[:n], []byte("\n"), 2)
			if len(parts) != 2 {
				logger.Error.Printf("Invalid DTLS response format")
				continue
			}
			// Note: In a real multi-client scenario, we'd need to map this back to the original local sender.
			// For now, we assume a single local client.
			// We need to look up the original sender from the session map.
			udpSessionMutex.Lock()
			originalAddr, ok := udpSessionMap[cfg.DestinationUdpHost]
			udpSessionMutex.Unlock()

			if ok {
				n, _ := localConn.WriteToUDP(parts[1], originalAddr)
				atomic.AddUint64(&udpBytesOut, uint64(n))
				atomic.AddUint64(&udpPacketsOut, 1)
			}
		}
	}()

	// Main loop to read from local applications and forward to the DTLS tunnel.
	buf := make([]byte, 4096)
	for {
		// Dynamic payload size adjustment
		currentSize := atomic.LoadUint64(&currentUdpPayloadSize)
		// Ensure we don't exceed buffer size
		if currentSize > 4096 {
			currentSize = 4096
		}
		
		n, remoteUdpAddr, err := localConn.ReadFromUDP(buf[:currentSize])
		if err != nil {
			logger.Error.Printf("Failed to read from local UDP conn: %v", err)
			continue
		}
		
		atomic.AddUint64(&udpBytesIn, uint64(n))
		atomic.AddUint64(&udpPacketsIn, 1)

		// Store the address so we can send responses back.
		udpSessionMutex.Lock()
		udpSessionMap[cfg.DestinationUdpHost] = remoteUdpAddr
		udpSessionMutex.Unlock()

		// Prepend the destination and send it over the DTLS connection.
		payload := append([]byte(cfg.DestinationUdpHost+"\n"), buf[:n]...)
		
		start := time.Now()
		if _, err := dtlsConn.Write(payload); err != nil {
			logger.Error.Printf("DTLS write error: %v", err)
			// On error, decrease payload size aggressively
			newSize := currentSize / 2
			if newSize < minUdpPayloadSize {
				newSize = minUdpPayloadSize
			}
			atomic.StoreUint64(&currentUdpPayloadSize, newSize)
			return
		}
		
		// Adjust payload size based on write duration
		duration := time.Since(start)
		if duration < 10*time.Millisecond {
			// Fast write, increase payload size
			newSize := currentSize + udpSizeStep
			if newSize > maxUdpPayloadSize {
				newSize = maxUdpPayloadSize
			}
			atomic.StoreUint64(&currentUdpPayloadSize, newSize)
		} else if duration > 100*time.Millisecond {
			// Slow write, decrease payload size
			newSize := currentSize - udpSizeStep
			if newSize < minUdpPayloadSize {
				newSize = minUdpPayloadSize
			}
			atomic.StoreUint64(&currentUdpPayloadSize, newSize)
		}
	}
}

func forwardDnsQuery(query []byte, cfg *config.Config, httpClient *http.Client, key []byte) ([]byte, error) {
	// Encrypt DNS query using AES-GCM (via crypto package)
	encrypted, err := crypto.Encrypt(query, key)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt DNS query: %v", err)
	}

	port := cfg.TunnelPort
	if port == 0 {
		port = 443
	}
	targetHost := fmt.Sprintf("%s:%d", cfg.RemoteHost, port)

	req, err := masquerade.WrapInHttpRequest(encrypted, targetHost)
	if err != nil {
		return nil, fmt.Errorf("failed to wrap DNS query in HTTP request: %v", err)
	}
	req.Header.Set("X-Tunnel-Type", "dns")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send DNS query: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned status %d", resp.StatusCode)
	}

	encryptedResp, err := masquerade.UnwrapFromHttpResponse(resp)
	if err != nil {
		return nil, fmt.Errorf("failed to unwrap DNS response: %v", err)
	}

	// Decrypt DNS response using AES-GCM (via crypto package)
	return crypto.Decrypt(encryptedResp, key)
}

func runProxyServer(cfg *config.Config) {
	listenKey, err := crypto.DecodeBase64Key(cfg.TunnelListenKey)
	if err != nil {
		logger.Error.Fatalf("Invalid listen tunnel key: %v", err)
	}

	// This key is for the *next* hop
	forwardKey, err := crypto.DecodeBase64Key(cfg.ConnectionKey)
	if err != nil {
		logger.Error.Fatalf("Invalid forward connection key: %v", err)
	}

	// Create a dedicated http client for the forward connection
	// This is important to avoid conflicts with the main client's transport
	netDialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return netDialer.DialContext(ctx, network, addr)
		},
	}
	
	// Wrap the transport with QoS, allowing 50 concurrent TCP requests
	qosTr := NewQoSTransport(tr, 50)
	forwardHttpClient := &http.Client{Transport: qosTr, Timeout: 15 * time.Second}

	proxyHandler := http.HandlerFunc(handleProxyRequest(listenKey, forwardKey, cfg, forwardHttpClient))

	http.Handle("/", proxyHandler) // Listen on all paths

	logger.Info.Printf("Internal proxy server listening on %s", cfg.TunnelListenAddr)
	if err := http.ListenAndServeTLS(cfg.TunnelListenAddr, "cert.pem", "key.pem", nil); err != nil {
		logger.Error.Fatalf("Proxy server failed: %v", err)
	}
}

func handleProxyRequest(listenKey, forwardKey []byte, cfg *config.Config, httpClient *http.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		clientAddr := r.RemoteAddr

		// 1. Unwrap and decrypt the request from the *previous* node
		encryptedData, err := masquerade.UnwrapFromHttpRequest(r)
		if err != nil {
			msg := fmt.Sprintf("[%s] Invalid proxy request format: %v", clientAddr, err)
			http.Error(w, msg, http.StatusBadRequest)
			logger.Error.Println(msg)
			return
		}

		decryptedData, err := crypto.Decrypt(encryptedData, listenKey)
		if err != nil {
			msg := fmt.Sprintf("[%s] Proxy decryption failed: %v", clientAddr, err)
			http.Error(w, "Forbidden", http.StatusForbidden)
			logger.Error.Println(msg)
			return
		}

		// 2. Re-encrypt the payload for the *next* node
		reEncryptedData, err := crypto.Encrypt(decryptedData, forwardKey)
		if err != nil {
			msg := fmt.Sprintf("[%s] Proxy re-encryption failed: %v", clientAddr, err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			logger.Error.Println(msg)
			return
		}

		// 3. Forward the request to the next node (which could be the final external server or another proxy)
		// We need to resolve the remote host IP just like the main client does
		ips, err := net.LookupIP(cfg.RemoteHost)
		if err != nil || len(ips) == 0 {
			msg := fmt.Sprintf("[%s] Could not resolve remote host for proxy: %v", clientAddr, err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			logger.Error.Println(msg)
			return
		}
		remoteIP := ips[0].String()

		forwardReq, err := masquerade.WrapInHttpRequest(reEncryptedData, cfg.RemoteHost)
		if err != nil {
			msg := fmt.Sprintf("[%s] Failed to wrap proxy forward request: %v", clientAddr, err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			logger.Error.Println(msg)
			return
		}
		forwardReq.URL.Scheme = "https"
		forwardReq.URL.Host = remoteIP

		resp, err := httpClient.Do(forwardReq)
		if err != nil {
			msg := fmt.Sprintf("[%s] Failed to forward proxy request: %v", clientAddr, err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			logger.Error.Println(msg)
			return
		}
		defer resp.Body.Close()

		// 4. Unwrap the response from the next node
		encryptedResp, err := masquerade.UnwrapFromHttpResponse(resp)
		if err != nil {
			msg := fmt.Sprintf("[%s] Failed to unwrap proxy response: %v", clientAddr, err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			logger.Error.Println(msg)
			return
		}

		// 5. Decrypt the response
		decryptedResp, err := crypto.Decrypt(encryptedResp, forwardKey)
		if err != nil {
			msg := fmt.Sprintf("[%s] Proxy response decryption failed: %v", clientAddr, err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			logger.Error.Println(msg)
			return
		}

		// 6. Re-encrypt the response for the *previous* node
		reEncryptedResp, err := crypto.Encrypt(decryptedResp, listenKey)
		if err != nil {
			msg := fmt.Sprintf("[%s] Proxy response re-encryption failed: %v", clientAddr, err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			logger.Error.Println(msg)
			return
		}

		// 7. Send the final response back down the chain
		finalResponse := masquerade.WrapInRandomHttpResponse(reEncryptedResp)
		finalResponse.Header.Write(w)
		io.Copy(w, finalResponse.Body)
	}
}

// manageConnection runs in the background, periodically checking the connection
// and attempting to reconnect with exponential backoff if it fails.
func manageConnection(httpClient *http.Client, host, remoteIP string, key []byte, port int) {
	const (
		pingInterval  = 30 * time.Second
		maxRetries    = 10
		baseBackoff   = 2 * time.Second
		maxBackoff    = 5 * time.Minute
	)

	ticker := time.NewTicker(pingInterval)
	defer ticker.Stop()

	targetHost := fmt.Sprintf("%s:%d", host, port)
	targetIP := fmt.Sprintf("%s:%d", remoteIP, port)

	for {
		pingData, err := crypto.Encrypt([]byte("SEARCH_TUNNEL_PING"), key)
		if err != nil {
			logger.Error.Printf("Failed to encrypt ping data: %v", err)
			time.Sleep(baseBackoff)
			continue
		}
		req, _ := masquerade.WrapInHttpRequest(pingData, targetHost) // Masquerade with the original hostname and port
		req.URL.Scheme = "https"
		req.URL.Host = targetIP // Connect to the resolved IP and port
		req.URL.Path = "/favicon.ico"

		for i := 0; i < maxRetries; i++ {
			var resp *http.Response
			resp, err = httpClient.Do(req)
			if err == nil {
				var encryptedPong []byte
				encryptedPong, err = masquerade.UnwrapFromHttpResponse(resp)
				resp.Body.Close()
				if err != nil {
					err = fmt.Errorf("invalid pong response: %w", err)
					continue // Retry on invalid response
				}

				var pong []byte
				pong, err = crypto.Decrypt(encryptedPong, key)
				if err != nil || string(pong) != "SEARCH_TUNNEL_PONG" {
					err = fmt.Errorf("pong authentication failed")
					continue // Retry on auth failure
				}

				stats.SetLastSuccessfulPing(time.Now().Unix())
				fmt.Println("[Health Check] Connection OK.")
				break // Success
			}

			if i == maxRetries-1 {
				fmt.Printf("[Health Check] Connection failed after %d attempts: %v\n", maxRetries, err)
				if strings.Contains(err.Error(), "connection refused") {
					fmt.Println("\n⚠️  TROUBLESHOOTING TIP:")
					fmt.Println("   The remote server (External) refused the connection.")
					fmt.Printf("   1. SSH into your external server (%s).\n", remoteIP)
					fmt.Println("   2. Ensure 'elahe-tunnel' is running.")
					fmt.Printf("   3. Check if it's listening on port %d: 'netstat -tulnp | grep %d'\n", port, port)
					fmt.Printf("   4. Check firewall settings (ufw/iptables) to allow traffic on port %d.\n", port)
				}
				break
			}

			backoff := time.Duration(int64(baseBackoff) * (1 << i))
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
			fmt.Printf("[Health Check] Connection failed: %v. Retrying in %v...\n", err, backoff)
			time.Sleep(backoff)
		}

		<-ticker.C
	}
}

func handleClientConnection(localConn net.Conn, httpClient *http.Client, remoteIP string, key []byte, cfg *config.Config, target string) {
	// Generate Session ID
	sidBytes, err := crypto.GenerateKey()
	if err != nil {
		fmt.Printf("Failed to generate session ID: %v\n", err)
		return
	}
	sessionID := hex.EncodeToString(sidBytes[:8])

	stats.RegisterConnection(sessionID, localConn.RemoteAddr().String(), target, "TCP")
	defer stats.UnregisterConnection(sessionID)
	defer localConn.Close()

	buf := make([]byte, 32*1024)
	lastRequestTime := time.Now()

	for {
		// Read data from local application with a short timeout to allow polling
		localConn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		n, err := localConn.Read(buf)
		
		isIdle := false
		if err != nil {
			if err == io.EOF {
				return // Connection closed by local app
			}
			// Check for timeout
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				// Timeout means no data to send
				n = 0
				isIdle = true
			} else {
				fmt.Printf("Error reading from local connection: %v\n", err)
				return
			}
		}

		// If idle, only send a keep-alive request every 5 seconds
		if isIdle && time.Since(lastRequestTime) < 5*time.Second {
			continue
		}

		lastRequestTime = time.Now()

		// Construct payload: SessionID|Destination|Payload
		var payload []byte
		prefix := []byte(sessionID + "|" + target + "|")
		if n > 0 {
			payload = append(prefix, buf[:n]...)
			stats.AddTcpBytesIn(uint64(n))
		} else {
			payload = prefix
		}

		encrypted, err := crypto.Encrypt(payload, key)
		if err != nil {
			fmt.Printf("Encryption error: %v\n", err)
			return
		}

		port := cfg.TunnelPort
		if port == 0 {
			port = 443
		}
		targetHost := fmt.Sprintf("%s:%d", cfg.RemoteHost, port)

		// The host in the request must match the CN of the certificate (www.google.com)
		// but the request itself goes to the user's server IP.
		req, err := masquerade.WrapInHttpRequest(encrypted, targetHost)
		if err != nil {
			fmt.Printf("Failed to wrap HTTP request: %v\n", err)
			return
		}
		// Override the request URL to point to the actual server IP
		req.URL.Scheme = "https"
		req.URL.Host = fmt.Sprintf("%s:%d", remoteIP, port)

		resp, err := httpClient.Do(req)
		if err != nil {
			fmt.Printf("Failed to send HTTP request: %v\n", err)
			return
		}
		
		// Unwrap the response
		respData, err := masquerade.UnwrapFromHttpResponse(resp)
		resp.Body.Close() // Close immediately
		if err != nil {
			fmt.Printf("Failed to unwrap HTTP response: %v\n", err)
			return
		}

		// Decrypt the response data
		decrypted, err := crypto.Decrypt(respData, key)
		if err != nil {
			fmt.Printf("Decryption error: %v\n", err)
			return
		}

		// Write the final data back to the local application
		if len(decrypted) > 0 {
			bytesWritten, err := localConn.Write(decrypted)
			stats.AddTcpBytesOut(uint64(bytesWritten))
			if err != nil {
				fmt.Printf("Error writing to local connection: %v\n", err)
				return
			}
		} else {
			// No data received. If we also sent no data, sleep a bit to avoid busy loop.
			if n == 0 {
				time.Sleep(50 * time.Millisecond)
			}
		}
	}
}

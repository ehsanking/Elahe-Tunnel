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

	"github.com/ehsanking/search-tunnel/internal/config"
	"github.com/ehsanking/search-tunnel/internal/crypto"
	"github.com/ehsanking/search-tunnel/internal/logger"
	"github.com/ehsanking/search-tunnel/internal/masquerade"
	"github.com/google/uuid"
)

// RunClient starts the internal node client.
func RunClient(cfg *config.Config) error {
	// If listen address is provided, start the proxy server
	if cfg.TunnelListenAddr != "" {
		go runProxyServer(cfg)
	}

	key, err := crypto.DecodeBase64Key(cfg.ConnectionKey)
	if err != nil {
		return fmt.Errorf("invalid connection key: %w", err)
	}

	// Create a custom dialer to resolve the remote host through the tunnel itself
	netDialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	// Create a shared HTTP client with a custom transport
	tr := &http.Transport{
		// We still need to skip verification for the self-signed cert
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		// Use our custom dialer
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// If we're dialing the remote host, we need to resolve it securely
			if addr == cfg.RemoteHost+":443" {
				// This is a simplified example. A real implementation would need
				// to handle the bootstrapping problem of resolving the initial IP.
				// For now, we assume the initial IP is provided or resolved once insecurely.
				return netDialer.DialContext(ctx, network, addr)
			}
			// For all other addresses, use the default dialer
			return netDialer.DialContext(ctx, network, addr)
		},
	}
	httpClient := &http.Client{Transport: tr, Timeout: 15 * time.Second}

	// Perform an initial, insecure DNS lookup for the remote host
	ips, err := net.LookupIP(cfg.RemoteHost)
	if err != nil || len(ips) == 0 {
		return fmt.Errorf("could not resolve remote host: %w", err)
	}
	remoteIP := ips[0].String()
	fmt.Printf("Resolved remote host %s to %s\n", cfg.RemoteHost, remoteIP)

	// Start the connection manager in the background
	go manageConnection(httpClient, cfg.RemoteHost, remoteIP, key)

	// If enabled, start the DNS proxy
	if cfg.DnsProxyEnabled {
		tunnelQuery := func(query []byte) ([]byte, error) {
			encryptedQuery, err := crypto.Encrypt(query, key)
			if err != nil {
				return nil, fmt.Errorf("dns query encryption failed: %w", err)
			}

			req, err := masquerade.WrapInHttpRequest(encryptedQuery, cfg.RemoteHost)
			if err != nil {
				return nil, fmt.Errorf("dns request wrapping failed: %w", err)
			}
			req.URL.Path = "/dns-query"

			resp, err := httpClient.Do(req)
			if err != nil {
				return nil, fmt.Errorf("dns http request failed: %w", err)
			}
			defer resp.Body.Close()

			encryptedResp, err := masquerade.UnwrapFromHttpResponse(resp)
			if err != nil {
				return nil, fmt.Errorf("dns response unwrap failed: %w", err)
			}

			return crypto.Decrypt(encryptedResp, key)
		}
		go RunDnsProxy(53, tunnelQuery)
	}

	// If enabled, start the UDP proxy
	if cfg.UdpProxyEnabled {
		go RunUdpProxy(9091, httpClient, cfg.RemoteHost, remoteIP, key, cfg)
	}

	fmt.Println("Internal TCP proxy listening on localhost:9090")
	localListener, err := net.Listen("tcp", "localhost:9090")
	if err != nil {
		return fmt.Errorf("failed to listen on local port 9090: %w", err)
	}
	defer localListener.Close()

	for {
		localConn, err := localListener.Accept()
		if err != nil {
			fmt.Printf("Failed to accept local connection: %v\n", err)
			continue
		}
		go handleClientConnection(localConn, httpClient, remoteIP, key, cfg)
	}
}

var udpSessionMap = make(map[string]*net.UDPAddr)
var udpSessionMutex = &sync.Mutex{}

// RunUdpProxy starts a local UDP proxy to intercept and tunnel UDP packets.
func RunUdpProxy(localPort int, httpClient *http.Client, remoteHost, remoteIP string, key []byte, cfg *config.Config) {
	localAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("127.0.0.1:%d", localPort))
	if err != nil {
		logger.Error.Printf("Failed to resolve UDP address: %v", err)
		return
	}

	conn, err := net.ListenUDP("udp", localAddr)
	if err != nil {
		logger.Error.Printf("Failed to listen on UDP port %d: %v", localPort, err)
		return
	}
	defer conn.Close()

	logger.Info.Printf("Internal UDP proxy listening on 127.0.0.1:%d", localPort)

	buf := make([]byte, 4096)
	for {
		n, remoteUdpAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			logger.Error.Printf("Failed to read from UDP conn: %v", err)
			continue
		}

		go handleUdpPacket(buf[:n], remoteUdpAddr, conn, httpClient, remoteHost, remoteIP, key, cfg)
	}
}

func handleUdpPacket(data []byte, remoteUdpAddr *net.UDPAddr, conn *net.UDPConn, httpClient *http.Client, remoteHost, remoteIP string, key []byte, cfg *config.Config) {
	// Generate a unique session ID
	sessionID := uuid.New().String()
	udpSessionMutex.Lock()
	udpSessionMap[sessionID] = remoteUdpAddr
	udpSessionMutex.Unlock()

	// Clean up the session map after a timeout
	time.AfterFunc(30*time.Second, func() {
		udpSessionMutex.Lock()
		delete(udpSessionMap, sessionID)
		udpSessionMutex.Unlock()
	})

	// Prepend session ID and destination
	header := fmt.Sprintf("%s:%s\n", sessionID, cfg.DestinationUdpHost)
	payload := append([]byte(header), data...)
	encrypted, err := crypto.Encrypt(payload, key)
	if err != nil {
		logger.Error.Printf("UDP encryption error: %v", err)
		return
	}

	// Masquerade as a DNS query
	dnsQuery, err := masquerade.WrapInDnsQuery(encrypted)
	if err != nil {
		logger.Error.Printf("Failed to wrap UDP in DNS query: %v", err)
		return
	}

	// Send the raw UDP packet to the server's port 53
	serverAddr := fmt.Sprintf("%s:53", remoteIP)
	udpConn, err := net.Dial("udp", serverAddr)
	if err != nil {
		logger.Error.Printf("Failed to connect to server UDP port: %v", err)
		return
	}
	defer udpConn.Close()

	_, err = udpConn.Write(dnsQuery)
	if err != nil {
		logger.Error.Printf("Failed to send DNS query: %v", err)
		return
	}

	// Read the response
	respBuf := make([]byte, 4096)
	udpConn.SetReadDeadline(time.Now().Add(10 * time.Second)) // Generous timeout
	n, err := udpConn.Read(respBuf)
	if err != nil {
		logger.Error.Printf("Failed to read DNS response: %v", err)
		return
	}

	// Unwrap and decrypt response
	respData, err := masquerade.UnwrapFromDnsResponse(respBuf[:n])
	if err != nil {
		logger.Error.Printf("Failed to unwrap DNS response: %v", err)
		return
	}

	decrypted, err := crypto.Decrypt(respData, key)
	if err != nil {
		logger.Error.Printf("UDP decryption error: %v", err)
		return
	}

	// The response from the server should have the session ID prepended
	parts := bytes.SplitN(decrypted, []byte(":"), 2)
	if len(parts) != 2 {
		logger.Error.Printf("Invalid multi-destination UDP response format")
		return
	}
	sessionID := string(parts[0])
	responseData := parts[1]

	// Look up the original sender and forward the response
	udpSessionMutex.Lock()
	originalAddr, ok := udpSessionMap[sessionID]
	udpSessionMutex.Unlock()

	if !ok {
		logger.Error.Printf("Could not find session for UDP response: %s", sessionID)
		return
	}

	_, err = conn.WriteToUDP(responseData, originalAddr)
	if err != nil {
		logger.Error.Printf("Error writing to UDP conn: %v", err)
	}
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
	forwardHttpClient := &http.Client{Transport: tr, Timeout: 15 * time.Second}

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
func manageConnection(httpClient *http.Client, host, remoteIP string, key []byte) {
	const (
		pingInterval  = 1 * time.Minute
		maxRetries    = 10
		baseBackoff   = 2 * time.Second
		maxBackoff    = 5 * time.Minute
	)

	ticker := time.NewTicker(pingInterval)
	defer ticker.Stop()

	for {
		pingData, _ := crypto.Encrypt([]byte("SEARCH_TUNNEL_PING"), key)
		req, _ := masquerade.WrapInHttpRequest(pingData, host) // Masquerade with the original hostname
		req.URL.Scheme = "https"
		req.URL.Host = remoteIP // Connect to the resolved IP
		req.URL.Path = "/favicon.ico"

		var err error
		for i := 0; i < maxRetries; i++ {
			resp, err := httpClient.Do(req)
			if err == nil {
				encryptedPong, err := masquerade.UnwrapFromHttpResponse(resp)
				resp.Body.Close()
				if err != nil {
					err = fmt.Errorf("invalid pong response: %w", err)
					continue // Retry on invalid response
				}

				pong, err := crypto.Decrypt(encryptedPong, key)
				if err != nil || string(pong) != "SEARCH_TUNNEL_PONG" {
					err = fmt.Errorf("pong authentication failed")
					continue // Retry on auth failure
				}

				fmt.Println("[Health Check] Connection OK.")
				break // Success
			}

			if i == maxRetries-1 {
				fmt.Printf("[Health Check] Connection failed after %d attempts: %v\n", maxRetries, err)
				// In a real app, you might want to exit or take other action here
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

func handleClientConnection(localConn net.Conn, httpClient *http.Client, remoteIP string, key []byte, cfg *config.Config) {
	defer localConn.Close()

	// Read data from the local application
	buf := make([]byte, 8192)
	n, err := localConn.Read(buf)
	if err != nil {
		if err != io.EOF {
			fmt.Printf("Error reading from local connection: %v\n", err)
		}
		return
	}

	// Prepend the destination and encrypt the data
	payload := append([]byte(cfg.DestinationHost+"\n"), buf[:n]...)
	encrypted, err := crypto.Encrypt(payload, key)
	if err != nil {
		fmt.Printf("Encryption error: %v\n", err)
		return
	}

	// The host in the request must match the CN of the certificate (www.google.com)
	// but the request itself goes to the user's server IP.
	req, err := masquerade.WrapInHttpRequest(encrypted, "www.google.com")
	if err != nil {
		fmt.Printf("Failed to wrap HTTP request: %v\n", err)
		return
	}
	// Override the request URL to point to the actual server IP
	req.URL.Scheme = "https"
	req.URL.Host = remoteIP

	resp, err := httpClient.Do(req)
	if err != nil {
		fmt.Printf("Failed to send HTTP request: %v\n", err)
		return
	}
	defer resp.Body.Close()

	// Unwrap the response
	respData, err := masquerade.UnwrapFromHttpResponse(resp)
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
	_, err = localConn.Write(decrypted)
	if err != nil {
		fmt.Printf("Error writing to local connection: %v\n", err)
	}
}

package tunnel

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/ehsanking/search-tunnel/internal/config"
	"github.com/ehsanking/search-tunnel/internal/crypto"
	"github.com/ehsanking/search-tunnel/internal/masquerade"
)

// RunClient starts the internal node client.
func RunClient(cfg *config.Config) error {
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
		go handleClientConnection(localConn, httpClient, remoteIP, key)
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

func handleClientConnection(localConn net.Conn, httpClient *http.Client, remoteIP string, key []byte) {
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

	// Encrypt the data
	encrypted, err := crypto.Encrypt(buf[:n], key)
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

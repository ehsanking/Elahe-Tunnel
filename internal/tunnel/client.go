package tunnel

import (
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

	fmt.Println("Internal client listening on localhost:9090")
	localListener, err := net.Listen("tcp", "localhost:9090")
	if err != nil {
		return fmt.Errorf("failed to listen on local port 9090: %w", err)
	}
	defer localListener.Close()

	// Create a custom transport to skip TLS verification
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	httpClient := &http.Client{Transport: tr}

	for {
		localConn, err := localListener.Accept()
		if err != nil {
			fmt.Println("Failed to accept local connection:", err)
			continue
		}

		go handleClientConnection(localConn, httpClient, cfg.RemoteHost, key)
	}
}

const (
	maxRetries    = 5
	baseBackoff   = 1 * time.Second
	maxBackoff    = 30 * time.Second
)

func handleClientConnection(localConn net.Conn, httpClient *http.Client, host string, key []byte) {
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
	req.URL.Host = host

	var resp *http.Response
	for i := 0; i < maxRetries; i++ {
		resp, err = httpClient.Do(req)
		if err == nil {
			break // Success
		}
		backoff := time.Duration(int64(baseBackoff) * (1 << i)) 
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
		fmt.Printf("Failed to send HTTP request (attempt %d/%d): %v. Retrying in %v...\n", i+1, maxRetries, err, backoff)
		time.Sleep(backoff)
	}

	if err != nil {
		fmt.Printf("Failed to send HTTP request after %d attempts: %v\n", maxRetries, err)
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

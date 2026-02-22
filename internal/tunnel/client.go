package tunnel

import (
	"fmt"
	"io"
	"net"
	"net/http"

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

	httpClient := &http.Client{}

	for {
		localConn, err := localListener.Accept()
		if err != nil {
			fmt.Println("Failed to accept local connection:", err)
			continue
		}

		go handleClientConnection(localConn, httpClient, cfg.RemoteHost, key)
	}
}

func handleClientConnection(localConn net.Conn, httpClient *http.Client, host string, key []byte) {
	defer localConn.Close()

	// Read data from the local application
	buf := make([]byte, 8192) // Increased buffer size
	n, err := localConn.Read(buf)
	if err != nil {
		return
	}

	// Encrypt the data
	encrypted, err := crypto.Encrypt(buf[:n], key)
	if err != nil {
		fmt.Println("Encryption error:", err)
		return
	}

	// Wrap it in a fake HTTP request
	req, err := masquerade.WrapInHttpRequest(encrypted, host)
	if err != nil {
		fmt.Println("Failed to wrap HTTP request:", err)
		return
	}

	// Send the request
	resp, err := httpClient.Do(req)
	if err != nil {
		fmt.Println("Failed to send HTTP request:", err)
		return
	}
	defer resp.Body.Close()

	// Unwrap the response
	respData, err := masquerade.UnwrapFromHttpResponse(resp)
	if err != nil {
		fmt.Println("Failed to unwrap HTTP response:", err)
		return
	}

	// Decrypt the response data
	decrypted, err := crypto.Decrypt(respData, key)
	if err != nil {
		fmt.Println("Decryption error:", err)
		return
	}

	// Write the final data back to the local application
	localConn.Write(decrypted)
}

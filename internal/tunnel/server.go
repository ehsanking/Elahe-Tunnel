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

// RunServer starts the external node as an HTTP server.
func RunServer(cfg *config.Config) error {
	key, err := crypto.DecodeBase64Key(cfg.ConnectionKey)
	if err != nil {
		return fmt.Errorf("invalid connection key: %w", err)
	}

	http.HandleFunc("/search", handleSearchRequest(key))

	fmt.Println("External HTTP server listening on :80") // Listening on port 80 for HTTP
	return http.ListenAndServe(":80", nil)
}

func handleSearchRequest(key []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Unwrap the request from the client
		encryptedData, err := masquerade.UnwrapFromHttpRequest(r)
		if err != nil {
			http.Error(w, "Invalid request format", http.StatusBadRequest)
			return
		}

		// Decrypt the data
		decryptedData, err := crypto.Decrypt(encryptedData, key)
		if err != nil {
			http.Error(w, "Decryption failed", http.StatusForbidden)
			return
		}

		// Connect to the target service (e.g., tcpbin for echo testing)
		targetConn, err := net.Dial("tcp", "tcpbin.com:4242")
		if err != nil {
			http.Error(w, "Failed to connect to target service", http.StatusInternalServerError)
			return
		}
		defer targetConn.Close()

		// Write the decrypted data to the target
		_, err = targetConn.Write(decryptedData)
		if err != nil {
			http.Error(w, "Failed to write to target service", http.StatusInternalServerError)
			return
		}

		// Read the response from the target
		respData, err := io.ReadAll(targetConn)
		if err != nil {
			http.Error(w, "Failed to read from target service", http.StatusInternalServerError)
			return
		}

		// Encrypt the response
		encryptedResp, err := crypto.Encrypt(respData, key)
		if err != nil {
			http.Error(w, "Encryption failed", http.StatusInternalServerError)
			return
		}

		// Wrap the response in a fake Google search page
		response := masquerade.WrapInHttpResponse(encryptedResp)
		response.Header.Write(w)
		io.Copy(w, response.Body)
	}
}

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
	http.HandleFunc("/favicon.ico", handlePingRequest(key)) // Discreet endpoint for status check

	fmt.Println("External HTTPS server listening on :443") // Listening on port 443 for HTTPS
	return http.ListenAndServeTLS(":443", "cert.pem", "key.pem", nil)
}

func handleSearchRequest(key []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		clientAddr := r.RemoteAddr

		// Unwrap the request from the client
		encryptedData, err := masquerade.UnwrapFromHttpRequest(r)
		if err != nil {
			msg := fmt.Sprintf("[%s] Invalid request format: %v", clientAddr, err)
			http.Error(w, msg, http.StatusBadRequest)
			fmt.Println(msg)
			return
		}

		// Decrypt the data
		decryptedData, err := crypto.Decrypt(encryptedData, key)
		if err != nil {
			msg := fmt.Sprintf("[%s] Decryption failed: %v", clientAddr, err)
			http.Error(w, "Forbidden", http.StatusForbidden) // Don't leak crypto details
			fmt.Println(msg)
			return
		}

		// Connect to the target service (e.g., tcpbin for echo testing)
		targetConn, err := net.Dial("tcp", "tcpbin.com:4242")
		if err != nil {
			msg := fmt.Sprintf("[%s] Failed to connect to target service: %v", clientAddr, err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			fmt.Println(msg)
			return
		}
		defer targetConn.Close()

		// Write the decrypted data to the target
		_, err = targetConn.Write(decryptedData)
		if err != nil {
			msg := fmt.Sprintf("[%s] Failed to write to target service: %v", clientAddr, err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			fmt.Println(msg)
			return
		}

		// Read the response from the target
		respData, err := io.ReadAll(targetConn)
		if err != nil {
			msg := fmt.Sprintf("[%s] Failed to read from target service: %v", clientAddr, err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			fmt.Println(msg)
			return
		}

		// Encrypt the response
		encryptedResp, err := crypto.Encrypt(respData, key)
		if err != nil {
			msg := fmt.Sprintf("[%s] Encryption failed: %v", clientAddr, err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			fmt.Println(msg)
			return
		}

		// Wrap the response in a fake Google search page
		response := masquerade.WrapInHttpResponse(encryptedResp)
		response.Header.Write(w)
		io.Copy(w, response.Body)
	}
}

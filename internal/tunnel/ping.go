package tunnel

import (
	"net/http"

	"github.com/ehsanking/elahe-tunnel/internal/crypto"
	"github.com/ehsanking/elahe-tunnel/internal/masquerade"
)

func handlePingRequest(key []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		encryptedPing, err := masquerade.UnwrapFromHttpRequest(r)
		if err != nil {
			http.Error(w, "Invalid ping request", http.StatusBadRequest)
			return
		}

		ping, err := crypto.Decrypt(encryptedPing, key)
		if err != nil || string(ping) != "SEARCH_TUNNEL_PING" {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		encryptedPong, err := crypto.Encrypt([]byte("SEARCH_TUNNEL_PONG"), key)
		if err != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		masquerade.WrapInRandomHttpResponse(w, encryptedPong)
	}
}

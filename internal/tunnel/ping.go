package tunnel

import (
	"fmt"
	"io"
	"net/http"

	"github.com/ehsanking/elahe-tunnel/internal/crypto"
	"github.com/ehsanking/elahe-tunnel/internal/masquerade"
)

const pingMessage = "SEARCH_TUNNEL_PING"
const pongMessage = "SEARCH_TUNNEL_PONG"

func handlePingRequest(key []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		encryptedData, err := masquerade.UnwrapFromHttpRequest(r)
		if err != nil {
			http.Error(w, "", http.StatusBadRequest)
			return
		}

		decryptedData, err := crypto.Decrypt(encryptedData, key)
		if err != nil {
			http.Error(w, "", http.StatusForbidden)
			return
		}

		if string(decryptedData) == pingMessage {
			encryptedPong, err := crypto.Encrypt([]byte(pongMessage), key)
			if err != nil {
				http.Error(w, "", http.StatusInternalServerError)
				return
			}
			response := masquerade.WrapInRandomHttpResponse(encryptedPong)
			response.Header.Write(w)
			io.Copy(w, response.Body)
		} else {
			http.Error(w, "", http.StatusBadRequest)
		}
	}
}

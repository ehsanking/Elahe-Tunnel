package tunnel

import (
	"encoding/json"
	"io"

	"github.com/ehsanking/elahe-tunnel/internal/config"
)

const (
	CmdRegisterProxies = "register_proxies"
	CmdNewConnection   = "new_connection"
	CmdRegistrationFailed = "registration_failed"
)

// ControlMessage represents a command sent over the control channel.

type ControlMessage struct {
	Command string          `json:"command"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

// RegisterProxiesPayload is the payload for the 'register_proxies' command.

type RegisterProxiesPayload struct {
	Proxies []config.ProxyConfig `json:"proxies"`
}

// NewConnectionPayload is the payload for the 'new_connection' command.

type NewConnectionPayload struct {
	ProxyName string `json:"proxy_name"`
}

// WriteControlMessage sends a JSON-encoded control message to the given writer.
func WriteControlMessage(w io.Writer, cmd string, payload interface{}) error {
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	msg := ControlMessage{
		Command: cmd,
		Payload: payloadBytes,
	}

	return json.NewEncoder(w).Encode(msg)
}

// ReadControlMessage reads and decodes a JSON control message from the given reader.
func ReadControlMessage(r io.Reader) (*ControlMessage, error) {
	var msg ControlMessage
	err := json.NewDecoder(r).Decode(&msg)
	return &msg, err
}

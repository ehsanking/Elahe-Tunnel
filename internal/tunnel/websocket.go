package tunnel

import (
	"crypto/tls"
	"net/http"
	"time"

	"github.com/gorilla/websocket"
	"github.com/xtaci/smux"
)

// SmuxConfig returns a standard smux configuration
func SmuxConfig() *smux.Config {
	config := smux.DefaultConfig()
	config.KeepAliveInterval = 10 * time.Second
	config.KeepAliveTimeout = 30 * time.Second
	config.MaxFrameSize = 32768
	config.MaxReceiveBuffer = 4194304
	return config
}

// WebSocketConn wraps a gorilla websocket connection to implement net.Conn
type WebSocketConn struct {
	*websocket.Conn
	reader []byte
}

func NewWebSocketConn(conn *websocket.Conn) *WebSocketConn {
	return &WebSocketConn{Conn: conn}
}

func (w *WebSocketConn) Read(b []byte) (n int, err error) {
	if len(w.reader) > 0 {
		n = copy(b, w.reader)
		w.reader = w.reader[n:]
		return n, nil
	}

	_, message, err := w.ReadMessage()
	if err != nil {
		return 0, err
	}

	n = copy(b, message)
	if n < len(message) {
		w.reader = message[n:]
	}
	return n, nil
}

func (w *WebSocketConn) Write(b []byte) (n int, err error) {
	err = w.WriteMessage(websocket.BinaryMessage, b)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

func (w *WebSocketConn) SetDeadline(t time.Time) error {
	if err := w.SetReadDeadline(t); err != nil {
		return err
	}
	return w.SetWriteDeadline(t)
}

// DialWebSocket establishes a websocket connection and returns a smux session
func DialWebSocket(url string, host string) (*smux.Session, error) {
	dialer := websocket.Dialer{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		Proxy:           http.ProxyFromEnvironment,
		HandshakeTimeout: 15 * time.Second,
	}

	header := http.Header{}
	header.Set("Host", host)
	header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	header.Set("Origin", "https://www.google.com")
	header.Set("Cookie", "NID=elahe-tunnel") // Simple auth for now, can be encrypted later
	// Removed Sec-WebSocket-Protocol as it's a dead giveaway

	conn, _, err := dialer.Dial(url, header)
	if err != nil {
		return nil, err
	}

	wsConn := NewWebSocketConn(conn)
	session, err := smux.Client(wsConn, SmuxConfig())
	if err != nil {
		conn.Close()
		return nil, err
	}

	return session, nil
}

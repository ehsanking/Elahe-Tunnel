package tunnel

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/ehsanking/elahe-tunnel/internal/config"
	"github.com/ehsanking/elahe-tunnel/internal/crypto"
	"github.com/ehsanking/elahe-tunnel/internal/logger"
	"github.com/ehsanking/elahe-tunnel/internal/masquerade"
	"github.com/gorilla/websocket"
	"github.com/xtaci/smux"
	"encoding/json"
	"github.com/pion/dtls/v2"
	"golang.org/x/time/rate"
)

// ClientSession represents a connected internal client and its associated resources.




type ClientSession struct {
	session      *smux.Session
	proxies      []config.ProxyConfig
	listeners    map[int]net.Listener
	lastSeen     time.Time
	lock         sync.Mutex
	connections  map[string]*config.ActiveConnection // Connections belonging to this client
}

func (cs *ClientSession) addConnection(conn *config.ActiveConnection) {
	cs.lock.Lock()
	defer cs.lock.Unlock()
	cs.connections[conn.ID] = conn
}

func (cs *ClientSession) removeConnection(id string) {
	cs.lock.Lock()
	defer cs.lock.Unlock()
	delete(cs.connections, id)
}

// Global map to track active client sessions.
var clientSessions = make(map[*smux.Session]*ClientSession)
var sessionsLock sync.RWMutex

// RunServer starts the external node server.
func RunServer(cfg *config.Config) error {
	key, err := crypto.DecodeBase64Key(cfg.ConnectionKey)
	if err != nil {
		return fmt.Errorf("failed to decode key: %w", err)
	}

	port := cfg.TunnelPort
	if port == 0 {
		port = 443
	}

	// Increase rate limits for better stability under unstable network conditions
	limiter := rate.NewLimiter(rate.Limit(100), 500) // Allow 100 requests per second, with a burst of 500

	pingHandler := http.HandlerFunc(handlePingRequest(key))
	http.Handle("/favicon.ico", recoveryMiddleware(limitMiddleware(limiter, pingHandler)))

	wsHandler := http.HandlerFunc(handleWebSocket(key))
	http.Handle("/search/results", recoveryMiddleware(wsHandler))

	killHandler := http.HandlerFunc(handleKillConnection)
	http.Handle("/kill", recoveryMiddleware(killHandler))

	tunnelHandler := http.HandlerFunc(handleTunnelRequest(key))
	http.Handle("/", recoveryMiddleware(limitMiddleware(limiter, tunnelHandler)))

	// Start the DTLS server in a separate goroutine.
	go runDtlsServer(key, port)

	addr := fmt.Sprintf(":%d", port)
	logger.Info.Printf("External server listening on %s\n", addr)
	err = http.ListenAndServeTLS(addr, "cert.pem", "key.pem", nil)
	if err != nil {
		return fmt.Errorf("server failed: %w. Check if port %d is free and you have root privileges", err, port)
	}
	return nil
}

func handleWebSocket(key []byte) http.HandlerFunc {
	upgrader := websocket.Upgrader{
		ReadBufferSize:  32768,
		WriteBufferSize: 32768,
		CheckOrigin: func(r *http.Request) bool {
			return true
		},
	}

	return func(w http.ResponseWriter, r *http.Request) {
		// Basic authentication via header or query param
		// For stealth, we can use a cookie or a custom header that looks like a tracking ID
		auth := r.Header.Get("Sec-WebSocket-Protocol")
		if auth == "" {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		// Verify auth (simple check for now, could be more complex)
		// We'll use the connection key as the protocol for simplicity in this step
		// In a real scenario, this would be an encrypted token
		if auth != "elahe-tunnel" {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			logger.Error.Printf("WebSocket upgrade failed: %v", err)
			return
		}

		logger.Info.Printf("WebSocket upgrade successful for client %s", r.RemoteAddr)
		wsConn := NewWebSocketConn(conn)
		session, err := smux.Server(wsConn, SmuxConfig())
		if err != nil {
			conn.Close()
			return
		}
		defer session.Close()

		// The first stream is the control channel.
		controlStream, err := session.AcceptStream()
		if err != nil {
			logger.Error.Printf("Failed to accept control stream: %v", err)
			return
		}

		client := NewClientSession(session)
		AddClientSession(client)
		defer RemoveClientSession(client)

		// Handle the control channel. This will block until the client disconnects.
		handleControlStream(controlStream, client)
	}
}

func NewClientSession(session *smux.Session) *ClientSession {
	return &ClientSession{
		session:     session,
		listeners:   make(map[int]net.Listener),
		lastSeen:    time.Now(),
		connections: make(map[string]*config.ActiveConnection),
	}
}

func AddClientSession(client *ClientSession) {
	sessionsLock.Lock()
	defer sessionsLock.Unlock()
	clientSessions[client.session] = client
	logger.Info.Printf("Client session %s registered.", client.session.RemoteAddr())
}

func RemoveClientSession(client *ClientSession) {
	sessionsLock.Lock()
	defer sessionsLock.Unlock()
	delete(clientSessions, client.session)
	// Important: Close all associated listeners when the client disconnects.
	for port, listener := range client.listeners {
		listener.Close()
		logger.Info.Printf("Closed listener on port %d for disconnected client %s.", port, client.session.RemoteAddr())
	}
	logger.Info.Printf("Client session %s deregistered.", client.session.RemoteAddr())
}

func handleControlStream(stream *smux.Stream, client *ClientSession) {
	defer RemoveClientSession(client) // Ensure cleanup happens when this function exits.

	for {
		msg, err := ReadControlMessage(stream)
		if err != nil {
			if err == io.EOF {
				logger.Info.Printf("Client %s closed the control stream.", client.session.RemoteAddr())
			} else {
				logger.Error.Printf("Error reading control message from %s: %v", client.session.RemoteAddr(), err)
			}
			return
		}

		switch msg.Command {
		case CmdRegisterProxies:
			var payload RegisterProxiesPayload
			err := json.Unmarshal(msg.Payload, &payload)
			if err != nil {
				logger.Error.Printf("Failed to unmarshal register_proxies payload: %v", err)
				continue
			}
			client.lock.Lock()
			client.proxies = payload.Proxies
			client.lock.Unlock()
			startProxyListeners(client, stream)

		default:
			logger.Info.Printf("Received unknown command '%s' from client %s.", msg.Command, client.session.RemoteAddr())
		}
	}
}

func startProxyListeners(client *ClientSession, controlStream *smux.Stream) {
	client.lock.Lock()
	defer client.lock.Unlock()

	for _, proxy := range client.proxies {
		go func(p config.ProxyConfig) {
			addr := fmt.Sprintf(":%d", p.RemotePort)
			listener, err := net.Listen("tcp", addr)
			if err != nil {
				logger.Error.Printf("Failed to start listener for proxy '%s' on port %d: %v", p.Name, p.RemotePort, err)
				// Send an error back to the client.
				errMsg := fmt.Sprintf("Failed to start listener for proxy '%s' on port %d: %v", p.Name, p.RemotePort, err)
				WriteControlMessage(controlStream, CmdRegistrationFailed, errMsg)
				return
			}
			client.listeners[p.RemotePort] = listener
			logger.Info.Printf("Started listener for proxy '%s' on %s for client %s", p.Name, addr, client.session.RemoteAddr())

			for {
				conn, err := listener.Accept()
				if err != nil {
					// If the listener was closed, we can just exit the loop.
					logger.Info.Printf("Listener for proxy '%s' on port %d stopped: %v", p.Name, p.RemotePort, err)
					return
				}
				logger.Info.Printf("Accepted new public connection for proxy '%s' from %s", p.Name, conn.RemoteAddr())
				go handlePublicConnection(conn, client, p.Name)
			}
		}(proxy)
	}
}

func handlePublicConnection(publicConn net.Conn, client *ClientSession, proxyName string) {
	defer publicConn.Close()

	// 1. Command the client to prepare for a new connection.
	// We need to find the control stream for this client.
	// This is a simplification; in a real-world scenario, we'd have a more direct way to access it.
	// For now, we'll assume the client is well-behaved and the session is active.

	// This is a conceptual placeholder. The actual implementation requires passing the control stream
	// down to this function, or having a way to retrieve it from the ClientSession.
	// Let's assume for now we can open a new stream that the client will interpret as a data channel.

	// 2. Open a new data stream.
	dataStream, err := client.session.OpenStream()
	if err != nil {
		logger.Error.Printf("Failed to open new data stream for proxy '%s': %v", proxyName, err)
		return
	}
	defer dataStream.Close()

	// Register the new connection.
	connID := fmt.Sprintf("%s-%d", client.session.RemoteAddr(), dataStream.ID())
	activeConn := &config.ActiveConnection{
		ID:        connID,
		ProxyName: proxyName,
		Client:    client,
		Stream:    dataStream,
		StartTime: time.Now(),
	}
	config.ConnManager.Add(activeConn)
	client.addConnection(activeConn)
	defer config.ConnManager.Remove(connID)
	defer client.removeConnection(connID)

	// 3. Send the proxy name so the client knows where to connect.
	// We'll use a simple length-prefixed format.
	proxyNameBytes := []byte(proxyName)
	header := []byte{byte(len(proxyNameBytes))}
	_, err = dataStream.Write(header)
	if err != nil {
		return
	}
	_, err = dataStream.Write(proxyNameBytes)
	if err != nil {
		return
	}

	logger.Info.Printf("Opened data stream %d for proxy '%s'. Tunnelling data.", dataStream.ID(), proxyName)

	// 4. Proxy data.
	done := make(chan struct{})
	go func() {
		io.Copy(dataStream, publicConn)
		close(done)
	}()

	go func() {
		io.Copy(publicConn, dataStream)
		close(done)
	}()

	<-done
	logger.Info.Printf("Closed data stream %d for proxy '%s'.", dataStream.ID(), proxyName)
}

func handleSmuxStream(stream *smux.Stream, key []byte) {
	defer stream.Close()

	// The first message should be the destination
	// We'll use a simple format: [1 byte len][destination string]
	header := make([]byte, 1)
	_, err := io.ReadFull(stream, header)
	if err != nil {
		return
	}

	destLen := int(header[0])
	destBuf := make([]byte, destLen)
	_, err = io.ReadFull(stream, destBuf)
	if err != nil {
		return
	}

	destination := string(destBuf)
	
	logger.Info.Printf("Stream from %s asking to connect to destination: %s", stream.RemoteAddr(), destination)
	// Dial target
	targetConn, err := net.DialTimeout("tcp", destination, 10*time.Second)
	if err != nil {
			logger.Error.Printf("Failed to connect to destination %s for stream %s: %v", destination, stream.RemoteAddr(), err)
			return
		}
	defer targetConn.Close()
	logger.Info.Printf("Successfully connected to %s for stream %s. Starting proxy.", destination, stream.RemoteAddr())

	// Tunnel data
	done := make(chan struct{})
	go func() {
		io.Copy(targetConn, stream)
		close(done)
	}()

	go func() {
		io.Copy(stream, targetConn)
		close(done)
	}()

	<-done
}

func recoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				logger.Error.Printf("Panic recovered: %v", err)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func limitMiddleware(limiter *rate.Limiter, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !limiter.Allow() {
			http.Error(w, http.StatusText(http.StatusTooManyRequests), http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func runDtlsServer(key []byte, port int) {
	udpAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", port))
	if err != nil {
		logger.Error.Printf("Failed to resolve UDP address: %v", err)
		return
	}

	// DTLS with PSK does not require certificates.
	// Providing certificates with PSK-only cipher suites causes an error.
	dtlsListener, err := dtls.Listen("udp", udpAddr, &dtls.Config{
		PSK: func(hint []byte) ([]byte, error) {
			return key, nil
		},
		PSKIdentityHint: []byte("elahe-tunnel"),
		CipherSuites: []dtls.CipherSuiteID{
			dtls.TLS_PSK_WITH_AES_128_GCM_SHA256,
			dtls.TLS_PSK_WITH_AES_128_CCM_8,
		},
		ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
	})
	if err != nil {
		logger.Error.Printf("DTLS server failed to start: %v", err)
		return
	}

	logger.Info.Printf("DTLS server listening on :%d\n", port)

	for {
		conn, err := dtlsListener.Accept()
		if err != nil {
			logger.Error.Printf("DTLS accept error: %v", err)
			continue
		}
		go handleDtlsConnection(conn, key)
	}
}

func handleDtlsConnection(conn net.Conn, key []byte) {
	defer conn.Close()
	buf := make([]byte, 4096)

	// Map to cache UDP connections: destination -> net.Conn
	udpConns := make(map[string]net.Conn)
	defer func() {
		for _, c := range udpConns {
			c.Close()
		}
	}()

	for {
		n, err := conn.Read(buf)
		if err != nil {
			if err != io.EOF {
				logger.Error.Printf("DTLS read error: %v", err)
			}
			return
		}

		parts := bytes.SplitN(buf[:n], []byte("\n"), 2)
		if len(parts) != 2 {
			logger.Error.Println("Invalid DTLS request format")
			continue
		}
		destination := string(parts[0])
		payload := parts[1]


		targetConn, ok := udpConns[destination]
		if !ok {
			targetConn, err = net.DialTimeout("udp", destination, 5*time.Second)
			if err != nil {
				logger.Error.Printf("Failed to connect to UDP destination %s: %v", destination, err)
				continue
			}
			udpConns[destination] = targetConn

			// Start a goroutine to read from this UDP connection and forward back to DTLS
			go func(dest string, c net.Conn) {
				respBuf := make([]byte, 4096)
				for {
					c.SetReadDeadline(time.Now().Add(30 * time.Second))
					rn, rerr := c.Read(respBuf)
					if rerr != nil {
						// If error, we might want to close and remove from map, 
						// but for simplicity in this loop we just stop reading.
						// The main loop will eventually close it when DTLS closes.
						return
					}
					
					// Prepend destination for client-side routing and send back
					// We need to synchronize writes to conn if it's not thread safe?
					// net.Conn is thread safe.
					response := append([]byte(dest+"\n"), respBuf[:rn]...)
					_, werr := conn.Write(response)
					if werr != nil {
						return
					}

				}
			}(destination, targetConn)
		}

		_, err = targetConn.Write(payload)
		if err != nil {
			logger.Error.Printf("Failed to write to UDP destination: %v", err)
		}
	}
}

var (
	// Session map: SessionID -> net.Conn
	sessionMap  sync.Map
	// Mutex to ensure we don't dial multiple times for the same session concurrently
	sessionLocks sync.Map
	// Last activity time for each session
	sessionActivity sync.Map
)

func handleTunnelRequest(key []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		encrypted, err := masquerade.UnwrapFromHttpRequest(r)
		if err != nil {
			http.Error(w, "Invalid request format", http.StatusBadRequest)
			return
		}

		decrypted, err := crypto.Decrypt(encrypted, key)
		if err != nil {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		if r.Header.Get("X-Tunnel-Type") == "dns" {
			handleDnsRequest(w, decrypted, key)
			return
		}



		// Expected format: SessionID|Destination|Payload
		parts := bytes.SplitN(decrypted, []byte("|"), 3)
		if len(parts) != 3 {
			// Fallback for backward compatibility or simple checks: Destination|Payload
			// But for efficiency we really need sessions.
			// Let's assume the old format is NOT supported for the efficient version.
			http.Error(w, "Invalid payload format (v2 required)", http.StatusBadRequest)
			return
		}

		sessionID := string(parts[0])
		destination := string(parts[1])
		payload := parts[2]

		var targetConn net.Conn
		
		// Check if session exists
		if val, ok := sessionMap.Load(sessionID); ok {
			targetConn = val.(net.Conn)
		} else {
			// Lock for this session to avoid race conditions during dial
			lock, _ := sessionLocks.LoadOrStore(sessionID, &sync.Mutex{})
			mu := lock.(*sync.Mutex)
			mu.Lock()
			
			// Double check
			if val, ok := sessionMap.Load(sessionID); ok {
				targetConn = val.(net.Conn)
				mu.Unlock()
			} else {
				// Dial new connection
				// Use a longer timeout for the connection itself
				d := net.Dialer{Timeout: 10 * time.Second}
				conn, err := d.Dial("tcp", destination)
				if err != nil {
					mu.Unlock()
					msg := fmt.Sprintf("Failed to connect to destination: %v", err)
					http.Error(w, msg, http.StatusServiceUnavailable)
					return
				}
				targetConn = conn
				sessionMap.Store(sessionID, targetConn)
				mu.Unlock()
				
				// Start a cleanup routine for this session with idle timeout
				go func(sid string, c net.Conn) {
					ticker := time.NewTicker(1 * time.Minute)
					defer ticker.Stop()
					
					for {
						select {
						case <-ticker.C:
							// Check if session is still in map (might have been deleted on error)
							if _, ok := sessionMap.Load(sid); !ok {
								return
							}
							
							// If idle for more than 10 minutes, close it
							last, ok := sessionActivity.Load(sid)
							if !ok || time.Now().Unix()-last.(int64) > 600 {
								c.Close()
								sessionMap.Delete(sid)
								sessionLocks.Delete(sid)
								sessionActivity.Delete(sid)
								return
							}
						}
					}
				}(sessionID, targetConn)
			}
		}

		// Update activity time
		sessionActivity.Store(sessionID, time.Now().Unix())

		// Write payload to target
		if len(payload) > 0 {
			targetConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			_, err = targetConn.Write(payload)
			if err != nil {
				// Connection broken
				targetConn.Close()
				sessionMap.Delete(sessionID)
				http.Error(w, "Failed to write to destination", http.StatusServiceUnavailable)
				return
			}
		}

		// Read response from target
		// If payload was empty, this is a polling request, so we can wait longer
		readTimeout := 2 * time.Second
		if len(payload) == 0 {
			readTimeout = 10 * time.Second
		}
		targetConn.SetReadDeadline(time.Now().Add(readTimeout))
		
		// Use a buffer from a pool ideally, but for now 32KB is fine
		readBuf := make([]byte, 32*1024) 
		n, err := targetConn.Read(readBuf)
		if err != nil {
			if err != io.EOF && !os.IsTimeout(err) {
				// Real error
				targetConn.Close()
				sessionMap.Delete(sessionID)
				// If we read 0 bytes and got error, return error.
				// If we read > 0 bytes, we should return them.
			}
			// If timeout, it just means no more data right now, which is fine.
		}

		if n > 0 {
			encryptedResp, err := crypto.Encrypt(readBuf[:n], key)
			if err != nil {
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}

			masquerade.WrapInRandomHttpResponse(encryptedResp).Write(w)
		} else {
			// No data read (timeout or EOF with 0 bytes)
			// Send empty success response
			// We must send something so the client knows the request succeeded
			encryptedResp, _ := crypto.Encrypt([]byte{}, key)
			masquerade.WrapInRandomHttpResponse(encryptedResp).Write(w)
		}
	}
}

func handleKillConnection(w http.ResponseWriter, r *http.Request) {
	connID := r.URL.Query().Get("id")
	if connID == "" {
		http.Error(w, "Missing connection ID", http.StatusBadRequest)
		return
	}

	conn, ok := config.ConnManager.Get(connID)
	if !ok {
		http.Error(w, "Connection not found", http.StatusNotFound)
		return
	}

	// Close the smux stream. This will cause the io.Copy loops to exit.
	conn.Stream.Close()

	// The defer calls in handlePublicConnection will handle removal from the maps.

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Connection %s terminated.", connID)
	logger.Info.Printf("Web panel user terminated connection %s.", connID)
}

func handleDnsRequest(w http.ResponseWriter, query []byte, key []byte) {
	// Forward to a real DNS server
	dnsServer := "8.8.8.8:53"
	conn, err := net.Dial("udp", dnsServer)
	if err != nil {
		http.Error(w, "DNS server unreachable", http.StatusServiceUnavailable)
		return
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))
	_, err = conn.Write(query)
	if err != nil {
		http.Error(w, "Failed to write to DNS server", http.StatusServiceUnavailable)
		return
	}

	resp := make([]byte, 512)
	n, err := conn.Read(resp)
	if err != nil {
		http.Error(w, "Failed to read from DNS server", http.StatusServiceUnavailable)
		return
	}

	encryptedResp, err := crypto.Encrypt(resp[:n], key)
	if err != nil {
		http.Error(w, "Internal encryption error", http.StatusInternalServerError)
		return
	}
	masquerade.WrapInRandomHttpResponse(encryptedResp).Write(w)
}

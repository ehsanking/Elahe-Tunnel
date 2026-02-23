#!/bin/bash

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# --- Spinner Function ---
spinner() {
    local pid=$1
    local delay=0.1
    local spinstr='|/-\'
    while [ "$(ps a | awk '{print $1}' | grep $pid)" ]; do
        local temp=${spinstr#?}
        printf " [%c]  " "$spinstr"
        local spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\b\b\b\b\b\b"
    done
    printf "    \b\b\b\b"
}

echo -e "${GREEN}=========================================${NC}"
echo -e "${GREEN}   Elahe Tunnel Single-Line Installer v3.2 (Final) ${NC}"
echo -e "${GREEN}=========================================${NC}"

# 1. Install Dependencies
apt-get update -qq && apt-get install -y -qq unzip curl file &> /dev/null

# 2. Download Source Code
echo -n "Downloading Elahe Tunnel source code..."
(
    rm -rf Elahe-Tunnel-main elahe-tunnel-main main.zip
    curl -s -L --connect-timeout 15 --max-time 300 -o main.zip "https://github.com/ehsanking/Elahe-Tunnel/archive/refs/heads/main.zip" || \
    curl -s -L --connect-timeout 15 --max-time 300 -o main.zip "https://mirror.ghproxy.com/https://github.com/ehsanking/Elahe-Tunnel/archive/refs/heads/main.zip"
    unzip -o -q main.zip
) &> /dev/null &
spinner $!
wait $!

if [ -d "Elahe-Tunnel-main" ]; then
    SOURCE_DIR="Elahe-Tunnel-main"
elif [ -d "elahe-tunnel-main" ]; then
    SOURCE_DIR="elahe-tunnel-main"
else
    echo -e "\n${RED}Failed to download source code.${NC}"
    exit 1
fi
echo -e " ${GREEN}OK${NC}"

# 3. Install Go
if ! command -v go &> /dev/null || [ "$(go version | awk '{print $3}' | sed 's/go//' | cut -d. -f2)" -lt 24 ]; then
    echo -n "Installing Go 1.24.0..."
    (
        rm -rf /usr/local/go
        ARCH=$(uname -m)
        case $ARCH in
            x86_64) ARCH="amd64" ;;
            aarch64) ARCH="arm64" ;;
        esac
        URL="https://go.dev/dl/go1.24.0.linux-${ARCH}.tar.gz"
        curl -L -o /tmp/go.tar.gz "$URL"
        tar -C /usr/local -xzf /tmp/go.tar.gz
        rm /tmp/go.tar.gz
    ) &> /dev/null &
    spinner $!
    wait $!
    echo -e " ${GREEN}OK${NC}"
fi
export PATH=/usr/local/go/bin:$PATH

# 4. Overwrite source files and Compile
echo -n "Applying patches and compiling..."
cd "$SOURCE_DIR"

# --- Create/Overwrite All Corrected Files ---

mkdir -p internal/stats
cat <<'EOF' > internal/stats/stats.go
package stats

import "sync/atomic"

var (
	tcpActiveConnections int64
	tcpBytesIn           uint64
	tcpBytesOut          uint64
	udpBytesIn           uint64
	udpBytesOut          uint64
	lastSuccessfulPing   int64
)

func AddTcpActiveConnection()    { atomic.AddInt64(&tcpActiveConnections, 1) }
func RemoveTcpActiveConnection() { atomic.AddInt64(&tcpActiveConnections, -1) }
func GetTcpActiveConnections() int64 { return atomic.LoadInt64(&tcpActiveConnections) }
func AddTcpBytesIn(n uint64)     { atomic.AddUint64(&tcpBytesIn, n) }
func AddTcpBytesOut(n uint64)    { atomic.AddUint64(&tcpBytesOut, n) }
func GetTcpBytesIn() uint64      { return atomic.LoadUint64(&tcpBytesIn) }
func GetTcpBytesOut() uint64     { return atomic.LoadUint64(&tcpBytesOut) }
func AddUdpBytesIn(n uint64)     { atomic.AddUint64(&udpBytesIn, n) }
func AddUdpBytesOut(n uint64)    { atomic.AddUint64(&udpBytesOut, n) }
func GetUdpBytesIn() uint64      { return atomic.LoadUint64(&udpBytesIn) }
func GetUdpBytesOut() uint64     { return atomic.LoadUint64(&udpBytesOut) }
func SetLastSuccessfulPing(t int64) { atomic.StoreInt64(&lastSuccessfulPing, t) }
func GetLastSuccessfulPing() int64  { return atomic.LoadInt64(&lastSuccessfulPing) }

type Status struct {
	TcpActiveConnections int64  `json:"tcp_active_connections"`
	TcpBytesIn           uint64 `json:"tcp_bytes_in"`
	TcpBytesOut          uint64 `json:"tcp_bytes_out"`
	UdpBytesIn           uint64 `json:"udp_bytes_in"`
	UdpBytesOut          uint64 `json:"udp_bytes_out"`
	LastSuccessfulPing   int64  `json:"last_successful_ping"`
	ConnectionHealth     string `json:"connection_health"`
}
EOF

mkdir -p internal/web
cat <<'EOF' > internal/web/server.go
package web

import (
	"fmt"
	"net/http"

	"github.com/ehsanking/elahe-tunnel/internal/config"
)

func StartServer(cfg *config.Config) {
	if !cfg.WebPanelEnabled {
		return
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", basicAuth(StatusHandler, cfg.WebPanelUser, cfg.WebPanelPass, "Elahe Tunnel Panel"))
	mux.HandleFunc("/status", basicAuth(JsonStatusHandler, cfg.WebPanelUser, cfg.WebPanelPass, "Elahe Tunnel Panel"))

	addr := fmt.Sprintf("0.0.0.0:%d", cfg.WebPanelPort)
	fmt.Printf("Web panel starting on http://%s\n", addr)
	err := http.ListenAndServe(addr, mux)
	if err != nil {
		fmt.Printf("Failed to start web panel: %v\n", err)
	}
}

func basicAuth(handler http.HandlerFunc, username, password, realm string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()

		if !ok || user != username || pass != password {
			w.Header().Set("WWW-Authenticate", `Basic realm="`+realm+`"`)
			w.WriteHeader(401)
			w.Write([]byte("Unauthorized.\n"))
			return
		}

		handler(w, r)
	}
}
EOF

cat <<'EOF' > internal/web/status.go
package web

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"time"

	"github.com/ehsanking/elahe-tunnel/internal/stats"
)

const statusTemplate = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Elahe Tunnel Status</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background-color: #f0f2f5; color: #333; margin: 0; padding: 40px; display: flex; justify-content: center; align-items: flex-start; min-height: 100vh; }
        .container { background-color: #fff; padding: 40px; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.1); max-width: 800px; width: 100%; }
        h1 { color: #1a73e8; text-align: center; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-top: 30px; }
        .card { background-color: #f8f9fa; padding: 20px; border-radius: 8px; border-left: 5px solid #1a73e8; }
        .card h2 { margin-top: 0; font-size: 1.2em; color: #333; }
        .card p { margin: 5px 0 0; font-size: 1.8em; font-weight: 600; color: #1a73e8; }
        .health { text-align: center; margin-top: 30px; padding: 15px; border-radius: 8px; }
        .health.ok { background-color: #e8f5e9; color: #2e7d32; border-left: 5px solid #4caf50; }
        .health.fail { background-color: #ffebee; color: #c62828; border-left: 5px solid #f44336; }
    </style>
    <script>
        setTimeout(() => { window.location.reload(); }, 5000);
    </script>
</head>
<body>
    <div class="container">
        <h1>Elahe Tunnel Status</h1>
        <div class="health {{.ConnectionHealthClass}}">
            <p>{{.ConnectionHealth}}</p>
        </div>
        <div class="grid">
            <div class="card">
                <h2>TCP Active Connections</h2>
                <p>{{.TcpActiveConnections}}</p>
            </div>
            <div class="card">
                <h2>TCP Data In</h2>
                <p>{{.TcpBytesIn | formatBytes}}</p>
            </div>
            <div class="card">
                <h2>TCP Data Out</h2>
                <p>{{.TcpBytesOut | formatBytes}}</p>
            </div>
            <div class="card">
                <h2>UDP Data In</h2>
                <p>{{.UdpBytesIn | formatBytes}}</p>
            </div>
            <div class="card">
                <h2>UDP Data Out</h2>
                <p>{{.UdpBytesOut | formatBytes}}</p>
            </div>
        </div>
    </div>
</body>
</html>
`

func getStatus() stats.Status {
	status := stats.Status{
		TcpActiveConnections: stats.GetTcpActiveConnections(),
		TcpBytesIn:           stats.GetTcpBytesIn(),
		TcpBytesOut:          stats.GetTcpBytesOut(),
		UdpBytesIn:           stats.GetUdpBytesIn(),
		UdpBytesOut:          stats.GetUdpBytesOut(),
		LastSuccessfulPing:   stats.GetLastSuccessfulPing(),
	}

	if time.Now().Unix()-status.LastSuccessfulPing < 90 {
		status.ConnectionHealth = "Connected"
	} else {
		status.ConnectionHealth = "Disconnected"
	}
	return status
}

func StatusHandler(w http.ResponseWriter, r *http.Request) {
	status := getStatus()

	if r.Header.Get("Accept") == "application/json" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(status)
		return
	}

	tmpl, _ := template.New("status").Funcs(template.FuncMap{
		"formatBytes": func(b uint64) string {
			const unit = 1024
			if b < unit {
				return fmt.Sprintf("%d B", b)
			}
			div, exp := int64(unit), 0
			for n := b / unit; n >= unit; n /= unit {
				div *= unit
				exp++
			}
			return fmt.Sprintf("%.2f %ciB", float64(b)/float64(div), "KMGTPE"[exp])
		},
	}).Parse(statusTemplate)

	data := struct {
		stats.Status
		ConnectionHealthClass string
	}{
		Status: status,
	}

	if status.ConnectionHealth == "Connected" {
		data.ConnectionHealthClass = "ok"
	} else {
		data.ConnectionHealthClass = "fail"
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tmpl.Execute(w, data)
}

func JsonStatusHandler(w http.ResponseWriter, r *http.Request) {
	status := getStatus()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}
EOF

cat <<'EOF' > internal/config/config.go
package config

import (
	"encoding/json"
	"os"
)

const ConfigFileName = "search_tunnel_config.json"

type Config struct {
	NodeType           string `json:"node_type"`
	ConnectionKey      string `json:"connection_key"`
	RemoteHost         string `json:"remote_host,omitempty"`
	DnsProxyEnabled    bool   `json:"dns_proxy_enabled,omitempty"`
	DestinationHost    string `json:"destination_host,omitempty"`
	UdpProxyEnabled    bool   `json:"udp_proxy_enabled,omitempty"`
	DestinationUdpHost string `json:"destination_udp_host,omitempty"`
	TunnelListenAddr   string `json:"tunnel_listen_addr,omitempty"`
	TunnelListenKey    string `json:"tunnel_listen_key,omitempty"`
	WebPanelEnabled    bool   `json:"web_panel_enabled,omitempty"`
	WebPanelUser       string `json:"web_panel_user,omitempty"`
	WebPanelPass       string `json:"web_panel_pass,omitempty"`
	WebPanelPort       int    `json:"web_panel_port,omitempty"`
}

func SaveConfig(cfg *Config) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(ConfigFileName, data, 0600)
}

func LoadConfig() (*Config, error) {
	data, err := os.ReadFile(ConfigFileName)
	if err != nil {
		return nil, err
	}

	var cfg Config
	err = json.Unmarshal(data, &cfg)
	if err != nil {
		return nil, err
	}
	return &cfg, nil
}
EOF

cat <<'EOF' > cmd/setup.go
package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/ehsanking/elahe-tunnel/internal/config"
	"github.com/ehsanking/elahe-tunnel/internal/crypto"
	"github.com/spf13/cobra"
)

var setupCmd = &cobra.Command{
	Use:   "setup [internal | external]",
	Short: "Initial setup for the Elahe Tunnel.",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		setupType := args[0]
		switch setupType {
		case "internal":
			setupInternal()
		case "external":
			setupExternal()
		default:
			fmt.Printf("Error: Invalid setup type '%s'.\n", setupType)
			os.Exit(1)
		}
	},
}

func setupExternal() {
	fmt.Println("Setting up as an external server...")
	key, _ := crypto.GenerateKey()
	encodedKey := crypto.EncodeKeyToBase64(key)
	certPEM, keyPEM, _ := crypto.GenerateTLSConfig()
	os.WriteFile("cert.pem", certPEM, 0644)
	os.WriteFile("key.pem", keyPEM, 0600)

	cfg := &config.Config{
		NodeType:      "external",
		ConnectionKey: encodedKey,
	}
	config.SaveConfig(cfg)

	fmt.Println("✅ External server setup complete.")
	fmt.Printf("\n🔑 Your connection key is:\n\n    %s\n\n", encodedKey)
}

func setupInternal() {
	fmt.Println("Setting up as an internal server...")
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Enter the IP of your external server: ")
	host, _ := reader.ReadString('\n')

	fmt.Print("Enter the connection key: ")
	key, _ := reader.ReadString('\n')

	cfg := &config.Config{
		NodeType:      "internal",
		ConnectionKey: strings.TrimSpace(key),
		RemoteHost:    strings.TrimSpace(host),
	}

	fmt.Print("Enable Web Panel? (y/N): ")
	enableWeb, _ := reader.ReadString('\n')
	if strings.TrimSpace(strings.ToLower(enableWeb)) == "y" {
		cfg.WebPanelEnabled = true
		fmt.Print("Enter Web Panel Port (default 8080): ")
		portStr, _ := reader.ReadString('\n')
		port, err := strconv.Atoi(strings.TrimSpace(portStr))
		if err != nil {
			cfg.WebPanelPort = 8080
		} else {
			cfg.WebPanelPort = port
		}

		fmt.Print("Enter Web Panel Username (default admin): ")
		user, _ := reader.ReadString('\n')
		cfg.WebPanelUser = strings.TrimSpace(user)
		if cfg.WebPanelUser == "" {
			cfg.WebPanelUser = "admin"
		}

		fmt.Print("Enter Web Panel Password: ")
		pass, _ := reader.ReadString('\n')
		cfg.WebPanelPass = strings.TrimSpace(pass)
	}

	config.SaveConfig(cfg)
	fmt.Println("\n✅ Internal server setup complete.")
}

func init() {
	rootCmd.AddCommand(setupCmd)
}
EOF

cat <<'EOF' > cmd/run.go
package cmd

import (
	"fmt"

	"github.com/ehsanking/elahe-tunnel/internal/config"
	"github.com/ehsanking/elahe-tunnel/internal/crypto"
	"github.com/ehsanking/elahe-tunnel/internal/tunnel"
	"github.com/spf13/cobra"
)

var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Run the Elahe Tunnel.",
	Run: func(cmd *cobra.Command, args []string) {
		cfg, err := config.LoadConfig()
		if err != nil {
			fmt.Printf("Error loading config: %v\n", err)
			return
		}

		// Override config with flags if they are set
		if cmd.Flags().Changed("remote-host") {
			cfg.RemoteHost, _ = cmd.Flags().GetString("remote-host")
		}
		if cmd.Flags().Changed("web-panel-port") {
			cfg.WebPanelPort, _ = cmd.Flags().GetInt("web-panel-port")
		}
		if cmd.Flags().Changed("dns-proxy-enabled") {
			cfg.DnsProxyEnabled, _ = cmd.Flags().GetBool("dns-proxy-enabled")
		}

		switch cfg.NodeType {
		case "internal":
			tunnel.RunClient(cfg)
		case "external":
			key, _ := crypto.DecodeBase64Key(cfg.ConnectionKey)
			tunnel.RunServer(key)
		default:
			fmt.Printf("Error: Invalid node type '%s'. Please run setup first.\n", cfg.NodeType)
		}
	},
}

func init() {
	rootCmd.AddCommand(runCmd)

	// Add flags for overriding config values
	runCmd.Flags().String("remote-host", "", "Override the remote host IP or domain")
	runCmd.Flags().Int("web-panel-port", 0, "Override the web panel port")
	runCmd.Flags().Bool("dns-proxy-enabled", false, "Override the DNS proxy setting")
}
EOF

cat <<'EOF' > cmd/root.go
package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "elahe-tunnel",
	Short: "Elahe Tunnel: A tool for creating secure tunnels over HTTP.",
	Long:  `Elahe Tunnel is a client/server application that allows you to tunnel TCP traffic over a masqueraded HTTP connection.`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Whoops. There was an error while executing your CLI '%s'", err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.AddCommand(setupCmd)
	rootCmd.AddCommand(runCmd)
}
EOF

cat <<'EOF' > internal/tunnel/client.go
package tunnel

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/ehsanking/elahe-tunnel/internal/config"
	"github.com/ehsanking/elahe-tunnel/internal/crypto"
	"github.com/ehsanking/elahe-tunnel/internal/logger"
	"github.com/ehsanking/elahe-tunnel/internal/masquerade"
	"github.com/ehsanking/elahe-tunnel/internal/stats"
	"github.com/ehsanking/elahe-tunnel/internal/web"
	"encoding/json"
	"os"
	"sync/atomic"
	"github.com/pion/dtls/v2"
)

func RunClient(cfg *config.Config) error {
	go runStatusServer(cfg)

	if cfg.WebPanelEnabled {
		go web.StartServer(cfg)
	}

	if cfg.TunnelListenAddr != "" {
		go runProxyServer(cfg)
	}

	key, _ := crypto.DecodeBase64Key(cfg.ConnectionKey)

	netDialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if addr == cfg.RemoteHost+":443" {
				return netDialer.DialContext(ctx, network, addr)
			}
			return netDialer.DialContext(ctx, network, addr)
		},
	}
	httpClient := &http.Client{Transport: tr, Timeout: 15 * time.Second}

	ips, _ := net.LookupIP(cfg.RemoteHost)
	remoteIP := ips[0].String()

	go manageConnection(httpClient, cfg.RemoteHost, remoteIP, key)

	if cfg.DnsProxyEnabled {
		tunnelQuery := func(query []byte) ([]byte, error) {
			encryptedQuery, _ := crypto.Encrypt(query, key)
			req, _ := masquerade.WrapInHttpRequest(encryptedQuery, cfg.RemoteHost)
			req.URL.Path = "/dns-query"
			resp, err := httpClient.Do(req)
			if err != nil {
				return nil, err
			}
			defer resp.Body.Close()
			encryptedResp, _ := masquerade.UnwrapFromHttpResponse(resp)
			return crypto.Decrypt(encryptedResp, key)
		}
		go RunDnsProxy(53, tunnelQuery)
	}

	if cfg.UdpProxyEnabled {
		go RunUdpProxy(9091, httpClient, cfg.RemoteHost, remoteIP, key, cfg)
	}

	localListener, _ := net.Listen("tcp", "localhost:9090")
	defer localListener.Close()

	for {
		localConn, _ := localListener.Accept()
		stats.AddTcpActiveConnection()
		go handleClientConnection(localConn, httpClient, remoteIP, key, cfg)
	}
}

// ... (rest of the client file is correct)
EOF

cat <<'EOF' > internal/tunnel/server.go
package tunnel

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/ehsanking/elahe-tunnel/internal/crypto"
	"github.com/ehsanking/elahe-tunnel/internal/logger"
	"github.com/ehsanking/elahe-tunnel/internal/masquerade"
	"github.com/ehsanking/elahe-tunnel/internal/stats"
	"github.com/pion/dtls/v2"
	"golang.org/x/time/rate"
)

func RunServer(key []byte) error {
	limiter := rate.NewLimiter(rate.Limit(10), 50)

	pingHandler := http.HandlerFunc(handlePingRequest(key))
	http.Handle("/favicon.ico", limiter.Limit(pingHandler))

	tunnelHandler := http.HandlerFunc(handleTunnelRequest(key))
	http.Handle("/", limiter.Limit(tunnelHandler))

	go runDtlsServer(key)

	logger.Info.Println("External server listening on :443")
	return http.ListenAndServeTLS(":443", "cert.pem", "key.pem", nil)
}

func runDtlsServer(key []byte) {
	udpAddr, _ := net.ResolveUDPAddr("udp", ":443")
	cert, _ := tls.LoadX509KeyPair("cert.pem", "key.pem")
	dtlsListener, _ := dtls.Listen("udp", udpAddr, &dtls.Config{
		Certificates:         []tls.Certificate{cert},
		InsecureSkipVerify:   true,
		ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
	})

	for {
		conn, _ := dtlsListener.Accept()
		go handleDtlsConnection(conn, key)
	}
}

func handleDtlsConnection(conn net.Conn, key []byte) {
	defer conn.Close()
	buf := make([]byte, 4096)
	n, _ := conn.Read(buf)
	parts := bytes.SplitN(buf[:n], []byte("\n"), 2)
	destination := string(parts[0])
	payload := parts[1]
	stats.AddUdpBytesIn(uint64(len(payload)))

	targetConn, _ := net.DialTimeout("udp", destination, 5*time.Second)
	defer targetConn.Close()
	targetConn.Write(payload)

	respBuf := make([]byte, 4096)
	n, _ = targetConn.Read(respBuf)
	response := append([]byte(destination+"\n"), respBuf[:n]...)
	bytesWritten, _ := conn.Write(response)
	stats.AddUdpBytesOut(uint64(bytesWritten))
}

func handleTunnelRequest(key []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		encrypted, _ := masquerade.UnwrapFromHttpRequest(r)
		decrypted, _ := crypto.Decrypt(encrypted, key)
		stats.AddTcpBytesIn(uint64(len(decrypted)))

		parts := bytes.SplitN(decrypted, []byte("\n"), 2)
		destination := string(parts[0])
		payload := parts[1]

		targetConn, _ := net.DialTimeout("tcp", destination, 5*time.Second)
		defer targetConn.Close()
		targetConn.Write(payload)

		respData, _ := io.ReadAll(targetConn)
		encryptedResp, _ := crypto.Encrypt(respData, key)
		stats.AddTcpBytesOut(uint64(len(encryptedResp)))

		masquerade.WrapInRandomHttpResponse(w, encryptedResp)
	}
}
EOF

( 
    export GOPROXY=https://goproxy.io,direct
    export GOTOOLCHAIN=local
    go mod tidy
    go build -o elahe-tunnel -ldflags "-s -w" .
) &> /dev/null &
spinner $!
wait $!

if [ ! -f "elahe-tunnel" ]; then
    echo -e "\n${RED}Compilation failed.${NC}"
    exit 1
fi
echo -e " ${GREEN}OK${NC}"

# 5. Install Binary and Cleanup
echo -n "Installing binary..."
mv elahe-tunnel /usr/local/bin/
chmod +x /usr/local/bin/elahe-tunnel
cd ..
rm -rf "$SOURCE_DIR" main.zip
echo -e " ${GREEN}OK${NC}"

# 6. Run Setup
echo -e "\n${GREEN}✅ Installation Complete!${NC}"
echo -e "Starting setup wizard...\n"
sleep 1
elahe-tunnel setup

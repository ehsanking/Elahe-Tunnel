package config

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtaci/smux"
)

// ActiveConnection represents a single, trackable data stream.
type ActiveConnection struct {
	ID        string
	ProxyName string
	Client    interface{} // Using interface{} to avoid import cycle
	Stream    *smux.Stream
	StartTime time.Time
}

// ConnectionManager tracks all active connections globally.
type ConnectionManager struct {
	connections map[string]*ActiveConnection
	lock        sync.RWMutex
}

// Global instance of the connection manager.
var ConnManager = &ConnectionManager{
	connections: make(map[string]*ActiveConnection),
}

func (cm *ConnectionManager) Add(conn *ActiveConnection) {
	cm.lock.Lock()
	defer cm.lock.Unlock()
	cm.connections[conn.ID] = conn
}

func (cm *ConnectionManager) Remove(id string) {
	cm.lock.Lock()
	defer cm.lock.Unlock()
	delete(cm.connections, id)
}

func (cm *ConnectionManager) Get(id string) (*ActiveConnection, bool) {
	cm.lock.RLock()
	defer cm.lock.RUnlock()
	conn, ok := cm.connections[id]
	return conn, ok
}

func ListConnections() []*ActiveConnection {
	return ConnManager.List()
}

func (cm *ConnectionManager) List() []*ActiveConnection {
	cm.lock.RLock()
	defer cm.lock.RUnlock()
	conns := make([]*ActiveConnection, 0, len(cm.connections))
	for _, conn := range cm.connections {
		conns = append(conns, conn)
	}
	return conns
}

const ConfigFileName = "search_tunnel_config.json"

// ProxyConfig defines a single port forwarding rule.
type ProxyConfig struct {
	Name       string `json:"name"`
	Type       string `json:"type"` // e.g., "tcp", "udp"
	RemotePort int    `json:"remote_port"`
	LocalIP    string `json:"local_ip"`
	LocalPort  int    `json:"local_port"`
}

// Config represents the application's configuration.
// Atomic pointer to the active configuration.
var atomicConfig atomic.Pointer[Config]

// GetConfig returns the currently active configuration.
func GetConfig() *Config {
	return atomicConfig.Load()
}

// SetConfig sets the active configuration.
func SetConfig(cfg *Config) {
	atomicConfig.Store(cfg)
}

// ReloadConfig reloads the configuration from the file and updates the atomic config.
func ReloadConfig() (*Config, error) {
	newCfg, err := LoadConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to load config for reload: %w", err)
	}
	SetConfig(newCfg)
	return newCfg, nil
}

type Config struct {
	NodeType           string `json:"node_type"`
	ConnectionKey      string `json:"connection_key"` // Stored as base64
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
	WebPanel2FASecret  string `json:"web_panel_2fa_secret,omitempty"`
	TunnelPort         int           `json:"tunnel_port,omitempty"`
	Proxies            []ProxyConfig `json:"proxies,omitempty"`
}

// SaveConfig saves the given configuration to the config file.
func SaveConfig(cfg *Config) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(ConfigFileName, data, 0600)
}

// LoadConfig loads the configuration from the config file.
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

package config

import (
	"encoding/json"
	"os"
)

const ConfigFileName = "search_tunnel_config.json"

// Config represents the application's configuration.
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

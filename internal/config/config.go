package config

import (
	"encoding/json"
	"os"
)

const ConfigFileName = "search_tunnel_config.json"

// Config represents the application's configuration.
type Config struct {
	NodeType      string `json:"node_type"`
	ConnectionKey string `json:"connection_key"` // Stored as base64
	RemoteHost    string `json:"remote_host,omitempty"`
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

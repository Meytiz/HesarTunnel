package config

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"runtime"

	"github.com/BurntSushi/toml"
)

type Config struct {
	Mode       string `toml:"mode"`
	ServerAddr string `toml:"server_addr"`
	ServerPort int    `toml:"server_port"`
	LocalPort  int    `toml:"local_port"`
	RemotePort int    `toml:"remote_port"`
	SecretKey  string `toml:"secret_key"`
	LogLevel   string `toml:"log_level"`
	Workers    int    `toml:"workers"`

	// Advanced settings
	MuxCapacity      int    `toml:"mux_capacity"`
	HeartbeatSec     int    `toml:"heartbeat_sec"`
	ReconnectSec     int    `toml:"reconnect_sec"`
	MaxReconnect     int    `toml:"max_reconnect"`
	BufferSize       int    `toml:"buffer_size"`
	Obfuscation      string `toml:"obfuscation"`
	PaddingRange     [2]int `toml:"padding_range"`
	FragmentRange    [2]int `toml:"fragment_range"`
	TLSSNI           string `toml:"tls_sni"`
	EnableMultipath  bool   `toml:"enable_multipath"`

	// Derived
	KeyHash [32]byte `toml:"-"`
}

type Overrides struct {
	Mode       string
	ServerAddr string
	ServerPort int
	LocalPort  int
	RemotePort int
	SecretKey  string
	LogLevel   string
	Workers    int
}

func Load(path string, ov Overrides) (*Config, error) {
	cfg := &Config{
		ServerPort:   4443,
		MuxCapacity:  256,
		HeartbeatSec: 15,
		ReconnectSec: 3,
		MaxReconnect: 0, // infinite
		BufferSize:   32768,
		Obfuscation:  "tls",  // tls, http, raw
		PaddingRange: [2]int{64, 256},
		FragmentRange: [2]int{1, 5},
		TLSSNI:       "cloudflare.com",
		LogLevel:     "info",
		Workers:      runtime.NumCPU(),
	}

	// Load from TOML file if provided
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read config: %w", err)
		}
		if _, err := toml.Decode(string(data), cfg); err != nil {
			return nil, fmt.Errorf("parse config: %w", err)
		}
	}

	// Apply CLI overrides
	if ov.Mode != "" { cfg.Mode = ov.Mode }
	if ov.ServerAddr != "" { cfg.ServerAddr = ov.ServerAddr }
	if ov.ServerPort > 0 { cfg.ServerPort = ov.ServerPort }
	if ov.LocalPort > 0 { cfg.LocalPort = ov.LocalPort }
	if ov.RemotePort > 0 { cfg.RemotePort = ov.RemotePort }
	if ov.SecretKey != "" { cfg.SecretKey = ov.SecretKey }
	if ov.LogLevel != "" { cfg.LogLevel = ov.LogLevel }
	if ov.Workers > 0 { cfg.Workers = ov.Workers }

	// Validate
	if err := cfg.validate(); err != nil {
		return nil, err
	}

	// Derive key hash for encryption
	cfg.KeyHash = sha256.Sum256([]byte(cfg.SecretKey))

	return cfg, nil
}

func (c *Config) validate() error {
	if c.Mode != "server" && c.Mode != "client" {
		return fmt.Errorf("mode must be 'server' or 'client'")
	}
	if c.SecretKey == "" {
		return fmt.Errorf("secret key is required (-key flag)")
	}
	if len(c.SecretKey) < 16 {
		return fmt.Errorf("secret key must be at least 16 characters")
	}
	if c.Mode == "client" {
		if c.ServerAddr == "" {
			return fmt.Errorf("server address required in client mode")
		}
		if c.LocalPort == 0 || c.RemotePort == 0 {
			return fmt.Errorf("local and remote ports required in client mode")
		}
	}
	return nil
}

func (c *Config) KeyHashHex() string {
	return hex.EncodeToString(c.KeyHash[:8])
}

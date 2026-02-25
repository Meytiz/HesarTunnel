package pkg

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"
)

// Config holds all configuration
type Config struct {
	Tunnel      TunnelConfig      `toml:"tunnel"`
	Crypto      CryptoConfig      `toml:"crypto"`
	KCP         KCPConfig         `toml:"kcp"`
	Performance PerformanceConfig `toml:"performance"`
}

type TunnelConfig struct {
	Protocol      string `toml:"protocol"`
	TunnelPort    int    `toml:"tunnel_port"`
	RemoteIP      string `toml:"remote_ip"`
	ConfigPorts   string `toml:"config_ports"`
	SecretKey     string `toml:"secret_key"`
	ServerBind    string `toml:"server_bind"`     // Server: forward address (e.g., 127.0.0.1)
	ClientForward string `toml:"client_forward"`  // Client: listen address (e.g., 0.0.0.0)
}

type CryptoConfig struct {
	Method      string `toml:"method"`
	Obfuscation bool   `toml:"obfuscation"`
	ObfsMode    string `toml:"obfs_mode"`
}

type KCPConfig struct {
	Preset      string `toml:"preset"`
	DataShard   int    `toml:"data_shard"`
	ParityShard int    `toml:"parity_shard"`
	SndWnd      int    `toml:"snd_wnd"`
	RcvWnd      int    `toml:"rcv_wnd"`
	MTU         int    `toml:"mtu"`
	DSCP        int    `toml:"dscp"`
}

type PerformanceConfig struct {
	TunnelCount int  `toml:"tunnel_count"`
	BufferSize  int  `toml:"buffer_size"`
	Timeout     int  `toml:"timeout"`
	Keepalive   int  `toml:"keepalive"`
	NoDelay     bool `toml:"no_delay"`
	MaxIdle     int  `toml:"max_idle"`
}

// LoadConfig reads and validates config from file
func LoadConfig(path string) (*Config, error) {
	cfg := &Config{}
	if _, err := toml.DecodeFile(path, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file %s: %w", path, err)
	}

	setDefaults(cfg)

	if err := validate(cfg); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	return cfg, nil
}

func setDefaults(cfg *Config) {
	if cfg.Tunnel.Protocol == "" {
		cfg.Tunnel.Protocol = "tcp"
	}
	if cfg.Tunnel.TunnelPort == 0 {
		cfg.Tunnel.TunnelPort = 4000
	}
	if cfg.Tunnel.RemoteIP == "" {
		cfg.Tunnel.RemoteIP = "0.0.0.0"
	}
	if cfg.Tunnel.ServerBind == "" {
		cfg.Tunnel.ServerBind = "127.0.0.1"
	}
	if cfg.Tunnel.ClientForward == "" {
		cfg.Tunnel.ClientForward = "0.0.0.0"
	}
	if cfg.Crypto.Method == "" {
		cfg.Crypto.Method = "chacha20-poly1305"
	}
	if cfg.Crypto.ObfsMode == "" {
		cfg.Crypto.ObfsMode = "tls-hello"
	}
	if cfg.Performance.TunnelCount <= 0 {
		cfg.Performance.TunnelCount = 4
	}
	if cfg.Performance.TunnelCount > 32 {
		cfg.Performance.TunnelCount = 32
	}
	if cfg.Performance.BufferSize <= 0 {
		cfg.Performance.BufferSize = 32768
	}
	if cfg.Performance.BufferSize > 1048576 {
		cfg.Performance.BufferSize = 1048576
	}
	if cfg.Performance.Timeout <= 0 {
		cfg.Performance.Timeout = 30
	}
	if cfg.Performance.Keepalive <= 0 {
		cfg.Performance.Keepalive = 10
	}
	if cfg.Performance.MaxIdle <= 0 {
		cfg.Performance.MaxIdle = 300
	}
	if cfg.KCP.MTU <= 0 {
		cfg.KCP.MTU = 1350
	}
	if cfg.KCP.SndWnd <= 0 {
		cfg.KCP.SndWnd = 1024
	}
	if cfg.KCP.RcvWnd <= 0 {
		cfg.KCP.RcvWnd = 1024
	}
	if cfg.KCP.DataShard <= 0 {
		cfg.KCP.DataShard = 10
	}
	if cfg.KCP.ParityShard <= 0 {
		cfg.KCP.ParityShard = 3
	}
	if cfg.KCP.Preset == "" {
		cfg.KCP.Preset = "fast2"
	}
}

func validate(cfg *Config) error {
	// Protocol
	switch cfg.Tunnel.Protocol {
	case "tcp", "kcp":
	default:
		return fmt.Errorf("invalid protocol '%s': must be 'tcp' or 'kcp'", cfg.Tunnel.Protocol)
	}

	// Tunnel port
	if cfg.Tunnel.TunnelPort < 1 || cfg.Tunnel.TunnelPort > 65535 {
		return fmt.Errorf("tunnel_port %d out of range (1-65535)", cfg.Tunnel.TunnelPort)
	}

	// Remote IP
	if cfg.Tunnel.RemoteIP != "0.0.0.0" {
		if ip := net.ParseIP(cfg.Tunnel.RemoteIP); ip == nil {
			if _, err := net.LookupHost(cfg.Tunnel.RemoteIP); err != nil {
				return fmt.Errorf("invalid remote_ip '%s': not a valid IP or hostname", cfg.Tunnel.RemoteIP)
			}
		}
	}

	// ServerBind
	if ip := net.ParseIP(cfg.Tunnel.ServerBind); ip == nil {
		return fmt.Errorf("invalid server_bind '%s': must be a valid IP", cfg.Tunnel.ServerBind)
	}

	// ClientForward
	if ip := net.ParseIP(cfg.Tunnel.ClientForward); ip == nil {
		return fmt.Errorf("invalid client_forward '%s': must be a valid IP", cfg.Tunnel.ClientForward)
	}

	// Config ports
	if cfg.Tunnel.ConfigPorts == "" {
		return fmt.Errorf("config_ports cannot be empty")
	}
	ports, err := ParsePorts(cfg.Tunnel.ConfigPorts)
	if err != nil {
		return fmt.Errorf("invalid config_ports: %w", err)
	}
	if len(ports) == 0 {
		return fmt.Errorf("no valid ports specified in config_ports")
	}
	if len(ports) > 500 {
		return fmt.Errorf("too many ports (%d), maximum is 500", len(ports))
	}

	// Secret key
	if cfg.Tunnel.SecretKey == "" {
		return fmt.Errorf("secret_key cannot be empty")
	}
	if len(cfg.Tunnel.SecretKey) < 8 {
		return fmt.Errorf("secret_key too short (minimum 8 characters)")
	}

	// Crypto method
	switch cfg.Crypto.Method {
	case "chacha20-poly1305", "aes-256-gcm":
	default:
		return fmt.Errorf("invalid crypto method '%s'", cfg.Crypto.Method)
	}

	// Obfuscation
	if cfg.Crypto.Obfuscation {
		switch cfg.Crypto.ObfsMode {
		case "tls-hello", "http", "random-padding":
		default:
			return fmt.Errorf("invalid obfs_mode '%s'", cfg.Crypto.ObfsMode)
		}
	}

	// KCP preset
	switch cfg.KCP.Preset {
	case "fast3", "fast2", "fast", "normal":
	default:
		return fmt.Errorf("invalid KCP preset '%s'", cfg.KCP.Preset)
	}

	return nil
}

// ParsePorts parses port specification: "80", "80,443", "80-100", "80,443,8000-8010"
func ParsePorts(portSpec string) ([]int, error) {
	portSpec = strings.TrimSpace(portSpec)
	if portSpec == "" {
		return nil, fmt.Errorf("empty port specification")
	}

	var ports []int
	seen := make(map[int]bool)

	parts := strings.Split(portSpec, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		if strings.Contains(part, "-") {
			rangeParts := strings.SplitN(part, "-", 2)
			if len(rangeParts) != 2 {
				return nil, fmt.Errorf("invalid port range format: '%s'", part)
			}
			start, err := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
			if err != nil {
				return nil, fmt.Errorf("invalid start port in range '%s': %w", part, err)
			}
			end, err := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
			if err != nil {
				return nil, fmt.Errorf("invalid end port in range '%s': %w", part, err)
			}
			if err := validatePort(start); err != nil {
				return nil, fmt.Errorf("range start: %w", err)
			}
			if err := validatePort(end); err != nil {
				return nil, fmt.Errorf("range end: %w", err)
			}
			if start > end {
				return nil, fmt.Errorf("invalid port range: start %d > end %d", start, end)
			}
			if end-start > 500 {
				return nil, fmt.Errorf("port range too large: %d-%d (max 500)", start, end)
			}
			for p := start; p <= end; p++ {
				if !seen[p] {
					seen[p] = true
					ports = append(ports, p)
				}
			}
		} else {
			p, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("invalid port number '%s': %w", part, err)
			}
			if err := validatePort(p); err != nil {
				return nil, err
			}
			if !seen[p] {
				seen[p] = true
				ports = append(ports, p)
			}
		}
	}

	if len(ports) == 0 {
		return nil, fmt.Errorf("no valid ports found")
	}

	return ports, nil
}

func validatePort(port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("port %d out of valid range (1-65535)", port)
	}
	return nil
}

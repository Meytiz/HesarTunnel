package pkg

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"
)

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
	ServerBind    string `toml:"server_bind"`
	ClientForward string `toml:"client_forward"`
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

func LoadConfig(path string) (*Config, error) {
	cfg := &Config{}
	if _, err := toml.DecodeFile(path, cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	setDefaults(cfg)
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

func setDefaults(cfg *Config) {
	d := func(s *string, v string) {
		if *s == "" {
			*s = v
		}
	}
	di := func(i *int, v, min, max int) {
		if *i < min {
			*i = v
		}
		if *i > max {
			*i = max
		}
	}

	d(&cfg.Tunnel.Protocol, "tcp")
	d(&cfg.Tunnel.RemoteIP, "0.0.0.0")
	d(&cfg.Tunnel.ServerBind, "127.0.0.1")
	d(&cfg.Tunnel.ClientForward, "0.0.0.0")
	d(&cfg.Crypto.Method, "chacha20-poly1305")
	d(&cfg.Crypto.ObfsMode, "tls-hello")
	d(&cfg.KCP.Preset, "fast2")

	di(&cfg.Tunnel.TunnelPort, 4000, 1, 65535)
	di(&cfg.Performance.TunnelCount, 4, 1, 32)
	di(&cfg.Performance.BufferSize, 32768, 4096, 1048576)
	di(&cfg.Performance.Timeout, 30, 5, 300)
	di(&cfg.Performance.Keepalive, 10, 3, 120)
	di(&cfg.Performance.MaxIdle, 300, 30, 3600)
	di(&cfg.KCP.MTU, 1350, 512, 1500)
	di(&cfg.KCP.SndWnd, 1024, 32, 8192)
	di(&cfg.KCP.RcvWnd, 1024, 32, 8192)
	di(&cfg.KCP.DataShard, 10, 0, 256)
	di(&cfg.KCP.ParityShard, 3, 0, 256)
}

func validateConfig(cfg *Config) error {
	switch cfg.Tunnel.Protocol {
	case "tcp", "kcp":
	default:
		return fmt.Errorf("invalid protocol '%s'", cfg.Tunnel.Protocol)
	}

	if cfg.Tunnel.RemoteIP != "0.0.0.0" {
		if net.ParseIP(cfg.Tunnel.RemoteIP) == nil {
			if _, err := net.LookupHost(cfg.Tunnel.RemoteIP); err != nil {
				return fmt.Errorf("invalid remote_ip '%s'", cfg.Tunnel.RemoteIP)
			}
		}
	}
	if net.ParseIP(cfg.Tunnel.ServerBind) == nil {
		return fmt.Errorf("invalid server_bind '%s'", cfg.Tunnel.ServerBind)
	}
	if net.ParseIP(cfg.Tunnel.ClientForward) == nil {
		return fmt.Errorf("invalid client_forward '%s'", cfg.Tunnel.ClientForward)
	}

	if cfg.Tunnel.ConfigPorts == "" {
		return fmt.Errorf("config_ports is empty")
	}
	ports, err := ParsePorts(cfg.Tunnel.ConfigPorts)
	if err != nil {
		return fmt.Errorf("config_ports: %w", err)
	}
	if len(ports) > 500 {
		return fmt.Errorf("too many ports (%d, max 500)", len(ports))
	}

	if len(cfg.Tunnel.SecretKey) < 8 {
		return fmt.Errorf("secret_key too short (min 8 chars)")
	}

	switch cfg.Crypto.Method {
	case "chacha20-poly1305", "aes-256-gcm":
	default:
		return fmt.Errorf("invalid crypto method '%s'", cfg.Crypto.Method)
	}

	if cfg.Crypto.Obfuscation {
		switch cfg.Crypto.ObfsMode {
		case "tls-hello", "http", "random-padding":
		default:
			return fmt.Errorf("invalid obfs_mode '%s'", cfg.Crypto.ObfsMode)
		}
	}

	switch cfg.KCP.Preset {
	case "fast3", "fast2", "fast", "normal":
	default:
		return fmt.Errorf("invalid KCP preset '%s'", cfg.KCP.Preset)
	}

	return nil
}

func ParsePorts(spec string) ([]int, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, fmt.Errorf("empty port specification")
	}

	var ports []int
	seen := make(map[int]bool)

	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		if idx := strings.IndexByte(part, '-'); idx >= 0 {
			start, err := strconv.Atoi(strings.TrimSpace(part[:idx]))
			if err != nil {
				return nil, fmt.Errorf("invalid range start in '%s'", part)
			}
			end, err := strconv.Atoi(strings.TrimSpace(part[idx+1:]))
			if err != nil {
				return nil, fmt.Errorf("invalid range end in '%s'", part)
			}
			if err := checkPort(start); err != nil {
				return nil, err
			}
			if err := checkPort(end); err != nil {
				return nil, err
			}
			if start > end {
				return nil, fmt.Errorf("range start > end: %d > %d", start, end)
			}
			if end-start > 500 {
				return nil, fmt.Errorf("range too large: %d-%d", start, end)
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
				return nil, fmt.Errorf("invalid port '%s'", part)
			}
			if err := checkPort(p); err != nil {
				return nil, err
			}
			if !seen[p] {
				seen[p] = true
				ports = append(ports, p)
			}
		}
	}

	if len(ports) == 0 {
		return nil, fmt.Errorf("no ports found")
	}
	return ports, nil
}

func checkPort(p int) error {
	if p < 1 || p > 65535 {
		return fmt.Errorf("port %d out of range (1-65535)", p)
	}
	return nil
}

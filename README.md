<div align="center">

# 🏰 HesarTunnel

**High-Performance Encrypted Reverse Tunnel with DPI Resistance**

[![Go](https://img.shields.io/badge/Go-1.22+-00ADD8?style=for-the-badge&logo=go&logoColor=white)](https://go.dev)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![Linux](https://img.shields.io/badge/Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)](https://github.com/Meytiz/HesarTunnel)
[![Release](https://img.shields.io/badge/Version-1.2.0-blue?style=for-the-badge)](https://github.com/Meytiz/HesarTunnel/releases)

*Secure, fast, and resource-efficient reverse tunnel designed to bypass Deep Packet Inspection (DPI) systems*

[Installation](#-quick-start) •
[Features](#-features) •
[Configuration](#-configuration) •
[Architecture](#-architecture) •
[Security](#-security)

</div>

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🔄 **Reverse Tunnel** | Iran server connects outbound to foreign server |
| 🛡️ **DPI Resistance** | Traffic obfuscation: TLS 1.3 records, HTTP, random padding |
| 🔐 **Strong Encryption** | XChaCha20-Poly1305 / AES-256-GCM with HKDF-SHA256 |
| ⚡ **Dual Protocol** | TCP and KCP (UDP-based) transport |
| 📊 **~1:1 Traffic** | Minimal overhead (~40 bytes/packet for encryption) |
| 🔁 **Auto Reconnect** | Exponential backoff with connection pooling |
| 🧵 **Multiplexed** | Thread-safe multiplexer prevents race conditions |
| 💾 **Low Resources** | Buffer pooling, atomic operations, zero-copy paths |
| 🔧 **Easy Setup** | Interactive shell script for installation |
| 📦 **Single Binary** | No runtime dependencies |

---

## 🏗️ Architecture

```
┌──────────────────────────────┐              ┌──────────────────────────────┐
│          🇮🇷 IRAN SERVER     │              │        🌍 FOREIGN SERVER     │
│          (Client Mode)       │              │         (Server Mode)        │
│                              │              │                              │
│  ┌────────────────────────┐  │              │  ┌────────────────────────┐  │
│  │     Local Services     │  │              │  │      Public Ports      │  │
│  │  127.0.0.1:80          │  │              │  │  0.0.0.0:80            │  │
│  │  127.0.0.1:443         │  │              │  │  0.0.0.0:443           │  │
│  └────────────────────────┘  │              │  └────────────────────────┘  │
│              ▲               │              │               ▲              │
│              │               │              │               │              │
│              │               │              │               │              │
│              └───────┐  ENCRYPTED & OBFUSCATED TUNNEL  ┌───────┘          │
│                      │  (TCP / KCP + TLS / HTTP / PAD)  │                  │
│              ┌───────┘        Multiplexed Streams       └───────┐          │
│              │               (Thread-Safe Mux)                 │          │
│              ▼                                                    ▼          │
└──────────────────────────────┘              └──────────────────────────────┘
```

### Data Flow

User → Foreign:ConfigPort → Encrypt+Obfuscate → Tunnel → Deobfuscate+Decrypt → Iran:LocalService  
User ← Foreign:ConfigPort ← Decrypt+Deobfuscate ← Tunnel ← Obfuscate+Encrypt ← Iran:LocalService  

---

## 🚀 Quick Start

### One-Line Installation

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/Meytiz/HesarTunnel/main/hesar-manager.sh)
```

### Manual Build

```bash
git clone https://github.com/Meytiz/HesarTunnel.git
cd HesarTunnel
make build
sudo make install
```

---

## 📖 Usage

### Interactive (Recommended)

```bash
sudo bash hesar-manager.sh
```

Menu options:

- Optimize Server — BBR, sysctl, ulimits  
- Setup Iran — Client configuration  
- Setup Foreign — Server configuration  
- Status — View tunnel status & connections  
- Manage — Start/Stop/Restart/Logs  
- Uninstall — Remove tunnel/binary/all  

---

### Command Line

```bash
# Foreign server
hesar-tunnel --mode server --config /etc/hesar-tunnel/config.toml

# Iran server
hesar-tunnel --mode client --config /etc/hesar-tunnel/config.toml

# Validate config
hesar-tunnel --validate --config config.toml

# Version info
hesar-tunnel --version
```

---

## ⚙️ Configuration

### Port Formats

| Format | Example | Description |
|--------|----------|------------|
| Single | 80 | One port |
| Multi | 80,443,8080 | Multiple ports |
| Range | 80-100 | Port range (21 ports) |
| Mixed | 80,443,8000-8010 | Combined |

---

### Encryption

| Method | Nonce | Best For |
|--------|--------|----------|
| chacha20-poly1305 | 24 bytes (XChaCha20) | CPUs without AES-NI |
| aes-256-gcm | 12 bytes | CPUs with AES-NI |

---

### Obfuscation Modes

| Mode | Overhead | Description |
|------|----------|-------------|
| tls-hello | 5 bytes | TLS 1.3 Application Data records |
| http | ~80 bytes | HTTP response wrapper |
| random-padding | 22-134 bytes | Random padding with length prefix |

---

### Transport

| Protocol | Use Case |
|----------|----------|
| tcp | Stable connections, lower overhead |
| kcp | Lossy networks, faster retransmission |

---

## 🔒 Security

- HKDF-SHA256 key derivation from shared secret  
- XChaCha20-Poly1305 with 24-byte nonces (no reuse risk)  
- Atomic nonce counter prevents nonce collision  
- HMAC-SHA256 constant-time authentication  
- No certificates needed — pre-shared key model  
- Traffic obfuscation against DPI (Iran, China, Russia)  

---

## 📊 Performance

- Buffer pooling with sync.Pool reduces GC pressure  
- Multiplexed tunnels with thread-safe writes (Mux)  
- Round-robin tunnel selection for load balancing  
- Atomic connection ID generation  
- Socket buffer tuning (4MB read/write buffers)  
- BBR congestion control (via server optimization)  

---

## 📋 Requirements

- OS: Linux (Ubuntu 18+, Debian 10+, CentOS 7+, AlmaLinux, Rocky)  
- Arch: amd64, arm64  
- Privileges: Root (for port binding and optimization)  
- Build: Go 1.22+ (only for building from source)  

---

## 🤝 Contributing

1. Fork the repository  
2. Create your feature branch (`git checkout -b feature/amazing`)  
3. Commit your changes (`git commit -m 'Add amazing feature'`)  
4. Push to the branch (`git push origin feature/amazing`)  
5. Open a Pull Request  

---

## 📄 License

MIT License - see LICENSE for details.

---

## ⚠️ Disclaimer

This software is provided for educational and legitimate purposes. Users are responsible for compliance with applicable laws in their jurisdiction.

<div align="center">

⬆ Back to top  

Made with ❤️ by Meytiz

</div>

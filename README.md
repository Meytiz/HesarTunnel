# 🏰 HesarTunnel

**Secure Reverse Tunnel with Anti-DPI Obfuscation**

[![Go Version](https://img.shields.io/badge/Go-1.22+-00ADD8?logo=go)](https://go.dev)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Release](https://img.shields.io/badge/Release-v1.2.0-blue.svg)](https://github.com/Meytiz/HesarTunnel/releases)

HesarTunnel is a high-performance reverse tunnel written in Go, designed to bypass Deep Packet Inspection (DPI) systems used in Iran, China, and Russia. It creates an encrypted, obfuscated tunnel between two servers without requiring domain names or TLS certificates.

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🔐 **XChaCha20-Poly1305** | Military-grade AEAD encryption with HKDF key derivation |
| 🛡️ **Anti-DPI** | TLS 1.3 mimicry, random padding, TCP fragmentation |
| 🔄 **Reverse Tunnel** | Iran → Foreign (outbound connection bypasses firewalls) |
| ⚡ **Multiplexing** | Multiple streams over single connection |
| 📊 **1:1 Traffic** | Minimal overhead (~40 bytes/frame) |
| 🔧 **Easy Setup** | One-command installer with interactive wizard |
| 💾 **Low Resources** | Buffer pooling, zero-allocation I/O paths |
| ♻️ **Auto-Reconnect** | Exponential backoff with infinite retry |
| 💓 **Keepalive** | Configurable heartbeat for connection health |
| 🐧 **Systemd** | Full service integration with security hardening |

---

## 🚀 Quick Start

\`\`\`bash
bash <(curl -fsSL https://raw.githubusercontent.com/Meytiz/HesarTunnel/main/hesar-manager.sh)
\`\`\`

---

## 📖 Manual Setup

### Foreign Server (Server Mode)

\`\`\`bash
./hesartunnel -mode server -port 4443 -key "your-secret-key-here"
\`\`\`

### Iran Server (Client Mode - Reverse)

\`\`\`bash
./hesartunnel -mode client \\
  -server your-foreign-server.com \\
  -port 4443 \\
  -local 8080 \\
  -remote 443 \\
  -key "your-secret-key-here"
\`\`\`

---

## 🏗️ Architecture

\`\`\`
┌─────────────────┐         ┌─────────────────────┐         ┌─────────────┐
│   Users/Clients │ ──TCP──▶│   Foreign Server     │◀──────  │ Iran Server │
│   (Internet)    │         │   (HesarTunnel SRV)  │ Reverse │ (HesarTunnel│
│                 │         │   Public Port :443   │ Tunnel  │  CLI)       │
│                 │         │                      │ (Out)   │ Local :8080 │
└─────────────────┘         └─────────────────────┘         └─────────────┘
                                       │
                            ┌──────────┴──────────┐
                            │   Encrypted Tunnel   │
                            │ XChaCha20-Poly1305   │
                            │ TLS 1.3 Mimicry      │
                            │ Random Padding        │
                            │ TCP Fragmentation     │
                            └─────────────────────┘
\`\`\`

---

## 🛡️ Anti-DPI Techniques

### 1. TLS 1.3 Record Mimicry
All tunnel traffic is wrapped in TLS 1.3 Application Data records (content type 0x17), making it indistinguishable from legitimate HTTPS traffic.

### 2. Fake ClientHello
The initial connection sends a realistic TLS ClientHello with configurable SNI, modern cipher suites, and X25519 key shares.

### 3. TCP Fragmentation
TCP segments are randomly split into 1-5 fragments with timing jitter, defeating DPI systems that rely on reassembling the first packet.

### 4. Random Padding
Each frame includes 64-256 bytes of random padding, preventing length-based traffic fingerprinting.

### 5. No Domain/Certificate Required
Uses pre-shared key (PSK) authentication with HKDF-SHA256 key derivation — no need for domain names or TLS certificates.

---

## ⚙️ Configuration

\`\`\`toml
# /etc/hesartunnel/config.toml
mode = "client"
server_addr = "your-foreign-server.com"
server_port = 4443
local_port = 8080
remote_port = 443
secret_key = "your-super-secret-key-change-this!"
obfuscation = "tls"
tls_sni = "cloudflare.com"
padding_range = [64, 256]
fragment_range = [1, 5]
\`\`\`

---

## 📊 Performance

| Metric | Value |
|--------|-------|
| Encryption overhead | ~40 bytes/frame |
| Traffic ratio | ~1:1 (with minimal padding) |
| Max concurrent streams | 256 (configurable) |
| Memory per connection | ~64 KB |
| Reconnect time | 3s base (exponential backoff) |

---

## 🔧 Build from Source

\`\`\`bash
git clone https://github.com/Meytiz/HesarTunnel.git
cd HesarTunnel
CGO_ENABLED=0 go build -ldflags="-s -w" -o hesartunnel .
\`\`\`

---

## 🛡️ Handshake Protocol

\`\`\`
Client (Iran)                          Server (Foreign)
     │                                        │
     │─── [FakeClientHello] ────────────────▶│  (optional, auto-detected)
     │                                        │
     │─── [32-byte Salt] ──────────────────▶│  (raw TCP)
     │                                        │
     │    ┌─ Both derive key: ──────────────┐ │
     │    │  HKDF(PSK, Salt, "hesartunnel") │ │
     │    └─────────────────────────────────┘ │
     │                                        │
     │─── [Encrypted Auth] ────────────────▶│  (TLS record wrapped)
     │                                        │
     │◀══════ Mux Session ════════════════▶│  (encrypted + obfuscated)
     │                                        │
\`\`\`

---

## 📜 License

MIT License - see [LICENSE](LICENSE) file.

---

## 🤝 Contributing

Contributions are welcome! Please open an issue or pull request.

---

**Made with ❤️ for internet freedom**

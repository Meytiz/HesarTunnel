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

## 🏗️ Architecture

# HESAR

> Lightweight remote connectivity and management platform built with Go.

HESAR is a Go-based project that combines a backend service and a web management panel for handling remote connectivity and service orchestration through a simple interface.

---

## Features

- Go backend
- Web-based management panel
- Release build system
- Linux build support
- Frontend asset bundling
- Automated installation script
- Modular project structure
- GitHub-friendly deployment workflow

---

## Project Structure

```text
cmd/
configs/
internal/
pkg/
public/
scripts/
release/
```

---

## Requirements

### Backend

- Go 1.24+

### Frontend

- Node.js
- npm

---

## Installation

### Automatic Installation

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/Meytiz/HesarTunnel/main/install.sh)
```

The installer automatically:

- Downloads required files
- Configures the environment
- Installs HESAR
- Starts required services

---

### Manual Installation

Clone repository:

```bash
git clone https://github.com/Meytiz/HesarTunnel.git
cd HesarTunnel
```

Install dependencies:

```bash
go mod download
npm install
```

Build frontend:

```bash
npm run build
```

Build backend:

```bash
go build ./...
```

Run:

```bash
go run .
```

---

## Release Build

Linux AMD64:

```bash
GOOS=linux GOARCH=amd64 HESAR_VERSION=1.4.2 bash ./scripts/build-release.sh
```

PowerShell:

```powershell
$env:GOOS="linux"
$env:GOARCH="amd64"
$env:HESAR_VERSION="1.4.2"

bash .\scripts\build-release.sh
```

---

## Development

Run frontend:

```bash
npm run dev
```

Run backend:

```bash
go run .
```

---

## Status

🚧 Active Development

This project is currently under active development.

---

## License

MIT License

---

## Author

GitHub: https://github.com/Meytiz

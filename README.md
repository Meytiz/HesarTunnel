## 🚀 Installation

### Automatic Installation

Install HESAR using the official installation script:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/Meytiz/HesarTunnel/main/install.sh)
```

The installer will guide you through:

- Panel configuration
- Administrator account creation
- Service setup
- Automatic startup configuration

After installation, the script will display:

```text
Panel URL
Panel Port
Username
Password
```

---

### Offline Installation

For environments without direct GitHub access:

```bash
git clone https://github.com/Meytiz/HesarTunnel.git
cd HesarTunnel
```

Build the frontend:

```bash
npm install
npm run build
```

Build the backend:

```bash
go build -o hesar .
```

Run:

```bash
./hesar
```

---

### Update

Update to the latest version:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/Meytiz/HesarTunnel/main/install.sh)
```

---

### Uninstall

Remove HESAR completely:

```bash
hesar uninstall
```

Or remove only specific components from the management panel.

#!/usr/bin/env bash
#
# HesarTunnel Manager - Quick Install & Management Script
# Usage: bash <(curl -fsSL https://raw.githubusercontent.com/YOUR_USER/HesarTunnel/main/hesar-manager.sh)
#
# Supports: Ubuntu 20+, Debian 11+, CentOS 8+, AlmaLinux 8+
#

set -euo pipefail

# ─────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────
VERSION="1.2.0"
REPO="YOUR_USER/HesarTunnel"
BINARY_NAME="hesartunnel"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/hesartunnel"
SERVICE_NAME="hesartunnel"
LOG_FILE="/var/log/hesartunnel.log"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m'
BOLD='\033[1m'

# ─────────────────────────────────────────────────────────
# Banner
# ─────────────────────────────────────────────────────────
show_banner() {
    clear
    echo -e "${CYAN}"
    echo "  ╦ ╦┌─┐┌─┐┌─┐┬─┐╔╦╗┬ ┬┌┐┌┌┐┌┌─┐┬  "
    echo "  ╠═╣├┤ └─┐├─┤├┬┘ ║ │ │││││││├┤ │  "
    echo "  ╩ ╩└─┘└─┘┴ ┴┴└─ ╩ └─┘┘└┘┘└┘└─┘┴─┘"
    echo -e "${NC}"
    echo -e "  ${BOLD}Secure Reverse Tunnel with Anti-DPI${NC}"
    echo -e "  ${PURPLE}Version: ${VERSION}${NC}"
    echo -e "  ─────────────────────────────────────"
    echo ""
}

# ─────────────────────────────────────────────────────────
# Utility Functions
# ─────────────────────────────────────────────────────────
log_info()  { echo -e "  ${GREEN}[✓]${NC} $1"; }
log_warn()  { echo -e "  ${YELLOW}[!]${NC} $1"; }
log_error() { echo -e "  ${RED}[✗]${NC} $1"; }
log_step()  { echo -e "  ${CYAN}[→]${NC} $1"; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$ID
        OS_VERSION=$VERSION_ID
    else
        log_error "Unsupported operating system"
        exit 1
    fi
}

detect_arch() {
    ARCH=$(uname -m)
    case $ARCH in
        x86_64)  ARCH="amd64" ;;
        aarch64) ARCH="arm64" ;;
        armv7l)  ARCH="armv7" ;;
        *)
            log_error "Unsupported architecture: $ARCH"
            exit 1
            ;;
    esac
}

# ─────────────────────────────────────────────────────────
# Install
# ─────────────────────────────────────────────────────────
install_hesartunnel() {
    log_step "Detecting system..."
    detect_os
    detect_arch
    log_info "OS: $OS $OS_VERSION | Arch: $ARCH"

    # Install dependencies
    log_step "Installing dependencies..."
    case $OS in
        ubuntu|debian)
            apt-get update -qq
            apt-get install -y -qq curl wget jq > /dev/null 2>&1
            ;;
        centos|almalinux|rocky|fedora)
            yum install -y -q curl wget jq > /dev/null 2>&1
            ;;
    esac
    log_info "Dependencies installed"

    # Download binary
    log_step "Downloading HesarTunnel v${VERSION}..."
    DOWNLOAD_URL="https://github.com/${REPO}/releases/download/v${VERSION}/${BINARY_NAME}_${VERSION}_linux_${ARCH}.tar.gz"

    cd /tmp
    if curl -fsSL "$DOWNLOAD_URL" -o hesartunnel.tar.gz; then
        tar xzf hesartunnel.tar.gz
        mv $BINARY_NAME $INSTALL_DIR/
        chmod +x $INSTALL_DIR/$BINARY_NAME
        rm -f hesartunnel.tar.gz
        log_info "Binary installed to $INSTALL_DIR/$BINARY_NAME"
    else
        log_warn "Download failed, building from source..."
        install_from_source
    fi

    # Create config directory
    mkdir -p $CONFIG_DIR
    log_info "Config directory: $CONFIG_DIR"

    log_info "Installation complete!"
    echo ""
}

install_from_source() {
    log_step "Installing Go compiler..."
    GO_VERSION="1.22.5"
    curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${ARCH}.tar.gz" -o /tmp/go.tar.gz
    rm -rf /usr/local/go
    tar -C /usr/local -xzf /tmp/go.tar.gz
    export PATH=$PATH:/usr/local/go/bin
    rm -f /tmp/go.tar.gz

    log_step "Cloning repository..."
    cd /tmp
    git clone "https://github.com/${REPO}.git" hesartunnel-src
    cd hesartunnel-src

    log_step "Building..."
    CGO_ENABLED=0 go build -ldflags="-s -w" -o $INSTALL_DIR/$BINARY_NAME .
    cd /
    rm -rf /tmp/hesartunnel-src

    log_info "Built from source successfully"
}

# ─────────────────────────────────────────────────────────
# Configuration Wizard
# ─────────────────────────────────────────────────────────
configure_tunnel() {
    echo -e "  ${BOLD}┌─ Tunnel Configuration ─────────────────┐${NC}"
    echo ""

    # Mode selection
    echo -e "  ${CYAN}Select mode:${NC}"
    echo -e "    ${GREEN}1)${NC} Server (Foreign VPS)"
    echo -e "    ${GREEN}2)${NC} Client (Iran Server - Reverse)"
    echo ""
    read -p "  Choice [1-2]: " MODE_CHOICE

    case $MODE_CHOICE in
        1) MODE="server" ;;
        2) MODE="client" ;;
        *) log_error "Invalid choice"; return ;;
    esac

    # Common settings
    read -p "  Control port [4443]: " PORT
    PORT=${PORT:-4443}

    read -p "  Secret key (16+ chars): " SECRET_KEY
    if [[ ${#SECRET_KEY} -lt 16 ]]; then
        log_error "Key must be at least 16 characters"
        return
    fi

    # Client-specific settings
    if [[ $MODE == "client" ]]; then
        read -p "  Foreign server address: " SERVER_ADDR
        read -p "  Local port to expose: " LOCAL_PORT
        read -p "  Remote public port: " REMOTE_PORT

        echo ""
        echo -e "  ${CYAN}Anti-DPI obfuscation:${NC}"
        echo -e "    ${GREEN}1)${NC} TLS 1.3 Mimicry (recommended)"
        echo -e "    ${GREEN}2)${NC} HTTP Obfuscation"
        echo -e "    ${GREEN}3)${NC} Raw (no obfuscation)"
        read -p "  Choice [1-3]: " OBF_CHOICE

        case $OBF_CHOICE in
            1) OBF="tls" ;;
            2) OBF="http" ;;
            3) OBF="raw" ;;
            *) OBF="tls" ;;
        esac

        if [[ $OBF == "tls" ]]; then
            read -p "  Fake SNI domain [cloudflare.com]: " SNI
            SNI=${SNI:-cloudflare.com}
        fi
    fi

    # Generate config
    CONFIG_FILE="$CONFIG_DIR/config.toml"

    cat > $CONFIG_FILE <<EOF
# HesarTunnel Configuration
# Generated: $(date)

mode = "$MODE"
server_port = $PORT
secret_key = "$SECRET_KEY"
log_level = "info"
workers = 0
mux_capacity = 256
buffer_size = 32768
heartbeat_sec = 15
reconnect_sec = 3
max_reconnect = 0
EOF

    if [[ $MODE == "client" ]]; then
        cat >> $CONFIG_FILE <<EOF

server_addr = "$SERVER_ADDR"
local_port = $LOCAL_PORT
remote_port = $REMOTE_PORT
obfuscation = "$OBF"
tls_sni = "${SNI:-cloudflare.com}"
padding_range = [64, 256]
fragment_range = [1, 5]
EOF
    else
        cat >> $CONFIG_FILE <<EOF

obfuscation = "tls"
tls_sni = "cloudflare.com"
padding_range = [64, 256]
fragment_range = [1, 5]
EOF
    fi

    log_info "Config saved to $CONFIG_FILE"

    # Create systemd service
    create_service
}

# ─────────────────────────────────────────────────────────
# Systemd Service
# ─────────────────────────────────────────────────────────
create_service() {
    cat > /etc/systemd/system/${SERVICE_NAME}.service <<EOF
[Unit]
Description=HesarTunnel - Secure Reverse Tunnel
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$INSTALL_DIR/$BINARY_NAME -config $CONFIG_DIR/config.toml
Restart=always
RestartSec=3
LimitNOFILE=65536
StandardOutput=append:$LOG_FILE
StandardError=append:$LOG_FILE

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$CONFIG_DIR $LOG_FILE

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    log_info "Systemd service created"
}

# ─────────────────────────────────────────────────────────
# Service Management
# ─────────────────────────────────────────────────────────
start_tunnel()   { systemctl start $SERVICE_NAME   && log_info "Tunnel started"; }
stop_tunnel()    { systemctl stop $SERVICE_NAME    && log_info "Tunnel stopped"; }
restart_tunnel() { systemctl restart $SERVICE_NAME && log_info "Tunnel restarted"; }
enable_tunnel()  { systemctl enable $SERVICE_NAME  && log_info "Autostart enabled"; }
disable_tunnel() { systemctl disable $SERVICE_NAME && log_info "Autostart disabled"; }

status_tunnel() {
    echo ""
    if systemctl is-active --quiet $SERVICE_NAME; then
        echo -e "  Status: ${GREEN}● Running${NC}"
    else
        echo -e "  Status: ${RED}● Stopped${NC}"
    fi

    if systemctl is-enabled --quiet $SERVICE_NAME 2>/dev/null; then
        echo -e "  Autostart: ${GREEN}Enabled${NC}"
    else
        echo -e "  Autostart: ${YELLOW}Disabled${NC}"
    fi

    if [[ -f $CONFIG_DIR/config.toml ]]; then
        MODE=$(grep '^mode' $CONFIG_DIR/config.toml | cut -d'"' -f2)
        echo -e "  Mode: ${CYAN}$MODE${NC}"
    fi

    echo ""
    echo -e "  ${BOLD}Recent logs:${NC}"
    tail -5 $LOG_FILE 2>/dev/null || echo "  No logs yet"
    echo ""
}

# ─────────────────────────────────────────────────────────
# Uninstall
# ─────────────────────────────────────────────────────────
uninstall_hesartunnel() {
    echo ""
    read -p "  Are you sure? This will remove HesarTunnel. [y/N]: " CONFIRM
    if [[ $CONFIRM != "y" && $CONFIRM != "Y" ]]; then
        return
    fi

    systemctl stop $SERVICE_NAME 2>/dev/null || true
    systemctl disable $SERVICE_NAME 2>/dev/null || true
    rm -f /etc/systemd/system/${SERVICE_NAME}.service
    systemctl daemon-reload
    rm -f $INSTALL_DIR/$BINARY_NAME
    rm -rf $CONFIG_DIR
    rm -f $LOG_FILE

    log_info "HesarTunnel has been completely removed"
}

# ─────────────────────────────────────────────────────────
# Main Menu
# ─────────────────────────────────────────────────────────
main_menu() {
    while true; do
        show_banner
        echo -e "  ${BOLD}┌─ Main Menu ────────────────────────────┐${NC}"
        echo ""
        echo -e "    ${GREEN}1)${NC}  Install HesarTunnel"
        echo -e "    ${GREEN}2)${NC}  Configure Tunnel"
        echo -e "    ${GREEN}3)${NC}  Start Tunnel"
        echo -e "    ${GREEN}4)${NC}  Stop Tunnel"
        echo -e "    ${GREEN}5)${NC}  Restart Tunnel"
        echo -e "    ${GREEN}6)${NC}  Tunnel Status"
        echo -e "    ${GREEN}7)${NC}  Enable Autostart"
        echo -e "    ${GREEN}8)${NC}  View Logs"
        echo -e "    ${GREEN}9)${NC}  Edit Config"
        echo -e "    ${GREEN}10)${NC} Uninstall"
        echo -e "    ${GREEN}0)${NC}  Exit"
        echo ""
        echo -e "  ${BOLD}└────────────────────────────────────────┘${NC}"
        echo ""
        read -p "  Select option: " CHOICE

        case $CHOICE in
            1)  install_hesartunnel ;;
            2)  configure_tunnel ;;
            3)  start_tunnel ;;
            4)  stop_tunnel ;;
            5)  restart_tunnel ;;
            6)  status_tunnel ;;
            7)  enable_tunnel ;;
            8)  echo ""; tail -50 $LOG_FILE 2>/dev/null || echo "  No logs"; echo "" ;;
            9)  ${EDITOR:-nano} $CONFIG_DIR/config.toml ;;
            10) uninstall_hesartunnel ;;
            0)  echo ""; log_info "Goodbye!"; exit 0 ;;
            *)  log_error "Invalid option" ;;
        esac

        echo ""
        read -p "  Press Enter to continue..."
    done
}

# ─────────────────────────────────────────────────────────
# Entry Point
# ─────────────────────────────────────────────────────────
check_root
main_menu

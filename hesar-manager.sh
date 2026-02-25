#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════
# HesarTunnel Manager v1.2.0
# https://github.com/Meytiz/HesarTunnel
# ═══════════════════════════════════════════════════════════

set -euo pipefail

# ─── Constants ────────────────────────────────────────────
readonly GITHUB_USER="Meytiz"
readonly GITHUB_REPO="HesarTunnel"
readonly BINARY_NAME="hesar-tunnel"
readonly SERVICE_NAME="hesar-tunnel"
readonly INSTALL_DIR="/usr/local/bin"
readonly CONFIG_DIR="/etc/hesar-tunnel"
readonly CONFIG_FILE="${CONFIG_DIR}/config.toml"
readonly SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
readonly LOG_FILE="/var/log/hesar-tunnel.log"
readonly HESAR_VERSION="1.2.0"

# ─── Colors ───────────────────────────────────────────────
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly PURPLE='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly WHITE='\033[1;37m'
readonly BOLD='\033[1m'
readonly NC='\033[0m'

# ─── Logging ──────────────────────────────────────────────
info()  { echo -e "${GREEN}[✓]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[✗]${NC} $*"; }
step()  { echo -e "${CYAN}[→]${NC} $*"; }

separator() {
    echo -e "${BLUE}══════════════════════════════════════════════════════════${NC}"
}

# ─── Checks ──────────────────────────────────────────────

check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root"
        exit 1
    fi
}

detect_arch() {
    case "$(uname -m)" in
        x86_64|amd64)  ARCH="amd64" ;;
        aarch64|arm64) ARCH="arm64" ;;
        *)
            error "Unsupported architecture: $(uname -m)"
            exit 1
            ;;
    esac
}

detect_os() {
    if [[ -f /etc/os-release ]]; then
        OS=$(grep -oP '^ID=\K.*' /etc/os-release | tr -d '"' | head -1)
    elif [[ -f /etc/centos-release ]]; then
        OS="centos"
    else
        OS="unknown"
    fi
}

install_deps() {
    step "Checking dependencies..."
    local missing=()

    for cmd in curl wget tar git; do
        if ! command -v "$cmd" &>/dev/null; then
            missing+=("$cmd")
        fi
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        step "Installing: ${missing[*]}"
        case "$OS" in
            ubuntu|debian)
                apt-get update -qq &>/dev/null
                apt-get install -y -qq "${missing[@]}" &>/dev/null
                ;;
            centos|rhel|fedora|almalinux|rocky)
                yum install -y -q "${missing[@]}" &>/dev/null
                ;;
            *)
                warn "Cannot auto-install. Please install: ${missing[*]}"
                ;;
        esac
    fi
    info "Dependencies OK"
}

# ─── Service Helpers ──────────────────────────────────────

is_installed() {
    [[ -f "${INSTALL_DIR}/${BINARY_NAME}" ]]
}

is_running() {
    systemctl is-active --quiet "${SERVICE_NAME}" 2>/dev/null
}

# ─── Config Reader Helpers ────────────────────────────────

get_config_value() {
    local key="$1"
    if [[ -f "$CONFIG_FILE" ]]; then
        grep "^${key}" "$CONFIG_FILE" 2>/dev/null | head -1 | sed 's/.*= *//;s/"//g;s/ *$//'
    fi
}

get_service_mode() {
    if [[ -f "$SERVICE_FILE" ]]; then
        grep -oP '(?<=--mode )\w+' "$SERVICE_FILE" 2>/dev/null | head -1
    fi
}

# ─── Banner ───────────────────────────────────────────────

print_banner() {
    clear
    echo -e "${CYAN}"
    cat << 'BANNER'
    ╔═══════════════════════════════════════════════════╗
    ║                                                   ║
    ║    ██╗  ██╗███████╗███████╗ █████╗ ██████╗        ║
    ║    ██║  ██║██╔════╝██╔════╝██╔══██╗██╔══██╗       ║
    ║    ███████║█████╗  ███████╗███████║██████╔╝       ║
    ║    ██╔══██║██╔══╝  ╚════██║██╔══██║██╔══██╗       ║
    ║    ██║  ██║███████╗███████║██║  ██║██║  ██║       ║
    ║    ╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝       ║
    ║                                                   ║
    ╚═══════════════════════════════════════════════════╝
BANNER
    echo -e "${NC}"
    echo -e "    ${WHITE}HesarTunnel Manager v${HESAR_VERSION}${NC}"
    echo -e "    ${CYAN}github.com/${GITHUB_USER}/${GITHUB_REPO}${NC}"
    echo ""

    if is_running; then
        local pid
        pid=$(systemctl show -p MainPID --value "${SERVICE_NAME}" 2>/dev/null || echo "?")
        echo -e "    Status: ${GREEN}● Running${NC} (PID: ${pid})"
    elif is_installed; then
        echo -e "    Status: ${YELLOW}○ Stopped${NC}"
    else
        echo -e "    Status: ${RED}✗ Not Installed${NC}"
    fi
    echo ""
}

# ─── Server Optimization ─────────────────────────────────

optimize_server() {
    separator
    echo -e "  ${PURPLE}${BOLD}Server Optimization${NC}"
    separator
    echo ""
    echo -e "  ${YELLOW}This will configure:${NC}"
    echo -e "    • BBR congestion control"
    echo -e "    • TCP buffer optimization"
    echo -e "    • Connection tracking limits"
    echo -e "    • File descriptor limits"
    echo ""

    read -rp "$(echo -e "${CYAN}  Proceed? [y/N]: ${NC}")" confirm
    [[ "$confirm" =~ ^[yY]$ ]] || return

    step "Applying kernel optimizations..."

    cat > /etc/sysctl.d/99-hesar-tunnel.conf << 'EOF'
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.core.rmem_default = 1048576
net.core.wmem_default = 1048576
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864
net.core.netdev_max_backlog = 250000
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_sack = 1
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.tcp_max_tw_buckets = 2000000
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_no_metrics_save = 1
fs.file-max = 1048576
fs.nr_open = 1048576
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.ip_forward = 1
net.core.optmem_max = 65535
EOF

    sysctl -p /etc/sysctl.d/99-hesar-tunnel.conf &>/dev/null || true
    sysctl -w net.netfilter.nf_conntrack_max=2097152 &>/dev/null || true

    cat > /etc/security/limits.d/99-hesar-tunnel.conf << 'EOF'
*       soft    nofile  1048576
*       hard    nofile  1048576
root    soft    nofile  1048576
root    hard    nofile  1048576
*       soft    nproc   65535
*       hard    nproc   65535
EOF

    ulimit -n 1048576 &>/dev/null || true

    info "Kernel parameters optimized"
    info "File descriptor limits increased"

    if sysctl net.ipv4.tcp_congestion_control 2>/dev/null | grep -q bbr; then
        info "BBR is active ✓"
    else
        warn "BBR may require a reboot"
    fi

    echo ""
    read -rp "$(echo -e "${CYAN}  Press Enter to continue...${NC}")"
}

# ─── Download Binary ──────────────────────────────────────

download_binary() {
    step "Downloading HesarTunnel for ${ARCH}..."

    local url="https://github.com/${GITHUB_USER}/${GITHUB_REPO}/releases/latest/download/${BINARY_NAME}-linux-${ARCH}"
    local tmp="/tmp/${BINARY_NAME}"

    if curl -fsSL -o "$tmp" "$url" 2>/dev/null; then
        chmod +x "$tmp"
        mv "$tmp" "${INSTALL_DIR}/${BINARY_NAME}"
        info "Binary installed from GitHub release"
        return 0
    fi

    warn "Release not found, building from source..."
    build_from_source
}

build_from_source() {
    step "Building from source..."

    if ! command -v go &>/dev/null; then
        step "Installing Go 1.22..."
        local go_ver="1.22.5"
        wget -q "https://go.dev/dl/go${go_ver}.linux-${ARCH}.tar.gz" -O /tmp/go.tar.gz
        rm -rf /usr/local/go
        tar -C /usr/local -xzf /tmp/go.tar.gz
        rm -f /tmp/go.tar.gz
        export PATH="$PATH:/usr/local/go/bin"
        info "Go ${go_ver} installed"
    fi

    local build_dir="/tmp/hesar-build-$$"
    rm -rf "$build_dir"

    if git clone --depth=1 "https://github.com/${GITHUB_USER}/${GITHUB_REPO}.git" "$build_dir" 2>/dev/null; then
        cd "$build_dir"
        export PATH="$PATH:/usr/local/go/bin"
        go mod tidy 2>/dev/null || true
        CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.Version=${HESAR_VERSION}" -o "${BINARY_NAME}" main.go
        mv "${BINARY_NAME}" "${INSTALL_DIR}/${BINARY_NAME}"
        chmod +x "${INSTALL_DIR}/${BINARY_NAME}"
        cd /
        rm -rf "$build_dir"
        info "Binary built and installed"
    else
        error "Failed to clone repository"
        rm -rf "$build_dir"
        return 1
    fi
}

# ─── Create systemd Service ──────────────────────────────

create_service() {
    local mode="$1"

    cat > "$SERVICE_FILE" << EOF
[Unit]
Description=HesarTunnel ${mode}
After=network.target network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
User=root
ExecStart=${INSTALL_DIR}/${BINARY_NAME} --mode ${mode} --config ${CONFIG_FILE}
Restart=always
RestartSec=3
LimitNOFILE=1048576
LimitNPROC=65535
StandardOutput=append:${LOG_FILE}
StandardError=append:${LOG_FILE}

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable "${SERVICE_NAME}" &>/dev/null
}

# ─── Write Config File ───────────────────────────────────

write_config() {
    local protocol="$1"
    local tunnel_port="$2"
    local remote_ip="$3"
    local config_ports="$4"
    local secret_key="$5"
    local mode="$6"    # "client" or "server"

    mkdir -p "$CONFIG_DIR"

    # تنظیم خودکار bind/forward بر اساس mode
    local server_bind="127.0.0.1"
    local client_forward="0.0.0.0"

    if [[ "$mode" == "server" ]]; then
        server_bind="127.0.0.1"     # Forward to Xray on localhost
        client_forward="0.0.0.0"    # Not used on server
    else
        server_bind="127.0.0.1"     # Not used on client
        client_forward="0.0.0.0"    # Listen for users from everywhere
    fi

    cat > "$CONFIG_FILE" << EOF
[tunnel]
protocol = "${protocol}"
tunnel_port = ${tunnel_port}
remote_ip = "${remote_ip}"
config_ports = "${config_ports}"
secret_key = "${secret_key}"
server_bind = "${server_bind}"
client_forward = "${client_forward}"

[crypto]
method = "chacha20-poly1305"
obfuscation = true
obfs_mode = "tls-hello"

[kcp]
preset = "fast2"
data_shard = 10
parity_shard = 3
snd_wnd = 1024
rcv_wnd = 1024
mtu = 1350
dscp = 46

[performance]
tunnel_count = 4
buffer_size = 32768
timeout = 30
keepalive = 10
no_delay = true
max_idle = 300
EOF

    chmod 600 "$CONFIG_FILE"
    info "Configuration saved to ${CONFIG_FILE}"
}

# ─── Input Helpers (>&2 for prompts) ──────────────────────

read_required() {
    local prompt="$1"
    local var
    while true; do
        echo -ne "${CYAN}  ${prompt}: ${NC}" >&2
        read -r var
        if [[ -n "$var" ]]; then
            echo "$var"
            return
        fi
        echo -e "${RED}[✗] This field is required${NC}" >&2
    done
}

read_default() {
    local prompt="$1"
    local default="$2"
    local var
    echo -ne "${CYAN}  ${prompt} [${default}]: ${NC}" >&2
    read -r var
    echo "${var:-$default}"
}

read_port() {
    local prompt="$1"
    local default="$2"
    local var
    while true; do
        echo -ne "${CYAN}  ${prompt} [${default}]: ${NC}" >&2
        read -r var
        var="${var:-$default}"
        if [[ "$var" =~ ^[0-9]+$ ]] && (( var >= 1 && var <= 65535 )); then
            echo "$var"
            return
        fi
        echo -e "${RED}[✗] Invalid port number (1-65535)${NC}" >&2
    done
}

read_protocol() {
    echo "" >&2
    echo -e "  ${YELLOW}Transport Protocol:${NC}" >&2
    echo -e "    1) ${WHITE}TCP${NC}  — Stable connections, lower overhead" >&2
    echo -e "    2) ${WHITE}KCP${NC}  — Better for lossy/unstable networks" >&2
    echo "" >&2
    local choice
    echo -ne "${CYAN}  Choose [1]: ${NC}" >&2
    read -r choice
    case "${choice:-1}" in
        2) echo "kcp" ;;
        *) echo "tcp" ;;
    esac
}

read_encryption() {
    echo "" >&2
    echo -e "  ${YELLOW}Encryption Method:${NC}" >&2
    echo -e "    1) ${WHITE}chacha20-poly1305${NC}  — Recommended (faster without AES-NI)" >&2
    echo -e "    2) ${WHITE}aes-256-gcm${NC}        — Faster with AES-NI CPUs" >&2
    echo "" >&2
    local choice
    echo -ne "${CYAN}  Choose [1]: ${NC}" >&2
    read -r choice
    case "${choice:-1}" in
        2) echo "aes-256-gcm" ;;
        *) echo "chacha20-poly1305" ;;
    esac
}

read_obfs_mode() {
    echo "" >&2
    echo -e "  ${YELLOW}Obfuscation Mode:${NC}" >&2
    echo -e "    1) ${WHITE}tls-hello${NC}        — TLS 1.3 records (recommended)" >&2
    echo -e "    2) ${WHITE}http${NC}             — HTTP response wrapper" >&2
    echo -e "    3) ${WHITE}random-padding${NC}   — Random padding" >&2
    echo -e "    4) ${WHITE}disabled${NC}         — No obfuscation" >&2
    echo "" >&2
    local choice
    echo -ne "${CYAN}  Choose [1]: ${NC}" >&2
    read -r choice
    case "${choice:-1}" in
        2) echo "http" ;;
        3) echo "random-padding" ;;
        4) echo "disabled" ;;
        *) echo "tls-hello" ;;
    esac
}

read_yes_no() {
    local prompt="$1"
    local default="$2"
    local var
    echo -ne "${CYAN}  ${prompt} [${default}]: ${NC}" >&2
    read -r var
    var="${var:-$default}"
    case "$var" in
        y|Y|yes|YES) echo "true" ;;
        *) echo "false" ;;
    esac
}

generate_key() {
    head -c 32 /dev/urandom | base64 | tr -d '/+=' | head -c 32
}

# ─── Setup Iran (Client) ─────────────────────────────────

setup_iran() {
    separator
    echo -e "  ${PURPLE}${BOLD}Setup Iran Server (Client)${NC}"
    separator
    echo ""

    if is_installed; then
        warn "Binary already installed"
        read -rp "$(echo -e "${CYAN}  Reinstall binary? [y/N]: ${NC}")" reinstall
        [[ "$reinstall" =~ ^[yY]$ ]] && download_binary
    else
        download_binary
    fi

    echo ""
    echo -e "  ${WHITE}${BOLD}Enter connection details:${NC}"
    echo ""

    local remote_ip tunnel_port config_ports protocol secret_key

    remote_ip=$(read_required "Foreign server IP")
    tunnel_port=$(read_port "Tunnel port" "4000")

    echo ""
    echo -e "  ${YELLOW}Port format: single=80 | multi=80,443 | range=80-100 | mixed=80,443,8000-8010${NC}"
    config_ports=$(read_required "Config ports")

    protocol=$(read_protocol)

    echo ""
    local default_key
    default_key=$(generate_key)
    secret_key=$(read_default "Secret key" "$default_key")

    # Write config
    write_config "$protocol" "$tunnel_port" "$remote_ip" "$config_ports" "$secret_key"

    # Create service
    create_service "client"

    # Start
    systemctl restart "${SERVICE_NAME}"

    echo ""
    separator
    echo -e "  ${GREEN}${BOLD}✓ Iran Server (Client) Setup Complete${NC}"
    separator
    echo ""
    echo -e "  ${WHITE}Summary:${NC}"
    echo -e "    Remote:     ${CYAN}${remote_ip}${NC}"
    echo -e "    Tunnel:     ${CYAN}${tunnel_port}${NC}"
    echo -e "    Ports:      ${CYAN}${config_ports}${NC}"
    echo -e "    Protocol:   ${CYAN}${protocol}${NC}"
    echo -e "    Secret Key: ${CYAN}${secret_key}${NC}"
    echo -e "    Encryption: ${CYAN}XChaCha20-Poly1305${NC}"
    echo -e "    Obfs:       ${CYAN}TLS 1.3 Records${NC}"
    echo ""
    echo -e "  ${YELLOW}${BOLD}⚠  Save the secret key! Use the same key on the foreign server.${NC}"
    echo ""

    sleep 2
    if is_running; then
        info "Service is running"
    else
        warn "Service failed to start. Check logs:"
        echo ""
        if [[ -f "$LOG_FILE" ]]; then
            tail -5 "$LOG_FILE" 2>/dev/null | while IFS= read -r line; do
                echo -e "    ${RED}${line}${NC}"
            done
        fi
    fi

    echo ""
    read -rp "$(echo -e "${CYAN}  Press Enter to continue...${NC}")"
}

# ─── Setup Foreign (Server) ──────────────────────────────

setup_foreign() {
    separator
    echo -e "  ${PURPLE}${BOLD}Setup Foreign Server${NC}"
    separator
    echo ""

    if is_installed; then
        warn "Binary already installed"
        read -rp "$(echo -e "${CYAN}  Reinstall binary? [y/N]: ${NC}")" reinstall
        [[ "$reinstall" =~ ^[yY]$ ]] && download_binary
    else
        download_binary
    fi

    echo ""
    echo -e "  ${WHITE}${BOLD}Enter configuration:${NC}"
    echo ""

    local tunnel_port config_ports protocol secret_key

    tunnel_port=$(read_port "Tunnel port" "4000")

    echo ""
    echo -e "  ${YELLOW}Port format: single=80 | multi=80,443 | range=80-100 | mixed=80,443,8000-8010${NC}"
    config_ports=$(read_required "Config ports")

    protocol=$(read_protocol)

    echo ""
    secret_key=$(read_required "Secret key (same as Iran server)")

    # Write config
    write_config "$protocol" "$tunnel_port" "0.0.0.0" "$config_ports" "$secret_key"

    # Create service
    create_service "server"

    # Start
    systemctl restart "${SERVICE_NAME}"

    echo ""
    separator
    echo -e "  ${GREEN}${BOLD}✓ Foreign Server Setup Complete${NC}"
    separator
    echo ""
    echo -e "  ${WHITE}Summary:${NC}"
    echo -e "    Tunnel:     ${CYAN}${tunnel_port}${NC}"
    echo -e "    Ports:      ${CYAN}${config_ports}${NC}"
    echo -e "    Protocol:   ${CYAN}${protocol}${NC}"
    echo -e "    Encryption: ${CYAN}XChaCha20-Poly1305${NC}"
    echo -e "    Obfs:       ${CYAN}TLS 1.3 Records${NC}"
    echo ""

    sleep 2
    if is_running; then
        info "Service is running"
    else
        warn "Service failed to start. Check logs:"
        if [[ -f "$LOG_FILE" ]]; then
            tail -5 "$LOG_FILE" 2>/dev/null | while IFS= read -r line; do
                echo -e "    ${RED}${line}${NC}"
            done
        fi
    fi

    echo ""
    read -rp "$(echo -e "${CYAN}  Press Enter to continue...${NC}")"
}

# ─── Status ───────────────────────────────────────────────

show_status() {
    separator
    echo -e "  ${PURPLE}${BOLD}Tunnel Status${NC}"
    separator
    echo ""

    echo -e "  ${WHITE}${BOLD}Service:${NC}"
    if is_running; then
        local pid mem cpu conns
        pid=$(systemctl show -p MainPID --value "${SERVICE_NAME}" 2>/dev/null || echo "?")
        mem=$(ps -p "$pid" -o rss= 2>/dev/null | awk '{printf "%.1f MB", $1/1024}' || echo "N/A")
        cpu=$(ps -p "$pid" -o %cpu= 2>/dev/null | awk '{print $1}' || echo "N/A")
        conns=$(ss -tnp 2>/dev/null | grep -c "pid=${pid}," || echo "0")

        echo -e "    State:       ${GREEN}● Active${NC}"
        echo -e "    PID:         ${CYAN}${pid}${NC}"
        echo -e "    Memory:      ${CYAN}${mem}${NC}"
        echo -e "    CPU:         ${CYAN}${cpu}%${NC}"
        echo -e "    Connections: ${CYAN}${conns}${NC}"
    elif is_installed; then
        echo -e "    State:       ${YELLOW}○ Stopped${NC}"
    else
        echo -e "    State:       ${RED}✗ Not Installed${NC}"
    fi

    echo ""

    if [[ -f "$CONFIG_FILE" ]]; then
        echo -e "  ${WHITE}${BOLD}Configuration:${NC}"
        local mode
        mode=$(get_service_mode)
        printf "    %-14s ${CYAN}%s${NC}\n" "mode:" "${mode:-N/A}"
        for key in protocol tunnel_port remote_ip config_ports; do
            local val
            val=$(get_config_value "$key")
            printf "    %-14s ${CYAN}%s${NC}\n" "${key}:" "${val:-N/A}"
        done
        local val
        val=$(get_config_value "method")
        printf "    %-14s ${CYAN}%s${NC}\n" "encryption:" "${val:-N/A}"
        val=$(get_config_value "obfs_mode")
        printf "    %-14s ${CYAN}%s${NC}\n" "obfuscation:" "${val:-N/A}"
    fi

    echo ""

    echo -e "  ${WHITE}${BOLD}Recent Logs (last 15 lines):${NC}"
    if [[ -f "$LOG_FILE" ]]; then
        tail -15 "$LOG_FILE" 2>/dev/null | while IFS= read -r line; do
            echo -e "    ${CYAN}${line}${NC}"
        done
    else
        echo -e "    ${YELLOW}No log file found${NC}"
    fi

    echo ""
    read -rp "$(echo -e "${CYAN}  Press Enter to continue...${NC}")"
}

# ═══════════════════════════════════════════════════════════
# ─── Edit Configuration ──────────────────────────────────
# ═══════════════════════════════════════════════════════════

edit_config() {
    if [[ ! -f "$CONFIG_FILE" ]]; then
        error "No configuration found at ${CONFIG_FILE}"
        echo -e "  ${YELLOW}Please run Setup first (option 2 or 3)${NC}"
        echo ""
        read -rp "$(echo -e "${CYAN}  Press Enter to continue...${NC}")"
        return
    fi

    # Read current values
    local cur_protocol cur_tunnel_port cur_remote_ip cur_config_ports cur_secret_key
    local cur_method cur_obfuscation cur_obfs_mode
    local cur_tunnel_count cur_buffer_size cur_timeout cur_keepalive cur_no_delay cur_max_idle

    cur_protocol=$(get_config_value "protocol")
    cur_tunnel_port=$(get_config_value "tunnel_port")
    cur_remote_ip=$(get_config_value "remote_ip")
    cur_config_ports=$(get_config_value "config_ports")
    cur_secret_key=$(get_config_value "secret_key")
    cur_method=$(get_config_value "method")
    cur_obfuscation=$(get_config_value "obfuscation")
    cur_obfs_mode=$(get_config_value "obfs_mode")
    cur_tunnel_count=$(get_config_value "tunnel_count")
    cur_buffer_size=$(get_config_value "buffer_size")
    cur_timeout=$(get_config_value "timeout")
    cur_keepalive=$(get_config_value "keepalive")
    cur_no_delay=$(get_config_value "no_delay")
    cur_max_idle=$(get_config_value "max_idle")

    # Set defaults for missing values
    cur_tunnel_count="${cur_tunnel_count:-4}"
    cur_buffer_size="${cur_buffer_size:-32768}"
    cur_timeout="${cur_timeout:-30}"
    cur_keepalive="${cur_keepalive:-10}"
    cur_no_delay="${cur_no_delay:-true}"
    cur_max_idle="${cur_max_idle:-300}"
    cur_obfuscation="${cur_obfuscation:-true}"

    while true; do
        separator
        echo -e "  ${PURPLE}${BOLD}Edit Configuration${NC}"
        separator
        echo ""
        echo -e "  ${WHITE}${BOLD}Current Settings:${NC}"
        echo ""
        echo -e "  ${WHITE}── Tunnel ──────────────────────────────────${NC}"
        echo -e "    1) Protocol:       ${CYAN}${cur_protocol}${NC}"
        echo -e "    2) Tunnel Port:    ${CYAN}${cur_tunnel_port}${NC}"
        echo -e "    3) Remote IP:      ${CYAN}${cur_remote_ip}${NC}"
        echo -e "    4) Config Ports:   ${CYAN}${cur_config_ports}${NC}"
        echo -e "    5) Secret Key:     ${CYAN}${cur_secret_key:0:8}...${NC}"
        echo ""
        echo -e "  ${WHITE}── Encryption ──────────────────────────────${NC}"
        echo -e "    6) Method:         ${CYAN}${cur_method}${NC}"
        echo -e "    7) Obfuscation:    ${CYAN}${cur_obfuscation}${NC}"
        echo -e "    8) Obfs Mode:      ${CYAN}${cur_obfs_mode}${NC}"
        echo ""
        echo -e "  ${WHITE}── Performance ─────────────────────────────${NC}"
        echo -e "    9) Tunnel Count:   ${CYAN}${cur_tunnel_count}${NC}"
        echo -e "   10) Buffer Size:    ${CYAN}${cur_buffer_size}${NC}"
        echo -e "   11) Timeout:        ${CYAN}${cur_timeout}s${NC}"
        echo -e "   12) Keepalive:      ${CYAN}${cur_keepalive}s${NC}"
        echo -e "   13) TCP NoDelay:    ${CYAN}${cur_no_delay}${NC}"
        echo -e "   14) Max Idle:       ${CYAN}${cur_max_idle}s${NC}"
        echo ""
        echo -e "  ${WHITE}── Actions ─────────────────────────────────${NC}"
        echo -e "   ${GREEN}s)${NC}  Save & Apply changes"
        echo -e "   ${RED}d)${NC}  Discard changes"
        echo -e "   ${WHITE}0)${NC}  Back (without saving)"
        echo ""

        read -rp "$(echo -e "${CYAN}  Edit option: ${NC}")" edit_choice

        case "$edit_choice" in
            1)
                local new_val
                new_val=$(read_protocol)
                cur_protocol="$new_val"
                info "Protocol changed to: ${cur_protocol}"
                ;;
            2)
                local new_val
                new_val=$(read_port "New tunnel port" "$cur_tunnel_port")
                cur_tunnel_port="$new_val"
                info "Tunnel port changed to: ${cur_tunnel_port}"
                ;;
            3)
                local new_val
                new_val=$(read_default "New remote IP" "$cur_remote_ip")
                cur_remote_ip="$new_val"
                info "Remote IP changed to: ${cur_remote_ip}"
                ;;
            4)
                echo -e "  ${YELLOW}Port format: single=80 | multi=80,443 | range=80-100${NC}"
                local new_val
                new_val=$(read_default "New config ports" "$cur_config_ports")
                cur_config_ports="$new_val"
                info "Config ports changed to: ${cur_config_ports}"
                ;;
            5)
                echo -e "  ${YELLOW}Current key: ${cur_secret_key}${NC}"
                local new_val
                new_val=$(read_default "New secret key" "$cur_secret_key")
                cur_secret_key="$new_val"
                info "Secret key updated"
                ;;
            6)
                local new_val
                new_val=$(read_encryption)
                cur_method="$new_val"
                info "Encryption changed to: ${cur_method}"
                ;;
            7)
                if [[ "$cur_obfuscation" == "true" ]]; then
                    cur_obfuscation="false"
                    info "Obfuscation DISABLED"
                else
                    cur_obfuscation="true"
                    info "Obfuscation ENABLED"
                fi
                ;;
            8)
                local new_val
                new_val=$(read_obfs_mode)
                if [[ "$new_val" == "disabled" ]]; then
                    cur_obfuscation="false"
                    cur_obfs_mode="tls-hello"
                    info "Obfuscation disabled"
                else
                    cur_obfuscation="true"
                    cur_obfs_mode="$new_val"
                    info "Obfs mode changed to: ${cur_obfs_mode}"
                fi
                ;;
            9)
                local new_val
                new_val=$(read_default "Tunnel count (1-32)" "$cur_tunnel_count")
                if [[ "$new_val" =~ ^[0-9]+$ ]] && (( new_val >= 1 && new_val <= 32 )); then
                    cur_tunnel_count="$new_val"
                    info "Tunnel count changed to: ${cur_tunnel_count}"
                else
                    error "Invalid value (1-32)"
                fi
                ;;
            10)
                local new_val
                new_val=$(read_default "Buffer size in bytes" "$cur_buffer_size")
                if [[ "$new_val" =~ ^[0-9]+$ ]] && (( new_val >= 4096 && new_val <= 1048576 )); then
                    cur_buffer_size="$new_val"
                    info "Buffer size changed to: ${cur_buffer_size}"
                else
                    error "Invalid value (4096-1048576)"
                fi
                ;;
            11)
                local new_val
                new_val=$(read_default "Timeout in seconds" "$cur_timeout")
                if [[ "$new_val" =~ ^[0-9]+$ ]] && (( new_val >= 5 && new_val <= 300 )); then
                    cur_timeout="$new_val"
                    info "Timeout changed to: ${cur_timeout}s"
                else
                    error "Invalid value (5-300)"
                fi
                ;;
            12)
                local new_val
                new_val=$(read_default "Keepalive in seconds" "$cur_keepalive")
                if [[ "$new_val" =~ ^[0-9]+$ ]] && (( new_val >= 3 && new_val <= 120 )); then
                    cur_keepalive="$new_val"
                    info "Keepalive changed to: ${cur_keepalive}s"
                else
                    error "Invalid value (3-120)"
                fi
                ;;
            13)
                if [[ "$cur_no_delay" == "true" ]]; then
                    cur_no_delay="false"
                    info "TCP NoDelay DISABLED"
                else
                    cur_no_delay="true"
                    info "TCP NoDelay ENABLED"
                fi
                ;;
            14)
                local new_val
                new_val=$(read_default "Max idle in seconds" "$cur_max_idle")
                if [[ "$new_val" =~ ^[0-9]+$ ]] && (( new_val >= 30 && new_val <= 3600 )); then
                    cur_max_idle="$new_val"
                    info "Max idle changed to: ${cur_max_idle}s"
                else
                    error "Invalid value (30-3600)"
                fi
                ;;

            s|S)
                # ─── Save configuration ───
                echo ""
                step "Saving configuration..."

                mkdir -p "$CONFIG_DIR"
                cat > "$CONFIG_FILE" << EOF
[tunnel]
protocol = "${cur_protocol}"
tunnel_port = ${cur_tunnel_port}
remote_ip = "${cur_remote_ip}"
config_ports = "${cur_config_ports}"
secret_key = "${cur_secret_key}"

[crypto]
method = "${cur_method}"
obfuscation = ${cur_obfuscation}
obfs_mode = "${cur_obfs_mode}"

[kcp]
preset = "fast2"
data_shard = 10
parity_shard = 3
snd_wnd = 1024
rcv_wnd = 1024
mtu = 1350
dscp = 46

[performance]
tunnel_count = ${cur_tunnel_count}
buffer_size = ${cur_buffer_size}
timeout = ${cur_timeout}
keepalive = ${cur_keepalive}
no_delay = ${cur_no_delay}
max_idle = ${cur_max_idle}
EOF

                chmod 600 "$CONFIG_FILE"
                info "Configuration saved"

                # Ask to restart
                echo ""
                read -rp "$(echo -e "${CYAN}  Restart service to apply changes? [Y/n]: ${NC}")" do_restart
                if [[ ! "$do_restart" =~ ^[nN]$ ]]; then
                    systemctl restart "${SERVICE_NAME}" 2>/dev/null
                    sleep 2
                    if is_running; then
                        info "Service restarted successfully"
                    else
                        warn "Service failed to start. Check logs with option 4 in Manage menu"
                    fi
                else
                    warn "Changes saved but service NOT restarted"
                    warn "Restart manually to apply changes"
                fi

                echo ""
                read -rp "$(echo -e "${CYAN}  Press Enter to continue...${NC}")"
                return
                ;;

            d|D)
                warn "Changes discarded"
                echo ""
                read -rp "$(echo -e "${CYAN}  Press Enter to continue...${NC}")"
                return
                ;;

            0|"")
                return
                ;;

            *)
                error "Invalid option"
                sleep 1
                ;;
        esac
    done
}

# ═══════════════════════════════════════════════════════════
# ─── Service Management (با Edit Config) ──────────────────
# ═══════════════════════════════════════════════════════════

manage_service() {
    separator
    echo -e "  ${PURPLE}${BOLD}Service Management${NC}"
    separator
    echo ""

    # Show current status
    if is_running; then
        local pid
        pid=$(systemctl show -p MainPID --value "${SERVICE_NAME}" 2>/dev/null || echo "?")
        echo -e "  Current: ${GREEN}● Running${NC} (PID: ${pid})"
    elif is_installed; then
        echo -e "  Current: ${YELLOW}○ Stopped${NC}"
    else
        echo -e "  Current: ${RED}✗ Not Installed${NC}"
    fi
    echo ""

    echo -e "    1) ${GREEN}Start${NC}          Start tunnel service"
    echo -e "    2) ${YELLOW}Stop${NC}           Stop tunnel service"
    echo -e "    3) ${BLUE}Restart${NC}        Restart tunnel service"
    echo -e "    4) ${CYAN}View Logs${NC}      Live log viewer"
    echo -e "    5) ${PURPLE}Edit Config${NC}    Modify tunnel configuration"
    echo -e "    6) ${WHITE}View Config${NC}    Show current config file"
    echo -e "    0) ${WHITE}Back${NC}"
    echo ""

    read -rp "$(echo -e "${CYAN}  Choose: ${NC}")" choice

    case "$choice" in
        1)
            if ! is_installed; then
                error "HesarTunnel is not installed. Run Setup first."
            elif is_running; then
                warn "Service is already running"
            else
                systemctl start "${SERVICE_NAME}" 2>/dev/null && info "Service started" || error "Start failed"
            fi
            ;;
        2)
            if is_running; then
                systemctl stop "${SERVICE_NAME}" 2>/dev/null && info "Service stopped" || error "Stop failed"
            else
                warn "Service is not running"
            fi
            ;;
        3)
            systemctl restart "${SERVICE_NAME}" 2>/dev/null
            sleep 2
            if is_running; then
                info "Service restarted successfully"
            else
                error "Restart failed. Check logs (option 4)"
            fi
            ;;
        4)
            echo ""
            echo -e "  ${YELLOW}Press Ctrl+C to exit log viewer${NC}"
            echo ""
            if [[ -f "$LOG_FILE" ]]; then
                # Show last 20 lines first, then follow
                echo -e "  ${WHITE}── Last 20 lines ──${NC}"
                tail -20 "$LOG_FILE" 2>/dev/null | while IFS= read -r line; do
                    echo -e "  ${CYAN}${line}${NC}"
                done
                echo -e "  ${WHITE}── Live feed ──${NC}"
                tail -f "$LOG_FILE" 2>/dev/null || true
            else
                journalctl -u "${SERVICE_NAME}" -f --no-pager 2>/dev/null || true
            fi
            ;;
        5)
            edit_config
            return
            ;;
        6)
            echo ""
            if [[ -f "$CONFIG_FILE" ]]; then
                echo -e "  ${WHITE}${BOLD}File: ${CONFIG_FILE}${NC}"
                separator
                while IFS= read -r line; do
                    if [[ "$line" =~ ^# ]] || [[ "$line" =~ ^\[  ]]; then
                        echo -e "  ${YELLOW}${line}${NC}"
                    elif [[ "$line" =~ = ]]; then
                        local key val
                        key=$(echo "$line" | cut -d'=' -f1 | tr -d ' ')
                        val=$(echo "$line" | cut -d'=' -f2-)
                        # Hide full secret key
                        if [[ "$key" == "secret_key" ]]; then
                            local raw_val
                            raw_val=$(echo "$val" | tr -d ' "')
                            echo -e "  ${WHITE}${key}${NC} = ${CYAN}${raw_val:0:8}...${NC}"
                        else
                            echo -e "  ${WHITE}${key}${NC} =${CYAN}${val}${NC}"
                        fi
                    else
                        echo -e "  ${line}"
                    fi
                done < "$CONFIG_FILE"
                separator
            else
                error "No configuration file found"
            fi
            ;;
        0|"") return ;;
        *)
            error "Invalid option"
            ;;
    esac

    echo ""
    read -rp "$(echo -e "${CYAN}  Press Enter to continue...${NC}")"
}

# ─── Uninstall ────────────────────────────────────────────

uninstall_menu() {
    separator
    echo -e "  ${PURPLE}${BOLD}Uninstall${NC}"
    separator
    echo ""
    echo -e "    1) ${YELLOW}Remove tunnel service only${NC}"
    echo -e "    2) ${YELLOW}Remove binary only${NC}"
    echo -e "    3) ${RED}Complete uninstall${NC}"
    echo -e "    0) ${WHITE}Back${NC}"
    echo ""

    read -rp "$(echo -e "${CYAN}  Choose: ${NC}")" choice

    case "$choice" in
        1)
            read -rp "$(echo -e "${RED}  Remove service? [y/N]: ${NC}")" confirm
            if [[ "$confirm" =~ ^[yY]$ ]]; then
                systemctl stop "${SERVICE_NAME}" 2>/dev/null || true
                systemctl disable "${SERVICE_NAME}" 2>/dev/null || true
                rm -f "$SERVICE_FILE"
                systemctl daemon-reload
                info "Service removed (binary & config kept)"
            fi
            ;;
        2)
            read -rp "$(echo -e "${RED}  Remove binary? [y/N]: ${NC}")" confirm
            if [[ "$confirm" =~ ^[yY]$ ]]; then
                rm -f "${INSTALL_DIR}/${BINARY_NAME}"
                info "Binary removed"
            fi
            ;;
        3)
            echo ""
            echo -e "  ${RED}${BOLD}This removes: service, binary, config, logs, optimizations${NC}"
            read -rp "$(echo -e "${RED}  Type 'YES' to confirm: ${NC}")" confirm
            if [[ "$confirm" == "YES" ]]; then
                systemctl stop "${SERVICE_NAME}" 2>/dev/null || true
                systemctl disable "${SERVICE_NAME}" 2>/dev/null || true
                rm -f "$SERVICE_FILE"
                systemctl daemon-reload
                rm -f "${INSTALL_DIR}/${BINARY_NAME}"
                rm -rf "$CONFIG_DIR"
                rm -f "$LOG_FILE"

                read -rp "$(echo -e "${CYAN}  Remove server optimizations? [y/N]: ${NC}")" rm_opt
                if [[ "$rm_opt" =~ ^[yY]$ ]]; then
                    rm -f /etc/sysctl.d/99-hesar-tunnel.conf
                    rm -f /etc/security/limits.d/99-hesar-tunnel.conf
                    sysctl --system &>/dev/null || true
                    info "Optimizations removed"
                fi

                info "HesarTunnel completely uninstalled"
            else
                warn "Cancelled"
            fi
            ;;
        0|"") return ;;
    esac

    echo ""
    read -rp "$(echo -e "${CYAN}  Press Enter to continue...${NC}")"
}

# ─── Main Menu ────────────────────────────────────────────

main_menu() {
    while true; do
        print_banner
        separator
        echo ""
        echo -e "    ${WHITE}1)${NC} ${GREEN}Optimize Server${NC}        BBR + Performance Tuning"
        echo -e "    ${WHITE}2)${NC} ${CYAN}Setup Iran Server${NC}      Client (connects to foreign)"
        echo -e "    ${WHITE}3)${NC} ${CYAN}Setup Foreign Server${NC}   Server (accepts connections)"
        echo -e "    ${WHITE}4)${NC} ${BLUE}Tunnel Status${NC}          View status & connections"
        echo -e "    ${WHITE}5)${NC} ${PURPLE}Manage Service${NC}         Start / Stop / Restart / Edit / Logs"
        echo -e "    ${WHITE}6)${NC} ${RED}Uninstall${NC}              Remove tunnel / binary / all"
        echo -e "    ${WHITE}0)${NC} ${WHITE}Exit${NC}"
        echo ""
        separator
        echo ""

        read -rp "$(echo -e "${CYAN}  Choose option: ${NC}")" choice

        case "$choice" in
            1) optimize_server ;;
            2) setup_iran ;;
            3) setup_foreign ;;
            4) show_status ;;
            5) manage_service ;;
            6) uninstall_menu ;;
            0)
                echo ""
                info "Goodbye!"
                exit 0
                ;;
            *)
                error "Invalid option"
                sleep 1
                ;;
        esac
    done
}

# ─── Entry Point ──────────────────────────────────────────

check_root
detect_os
detect_arch
install_deps
main_menu

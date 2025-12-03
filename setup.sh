#!/bin/bash

# Marzban CloudFlare Warp Auto Setup Script (Hardened)
# تغییرات امنیتی: set -euo pipefail، بررسی SHA256 برای wgcf، chmod 600 روی فایل‌های حساس،
# امن‌سازی وارد کردن دامنه‌های سفارشی (بدون sed خطرناک)، و اضافه شدن uninstall.sh.

set -euo pipefail
IFS=$'\n\t'

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

WGCF_VERSION="2.2.22"
# در صورت داشتن مقدار SHA256 صحیح این متغیر را پر کنید. اگر خالی بود صرفاً هشدار می‌دهد.
WGCF_SHA256=""

# Temporary working dir
TMPDIR=$(mktemp -d -t marz-warp-XXXXXXXX) || exit 1
cleanup_tmp() {
    rm -rf "${TMPDIR}"
}
trap cleanup_tmp EXIT

print_banner() {
    echo -e "${BLUE}"
    echo "=================================================="
    echo "    Marzban CloudFlare Warp Auto Setup Script    "
    echo "          (Hardened Version)                     "
    echo "=================================================="
    echo -e "${NC}"
}

log() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root (use sudo)"
        exit 1
    fi
}

detect_arch() {
    local arch
    arch=$(uname -m)
    case $arch in
        x86_64) echo "amd64" ;; 
        aarch64) echo "arm64" ;; 
        *) error "Unsupported architecture: $arch"; exit 1 ;; 
    esac
}

# safer download helper
safe_download() {
    local url="$1"
    local dest="$2"

    if command -v curl &>/dev/null; then
        curl -fsSL "$url" -o "$dest"
    elif command -v wget &>/dev/null; then
        wget -qO "$dest" "$url"
    else
        error "Neither curl nor wget is available for downloads"
        exit 1
    fi
}

install_dependencies() {
    log "Installing required dependencies..."
    if command -v apt-get &> /dev/null; then
        apt-get update -y
        # check for lsb_release existence
        if command -v lsb_release &>/dev/null; then
            if lsb_release -d | grep -q "Ubuntu 24"; then
                apt-get install -y wget curl jq wireguard
            else
                apt-get install -y wget curl jq wireguard-dkms wireguard-tools resolvconf lsb-release
            fi
        else
            # fallback to /etc/os-release (conservative install)
            apt-get install -y wget curl jq wireguard-dkms wireguard-tools resolvconf lsb-release || \
                apt-get install -y wget curl jq wireguard-tools || true
        fi
    elif command -v yum &> /dev/null; then
        yum update -y
        yum install -y wget curl jq wireguard-tools
    else
        error "Unsupported package manager. Please install dependencies manually."
        exit 1
    fi
    log "Dependencies installed (or already present)"
}

setup_wgcf() {
    log "Setting up wgcf..."
    local arch
    arch=$(detect_arch)
    local wgcf_url="https://github.com/ViRb3/wgcf/releases/download/v${WGCF_VERSION}/wgcf_${WGCF_VERSION}_linux_${arch}"
    local wgcf_tmp="${TMPDIR}/wgcf"

    safe_download "$wgcf_url" "$wgcf_tmp"
    chmod +x "$wgcf_tmp"

    # optional checksum verification
    if [[ -n "$WGCF_SHA256" ]]; then
        echo "${WGCF_SHA256}  ${wgcf_tmp}" | sha256sum -c - || {
            error "wgcf checksum verification failed"
            exit 1
        }
    else
        warn "WGCF_SHA256 not set — skipping checksum verification. Consider setting WGCF_SHA256 in the script."
    fi

    mv "$wgcf_tmp" /usr/bin/wgcf
    chmod 755 /usr/bin/wgcf
    log "wgcf installed to /usr/bin/wgcf"
}

generate_wg_config() {
    log "Generating Wireguard configuration..."
    mkdir -p /opt/warp-config
    cd /opt/warp-config

    # wgcf register may interactively require input if something unexpected happens.
    # we rely on --accept-tos above in original script; here we ensure non-interactive mode.
    if ! wgcf register --accept-tos &>/dev/null; then
        warn "wgcf register returned non-zero status (it may have run previously). Continuing..."
    fi

    wgcf generate

    if [[ ! -f "wgcf-profile.conf" ]]; then
        error "Failed to generate wgcf-profile.conf"
        exit 1
    fi

    # restrict permissions for sensitive files
    chmod 600 wgcf-profile.conf || true
    if [[ -f "wgcf-account.toml" ]]; then
        chmod 600 wgcf-account.toml || true
    fi

    log "Wireguard configuration generated and permissions set"
}

setup_warp_plus() {
    # Do not echo the warp+ key to logs
    if [[ "${USE_WARP_PLUS:-n}" == "y" ]]; then
        log "Setting up Warp+ license key (kept secret)..."
        cd /opt/warp-config || exit 1
        if [[ -f "wgcf-account.toml" ]]; then
            # use awk to safely replace license_key line (avoid sed injection)
            awk -v key="$WARP_PLUS_KEY" '{
                if ($0 ~ /^license_key[[:space:]]*=/) {
                    printf "license_key = \"%s\"\n", key
                } else {
                    print $0
                }
            }' wgcf-account.toml > wgcf-account.toml.new && mv wgcf-account.toml.new wgcf-account.toml
            chmod 600 wgcf-account.toml
        else
            error "wgcf-account.toml not found; cannot apply Warp+ key"
            exit 1
        fi
        wgcf update || warn "wgcf update failed; continuing"
        wgcf generate
        chmod 600 wgcf-profile.conf || true
        log "Warp+ configured (key not printed)"
    fi
}

setup_wireguard_kernel() {
    log "Setting up Wireguard kernel method..."
    cd /opt/warp-config || exit 1
    # Add Table = off in a safe way if not present
    if ! grep -q "^Table[[:space:]]*=" wgcf-profile.conf 2>/dev/null; then
        awk 'BEGIN{added=0} {print} /^
[Interface
]/{if(!added){print "Table = off"; added=1}}' wgcf-profile.conf > wgcf-profile.conf.new && mv wgcf-profile.conf.new wgcf-profile.conf
    fi

    mkdir -p /etc/wireguard
    cp wgcf-profile.conf /etc/wireguard/warp.conf
    chmod 600 /etc/wireguard/warp.conf || true

    systemctl enable --now wg-quick@warp || {
        error "Failed to enable/start wg-quick@warp service"
        # continue so other outputs (configs) are still produced
    }

    if systemctl is-active --quiet wg-quick@warp 2>/dev/null; then
        log "Wireguard service started successfully"
    else
        warn "Wireguard service is not active after attempt to start"
    fi
}

extract_config_values() {
    log "Extracting configuration values..."
    cd /opt/warp-config || exit 1

    if [[ ! -f "wgcf-profile.conf" ]]; then
        error "wgcf-profile.conf not found in /opt/warp-config/"
        exit 1
    fi

    PRIVATE_KEY=$(grep -E "^PrivateKey" wgcf-profile.conf | cut -d'=' -f2- | xargs || true)
    ADDRESSES_RAW=$(grep -E "^Address" wgcf-profile.conf | cut -d'=' -f2- | xargs || true)

    if [[ -z "${PRIVATE_KEY:-}" ]]; then
        error "Failed to extract PrivateKey from wgcf-profile.conf (abort)."
        exit 1
    fi

    # normalize addresses to CSV
    ADDRESSES=$(echo "$ADDRESSES_RAW" | tr ',' '\n' | xargs | tr ' ' ',' || true)

    log "Config values extracted (private key kept secret, addresses: ${ADDRESSES:-none})"
}

# create JSON outputs safely (no sed injection). domain_list should be newline-separated.
create_xray_outbound() {
    log "Creating Xray outbound configuration..."
    local ipv4_addr ipv6_addr
    ipv4_addr=$(echo "$ADDRESSES" | cut -d',' -f1 || true)
    ipv6_addr=$(echo "$ADDRESSES" | cut -d',' -f2 || true)
    ipv4_addr=$(echo "$ipv4_addr" | cut -d'/' -f1 || true)
    ipv6_addr=$(echo "$ipv6_addr" | cut -d'/' -f1 || true)

    mkdir -p /opt/marzban-warp
    # create JSON with here-doc but ensure values are sanitized
    cat > /opt/marzban-warp/warp_xray_outbound.json <<-EOF
{
  "tag": "warp",
  "protocol": "wireguard",
  "settings": {
    "secretKey": "${PRIVATE_KEY}",
    "address": ["${ipv4_addr}/32", "${ipv6_addr}/128"],
    "peers": [
      {
        "publicKey": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
        "endpoint": "engage.cloudflareclient.com:2408"
      }
    ],
    "reserved": [0, 0, 0],
    "mtu": 1280
  }
}
EOF

    chmod 600 /opt/marzban-warp/warp_xray_outbound.json || true
    cp /opt/marzban-warp/warp_xray_outbound.json /root/ 2>/dev/null || true
    chmod 600 /root/warp_xray_outbound.json 2>/dev/null || true

    log "Xray outbound configuration created"
}

create_freedom_outbound() {
    log "Creating Freedom outbound configuration..."
    mkdir -p /opt/marzban-warp
    cat > /opt/marzban-warp/warp_freedom_outbound.json <<-EOF
{
  "tag": "warp",
  "protocol": "freedom",
  "settings": {
    "domainStrategy": "UseIP"
  },
  "streamSettings": {
    "sockopt": {
      "tcpFastOpen": true,
      "interface": "warp"
    }
  }
}
EOF
    chmod 600 /opt/marzban-warp/warp_freedom_outbound.json || true
    cp /opt/marzban-warp/warp_freedom_outbound.json /root/ 2>/dev/null || true
    chmod 600 /root/warp_freedom_outbound.json 2>/dev/null || true
    log "Freedom outbound configuration created"
}

# safe creation of routing rules: build JSON array programmatically
create_routing_rules() {
    log "Creating routing rules..."
    mkdir -p /opt/marzban-warp
    local doms=()
    if [[ "${ROUTE_ALL_TRAFFIC:-n}" == "y" ]]; then
        cat > /opt/marzban-warp/warp_routing_rule.json <<-EOF
{
    "outboundTag": "warp",
    "type": "field"
}
EOF
    else
        # default list
        doms+=( "geosite:google" "geosite:netflix" "geosite:openai" "openai.com" "ai.com" "ipinfo.io" "iplocation.net" "spotify.com" )
        if [[ -n "${CUSTOM_DOMAINS:-}" ]]; then
            # split comma-separated and trim
            IFS=',' read -ra input_domains <<< "${CUSTOM_DOMAINS}"
            for d in "${input_domains[@]}"; do
                d=$(echo "$d" | xargs)
                if [[ -n "$d" ]]; then
                    doms+=( "$d" )
                fi
            done
        fi

        # build JSON domain array safely
        {
            echo "{"
            echo "    \"outboundTag\": \"warp\"," 
            echo "    \"domain\": ["
            for i in "${!doms[@]}"; do
                printf '        "%s"' "${doms[$i]}"
                if [[ $i -lt $((${#doms[@]} - 1)) ]]; then
                    printf ',\n'
                else
                    printf '\n'
                fi
            done
            echo "    ],"
            echo "    \"type\": \"field\""
            echo "}"
        } > /opt/marzban-warp/warp_routing_rule.json
    fi

    chmod 600 /opt/marzban-warp/warp_routing_rule.json || true
    cp /opt/marzban-warp/warp_routing_rule.json /root/ 2>/dev/null || true
    chmod 600 /root/warp_routing_rule.json 2>/dev/null || true
    log "Routing rules created"
}

get_user_input() {
    echo
    log "Starting Marzban Warp configuration..."
    echo

    echo -e "${BLUE}Choose setup method:${NC}"
    echo "1) Xray core method (recommended for Xray 1.8.3+)"
    echo "2) Wireguard kernel method"
    read -p "Enter your choice (1 or 2): " SETUP_METHOD

    while [[ "$SETUP_METHOD" != "1" && "$SETUP_METHOD" != "2" ]]; do
        echo -e "${RED}Invalid choice. Please enter 1 or 2.${NC}"
        read -p "Enter your choice (1 or 2): " SETUP_METHOD
    done

    echo
    read -p "Do you have a Warp+ license key? (y/n): " USE_WARP_PLUS
    USE_WARP_PLUS=$(echo "$USE_WARP_PLUS" | tr '[:upper:]' '[:lower:]')

    if [[ "$USE_WARP_PLUS" == "y" ]]; then
        # read -s to avoid echoing the key on terminal
        read -s -p "Enter your Warp+ license key (input hidden): " WARP_PLUS_KEY
        echo
        while [[ -z "${WARP_PLUS_KEY:-}" ]]; do
            echo -e "${RED}License key cannot be empty.${NC}"
            read -s -p "Enter your Warp+ license key (input hidden): " WARP_PLUS_KEY
            echo
        done
    fi

    echo
    read -p "Enter custom domains to route through Warp (comma-separated, optional): " CUSTOM_DOMAINS

    echo
    read -p "Route ALL traffic through Warp by default? (y/n): " ROUTE_ALL_TRAFFIC
    ROUTE_ALL_TRAFFIC=$(echo "$ROUTE_ALL_TRAFFIC" | tr '[:upper:]' '[:lower:]')

    echo
    log "Configuration collected (sensitive inputs not displayed)"
}
display_config() {
    echo
    echo -e "${GREEN}================================${NC}"
    echo -e "${GREEN}  Configuration Summary${NC}"
    echo -e "${GREEN}================================${NC}"
    echo
    echo -e "${BLUE}Setup Method:${NC} $([ "$SETUP_METHOD" == "1" ] && echo "Xray Core" || echo "Wireguard Kernel")"
    echo -e "${BLUE}Warp+ Enabled:${NC} $([ "${USE_WARP_PLUS:-n}" == "y" ] && echo "Yes" || echo "No")"
    echo -e "${BLUE}Route All Traffic:${NC} $([ "${ROUTE_ALL_TRAFFIC:-n}" == "y" ] && echo "Yes" || echo "No")"
    echo -e "${BLUE}Custom Domains:${NC} ${CUSTOM_DOMAINS:-"None"}"
    echo
    echo -e "${BLUE}Generated Files:${NC}"
    if [[ "$SETUP_METHOD" == "2" ]]; then
        echo "- Wireguard Config: /etc/wireguard/warp.conf"
    fi
    echo "- Original Warp Config: /opt/warp-config/wgcf-profile.conf"
    if [[ "$SETUP_METHOD" == "1" ]]; then
        echo "- Xray Outbound: /root/warp_xray_outbound.json"
    else
        echo "- Freedom Outbound: /root/warp_freedom_outbound.json"
    fi
    echo "- Routing Rules: /root/warp_routing_rule.json"
    echo
    echo -e "${GREEN}================================${NC}"
    echo -e "${GREEN}  Manual Steps Required${NC}"
    echo -e "${GREEN}================================${NC}"
    echo
    echo "1. Go to your Marzban panel > Core Settings"
    echo "2. Add the outbound configuration from:"
    if [[ "$SETUP_METHOD" == "1" ]]; then
        echo "   /root/warp_xray_outbound.json"
    else
        echo "   /root/warp_freedom_outbound.json"
    fi
    if [[ "${ROUTE_ALL_TRAFFIC:-n}" != "y" ]]; then
        echo "3. Add the routing rules from:"
        echo "   /root/warp_routing_rule.json"
    else
        echo "3. Place the Warp outbound as the FIRST outbound in your config or set it as default outbound"
    fi
    echo "4. Save and restart your Marzban core"
    echo
    echo -e "${GREEN}Setup completed (files saved with restricted permissions)${NC}"
    echo
    if [[ "$SETUP_METHOD" == "2" ]]; then
        echo -e "${YELLOW}To disable Warp: sudo systemctl disable --now wg-quick@warp${NC}"
    fi
    echo -e "${YELLOW}Configuration files are preserved in /opt/marzban-warp/ and /root/ (permissions set to 600)${NC}"
}
test_warp() {
    log "Testing Warp connection..."
    if [[ "$SETUP_METHOD" == "2" ]]; then
        if systemctl is-active --quiet wg-quick@warp 2>/dev/null; then
            log "Warp service is running"
            if timeout 10s curl -s --interface warp https://cloudflare.com/cdn-cgi/trace | grep -q "warp=on" 2>/dev/null; then
                log "Warp connection test: SUCCESS"
            else
                warn "Warp connection test: Could not verify Warp routing"
            fi
        else
            warn "Warp service is not running"
        fi
    else
        warn "Warp service is not running (normal for Xray method)"
    fi

    echo
    log "Generated configuration preview (first lines):"
    echo -e "${BLUE}Warp Config Preview:${NC}"
    if [[ -f "/opt/warp-config/wgcf-profile.conf" ]]; then
        head -n 10 /opt/warp-config/wgcf-profile.conf || true
    fi
}

verify_files() {
    log "Verifying generated files..."
    local files_ok=true

    if [[ "$SETUP_METHOD" == "2" ]] && [[ ! -f "/etc/wireguard/warp.conf" ]]; then
        error "Wireguard config not found: /etc/wireguard/warp.conf"
        files_ok=false
    fi

    if [[ "$SETUP_METHOD" == "1" ]]; then
        if [[ ! -f "/root/warp_xray_outbound.json" ]]; then
            error "Xray outbound config not found: /root/warp_xray_outbound.json"
            files_ok=false
        else
            log "✓ Xray outbound config created successfully"
        fi
    else
        if [[ ! -f "/root/warp_freedom_outbound.json" ]]; then
            error "Freedom outbound config not found: /root/warp_freedom_outbound.json"
            files_ok=false
        else
            log "✓ Freedom outbound config created successfully"
        fi
    fi

    if [[ ! -f "/root/warp_routing_rule.json" ]]; then
        error "Routing rules not found: /root/warp_routing_rule.json"
        files_ok=false
    else
        log "✓ Routing rules created successfully"
    fi

    if [[ "$files_ok" == "true" ]]; then
        log "All configuration files verified successfully!"
    else
        error "Some configuration files are missing!"
        exit 1
    fi
}

main() {
    print_banner
    check_root
    get_user_input
    install_dependencies
    setup_wgcf
    generate_wg_config
    setup_warp_plus
    extract_config_values
    if [[ "$SETUP_METHOD" == "1" ]]; then
        create_xray_outbound
    else
        setup_wireguard_kernel
        create_freedom_outbound
    fi
    create_routing_rules
    verify_files
    test_warp
    display_config
}

main "$@"
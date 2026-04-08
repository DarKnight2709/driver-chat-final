#!/usr/bin/env bash
# =============================================================================
# install.sh — Build, load driver, build apps, run smoke test
# Requires: CentOS 7/8 x86_64, kernel-devel, gcc, make
# Run as root or with sudo
# =============================================================================

set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

info()  { echo -e "${CYAN}[*]${NC} $*"; }
ok()    { echo -e "${GREEN}[✓]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[✗]${NC} $*"; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── 1. Check prerequisites ────────────────────────────────
info "Checking prerequisites..."

if ! rpm -q kernel-devel-$(uname -r) &>/dev/null; then
    warn "kernel-devel not found, attempting install..."
    yum install -y kernel-devel-$(uname -r) || \
    yum install -y kernel-devel || \
    error "Install kernel-devel manually: yum install kernel-devel"
fi

for pkg in gcc make; do
    command -v $pkg &>/dev/null || yum install -y $pkg || error "Install $pkg"
done

if ! rpm -q sqlite-devel &>/dev/null; then
    warn "sqlite-devel not found, attempting install..."
    yum install -y sqlite-devel || error "Install sqlite-devel"
fi

# Optional: GTK3 for GUI client
if ! pkg-config --exists gtk+-3.0 2>/dev/null; then
    warn "gtk3-devel not found — GUI client will be skipped"
    warn "Install with: yum install gtk3-devel"
fi

ok "Prerequisites satisfied (kernel $(uname -r))"

# ── 3. Build and load kernel driver ──────────────────────
info "Building kernel module..."
cd "$SCRIPT_DIR/driver"
make clean 2>/dev/null || true
make

info "Loading kernel module..."
# Remove previous instance if loaded
lsmod | grep -q crypto_chat && rmmod crypto_chat 2>/dev/null || true

insmod crypto_chat.ko
sleep 1

if lsmod | grep -q crypto_chat; then
    ok "crypto_chat module loaded"
else
    error "Failed to load crypto_chat module (check dmesg)"
fi

# Set permissions on device node
if [ -e /dev/crypto_chat ]; then
    chmod 666 /dev/crypto_chat
    ok "/dev/crypto_chat ready (permissions: 666)"
else
    error "/dev/crypto_chat not created — check dmesg"
fi

# Show driver log
echo ""
info "Driver kernel log:"
dmesg | grep crypto_chat | tail -10
echo ""

# ── 4. Build userspace apps ───────────────────────────────
info "Building userspace applications..."
cd "$SCRIPT_DIR/app"
make clean 2>/dev/null || true
make
ok "Applications built"


# ── 6. Summary ────────────────────────────────────────────
echo ""
echo -e "${BOLD}═══════════════════════════════════════════${NC}"
echo -e "${BOLD}  CryptoChat Installation Complete!         ${NC}"
echo -e "${BOLD}═══════════════════════════════════════════${NC}"
echo ""
echo "To start the server:"
echo "  cd $SCRIPT_DIR/app && sudo ./server [port]"
echo ""
echo "To start a client — Terminal:"
echo "  cd $SCRIPT_DIR/app && ./client [server_ip] [port]"
echo ""
echo "To start a client — GUI (requires gtk3-devel):"
echo "  cd $SCRIPT_DIR/app && ./gui_client [server_ip] [port]"
echo ""
echo "Default port: 9090"
echo "Built-in accounts: alice/password123  bob/secret456"
echo "                   charlie/hello789   admin/admin@CryptoChat#2024"
echo ""
echo "To unload driver:"
echo "  sudo rmmod crypto_chat"
echo ""
echo "To monitor driver logs:"
echo "  sudo dmesg | grep crypto_chat"
echo ""

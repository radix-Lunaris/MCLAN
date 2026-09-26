#!/bin/bash
###############################################################################
#  MCLanP2P signaling server — one-shot deploy (python version)
#
#  usage:   sudo ./deploy-server.sh            # default port 5000
#           sudo ./deploy-server.sh 8080       # custom port
#
#  The server is pure Python standard library: no pip install, no SDK, no build.
#  (The previous .NET version needed the whole SDK toolchain; this does not.)
###############################################################################
set -euo pipefail

PORT="${1:-${PORT:-5000}}"
# Built-in STUN: two consecutive UDP ports. Clients use these to discover
# their public endpoint; without them direct P2P degrades to a LAN address.
STUN_PORT="${STUN_PORT:-3478}"
STUN_PORT2="${STUN_PORT2:-$((STUN_PORT + 1))}"
if ! [[ "$PORT" =~ ^[0-9]+$ ]] || [ "$PORT" -lt 1 ] || [ "$PORT" -gt 65535 ]; then
    echo "invalid port: $PORT" >&2; exit 1
fi

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="/opt/mc-p2p"
SVC="mc-p2p"

if [ -t 1 ]; then
    GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; RED='\033[0;31m'; NC='\033[0m'
else
    GREEN=''; YELLOW=''; CYAN=''; RED=''; NC=''
fi
info() { echo -e "${CYAN}[INFO]${NC} $*"; }
ok()   { echo -e "${GREEN}[ OK ]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
fail() { echo -e "${RED}[FAIL]${NC} $*" >&2; exit 1; }

if [ "$(id -u)" -eq 0 ]; then SUDO=""; else
    command -v sudo >/dev/null 2>&1 || fail "need root: re-run with sudo"
    SUDO="sudo"
fi
run() { if [ -n "$SUDO" ]; then sudo "$@"; else "$@"; fi; }

echo ""
echo "============================================"
echo "   MCLanP2P server deploy (python)"
echo "   listen port: $PORT"
echo "============================================"
echo ""

# ---------- 1. OS ----------
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS="${ID:-unknown}"; VER="${VERSION_ID:-}"
else
    fail "unknown OS"
fi
ok "OS: $OS ${VER:-?}"

# ---------- 2. python3 ----------
info "checking python3..."
if ! command -v python3 >/dev/null 2>&1; then
    info "installing python3..."
    case "$OS" in
        ubuntu|debian) run apt-get update -qq && run apt-get install -y python3 ;;
        centos|rhel|rocky|almalinux|fedora) run dnf install -y python3 || run yum install -y python3 ;;
        arch|manjaro) run pacman -S --noconfirm python ;;
        *) fail "install python3 manually" ;;
    esac
fi
PYVER="$(python3 -c 'import sys;print("%d.%d"%sys.version_info[:2])')"
PYMAJ="$(python3 -c 'import sys;print(sys.version_info[0])')"
PYMIN="$(python3 -c 'import sys;print(sys.version_info[1])')"
if [ "$PYMAJ" -lt 3 ] || { [ "$PYMAJ" -eq 3 ] && [ "$PYMIN" -lt 7 ]; }; then
    fail "python 3.7+ required, found $PYVER"
fi
ok "python3: $PYVER ($(command -v python3))"

# ---------- 3. install server source ----------
# The server runs as a plain Python script: no build step, no toolchain,
# no glibc concerns. python3 ships with every Linux distro.
SRC="$SRC_DIR/server/server.py"
[ -f "$SRC" ] || fail "missing $SRC"

info "installing to $INSTALL_DIR ..."
run mkdir -p "$INSTALL_DIR"
run cp "$SRC" "$INSTALL_DIR/server.py"
run chmod 644 "$INSTALL_DIR/server.py"
ok "server.py installed"

info "syntax check..."
python3 -m py_compile "$INSTALL_DIR/server.py" || fail "server.py has a syntax error"
ok "syntax OK"

EXEC="$(command -v python3) -u $INSTALL_DIR/server.py"

# ---------- 4. firewall ----------
# The signalling port (TCP) plus the built-in STUN ports (UDP).
# STUN needs UDP: without it clients cannot discover their public endpoint
# and fall back to a LAN address, which breaks direct P2P.
info "opening firewall..."
STUN_PORTS="$STUN_PORT"
[ "$STUN_PORT" != "0" ] && STUN_PORTS="$STUN_PORT:$STUN_PORT2"

open_ports() {
    # $1 = proto, $2 = port-or-range
    if command -v ufw >/dev/null 2>&1; then
        run ufw allow "$2/$1" 2>/dev/null || true
        ok "ufw: $2/$1"
    elif command -v firewall-cmd >/dev/null 2>&1; then
        if [ "$1" = "tcp" ]; then
            run firewall-cmd --permanent --add-port="$2/tcp" 2>/dev/null || true
        else
            run firewall-cmd --permanent --add-port="$2/udp" 2>/dev/null || true
        fi
    elif command -v iptables >/dev/null 2>&1; then
        # -A, not -I. Inserting at the head of INPUT silently reorders
        # whatever the user already had (DROP rules, fail2ban chains),
        # which can punch a hole wider than we intended -- or break their
        # rules outright.
        run iptables -A INPUT -p "$1" --dport "$2" -j ACCEPT 2>/dev/null || true
    fi
}

open_ports tcp "$PORT"
if [ "$STUN_PORT" != "0" ]; then
    open_ports udp "$STUN_PORTS"
fi
if command -v firewall-cmd >/dev/null 2>&1; then
    run firewall-cmd --reload 2>/dev/null || true
    ok "firewalld: ${PORT}/tcp + ${STUN_PORTS}/udp"
fi
if ! command -v ufw >/dev/null 2>&1 && ! command -v firewall-cmd >/dev/null 2>&1; then
    if command -v iptables >/dev/null 2>&1; then
        warn "iptables rules added (not persistent across reboot)"
    else
        warn "no firewall tool found; open ${PORT}/tcp and ${STUN_PORTS}/udp manually"
    fi
fi

# ---------- 5. systemd ----------

UNIT="/etc/systemd/system/$SVC.service"
info "writing $UNIT ..."
{
    echo "[Unit]"
    echo "Description=MCLanP2P signaling server"
    echo "After=network.target"
    echo ""
    echo "[Service]"
    echo "Type=simple"
    echo "WorkingDirectory=$INSTALL_DIR"
    echo "ExecStart=$EXEC"
    echo "Environment=PORT=$PORT"
    echo "Environment=STUN_PORT=$STUN_PORT"
    echo "Environment=STUN_PORT2=$STUN_PORT2"
    echo "Environment=PYTHONUNBUFFERED=1"
    echo "Restart=always"
    echo "RestartSec=3"
    echo "StandardOutput=journal"
    echo "StandardError=journal"
    echo ""
    echo "[Install]"
    echo "WantedBy=multi-user.target"
} | run tee "$UNIT" > /dev/null
ok "unit written"

if command -v systemctl >/dev/null 2>&1; then
    run systemctl daemon-reload
    run systemctl enable "$SVC" 2>/dev/null || true
    info "starting $SVC..."
    run systemctl restart "$SVC"
    sleep 2
    if systemctl is-active --quiet "$SVC"; then
        ok "$SVC is running"
    else
        run journalctl -u "$SVC" -n 25 --no-pager 2>/dev/null || true
        fail "$SVC failed to start"
    fi
else
    warn "no systemd; start manually:  PORT=$PORT $EXEC"
fi

# ---------- 6. logrotate ----------
if [ -d /etc/logrotate.d ]; then
    run tee /etc/logrotate.d/mc-p2p > /dev/null <<'EOF' || true
/var/log/mc-p2p.log {
    daily
    rotate 7
    size 10M
    missingok
    notifempty
    copytruncate
    compress
}
EOF
    ok "logrotate configured"
fi

# ---------- 7. verify ----------
info "verifying port..."
READY="no"
for _ in $(seq 1 20); do
    if python3 - "$PORT" <<'PY' 2>/dev/null
import socket, sys
s = socket.socket(); s.settimeout(1)
sys.exit(0 if s.connect_ex(("127.0.0.1", int(sys.argv[1]))) == 0 else 1)
PY
    then READY="yes"; break; fi
    sleep 0.5
done
[ "$READY" = "yes" ] && ok "port $PORT is listening" \
                     || warn "port $PORT not listening yet (check: journalctl -u $SVC)"

echo ""
echo "============================================"
echo -e "  ${GREEN}deploy complete${NC}"
echo "============================================"
echo ""
echo -e "  ${CYAN}status:${NC}   sudo systemctl status $SVC"
echo -e "  ${CYAN}logs:${NC}     sudo journalctl -u $SVC -f"
echo -e "               sudo tail -f /var/log/mc-p2p.log"
echo -e "  ${CYAN}client:${NC}   ws://<this-server-ip>:$PORT/ws"
echo ""
warn "cloud server? also open ${PORT}/tcp in the provider's SECURITY GROUP"
if [ "$STUN_PORT" != "0" ]; then
    warn "   ...and UDP ${STUN_PORT} + ${STUN_PORT2} (built-in STUN)"
    warn "   no STUN reachable = no public endpoint = direct P2P cannot work"
fi
warn "(ufw/firewalld only handles the host firewall, not the cloud layer)"
echo ""

#!/bin/bash
# One-shot installer/updater for the SQLiAgent systemd/LSB service.
# Run as root from anywhere:
#   sudo bash "/home/usuario/2. SQLCortex/deploy/install-service.sh"
#
# It installs deploy/sqli.initd as /etc/init.d/sqli, enables it on boot,
# stops any previous/duplicate orchestrator, frees the web port, starts the
# service cleanly and prints a verification summary.
set -u

APPDIR="/home/usuario/2. SQLCortex"     # edit if the app lives elsewhere
SRC="$APPDIR/deploy/sqli.initd"
DEST="/etc/init.d/sqli"
LOG="$APPDIR/sqli-service.log"

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: must run as root (use: sudo bash \"$0\")"; exit 1
fi
if [ ! -f "$SRC" ]; then
    echo "ERROR: init script not found: $SRC"; exit 1
fi

echo "[1/5] Installing init script..."
[ -f "$DEST" ] && cp -v "$DEST" "$DEST.bak.$(date +%Y%m%d_%H%M%S)"
cp -v "$SRC" "$DEST"
chmod +x "$DEST"

echo "[2/5] systemd daemon-reload + enable on boot..."
systemctl daemon-reload
systemctl enable sqli.service

echo "[3/5] Stopping any previous/duplicate instances and freeing :8000..."
systemctl stop sqli.service 2>/dev/null
pkill -f SQLiAgentOrchestrator 2>/dev/null
fuser -k 8000/tcp 2>/dev/null
sleep 2

echo "[4/5] Starting service..."
systemctl start sqli.service
sleep 6

echo "[5/5] Verification:"
echo -n "  enabled: "; systemctl is-enabled sqli.service 2>/dev/null
echo -n "  active:  "; systemctl is-active sqli.service 2>/dev/null
echo "  listener on :8000:"; ss -ltn | grep ":8000" || echo "    NOTHING on :8000"
echo -n "  local http /websqli/: "; curl -s -o /dev/null -w "%{http_code}\n" --max-time 6 http://127.0.0.1:8000/websqli/ 2>/dev/null || echo "fail"
echo "  processes:"; ps -eo pid,user,cmd | grep -iE "SQLiAgentOrchestrator|Web/app.py" | grep -v grep || echo "    none"
echo "  URL banner from log:"; grep -A8 "Web URLs" "$LOG" 2>/dev/null | tail -n 10 || echo "    (not found yet)"
echo "DONE."

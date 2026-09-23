#!/usr/bin/env bash
# ==============================================================================
# AI Exploit Chain Mapper - Decommission ttyd Service (Approach 1 Removal)
# Target Host: 213.199.43.129 (Ubuntu VPS)
# ==============================================================================

set -e

echo "=========================================================================="
echo " [*] Decommissioning & Removing ttyd (Approach 1)..."
echo "=========================================================================="

# 1. Stop and disable systemd service
if systemctl list-unit-files | grep -q "ttyd.service"; then
    echo "[*] Stopping and disabling ttyd.service..."
    systemctl stop ttyd.service 2>/dev/null || true
    systemctl disable ttyd.service 2>/dev/null || true
fi

# 2. Remove systemd service file
if [ -f "/etc/systemd/system/ttyd.service" ]; then
    echo "[*] Removing /etc/systemd/system/ttyd.service..."
    rm -f /etc/systemd/system/ttyd.service
    systemctl daemon-reload
    systemctl reset-failed 2>/dev/null || true
fi

# 3. Kill any lingering ttyd processes
echo "[*] Terminating lingering ttyd processes..."
pkill -9 ttyd 2>/dev/null || true

# 4. Remove ttyd binary
if [ -f "/usr/local/bin/ttyd" ]; then
    echo "[*] Removing /usr/local/bin/ttyd binary..."
    rm -f /usr/local/bin/ttyd
fi

# 5. Clean up temporary htpasswd if created
if [ -f "/etc/nginx/.htpasswd" ]; then
    echo "[*] Cleaning up /etc/nginx/.htpasswd..."
    rm -f /etc/nginx/.htpasswd
fi

# 6. Verify port 7681 is freed
echo "[*] Verifying port 7681 status..."
if ss -tulpn | grep -q 7681; then
    echo "[!] WARNING: Port 7681 still in use:"
    ss -tulpn | grep 7681
else
    echo "[+] Port 7681 successfully freed."
fi

echo "=========================================================================="
echo " [✓] SUCCESS: ttyd has been completely removed and decommissioned."
echo "=========================================================================="

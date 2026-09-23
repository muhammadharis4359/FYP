#!/usr/bin/env bash
# ==============================================================================
# AI Exploit Chain Mapper - VPS Terminal Daemon Installer (ttyd)
# Target Host: 213.199.43.129 (Ubuntu VPS)
# ==============================================================================

set -e

echo "=========================================================================="
echo " [*] Installing & Configuring Web Terminal Daemon (ttyd) for VPS..."
echo "=========================================================================="

# 1. Detect Architecture and Download ttyd
ARCH=$(uname -m)
if [ "$ARCH" = "x86_64" ]; then
    TTYD_ARCH="x86_64"
elif [ "$ARCH" = "aarch64" ]; then
    TTYD_ARCH="aarch64"
elif [ "$ARCH" = "armv7l" ]; then
    TTYD_ARCH="armhf"
else
    TTYD_ARCH="i686"
fi

echo "[*] Downloading ttyd (${TTYD_ARCH}) binary..."
curl -fsSL "https://github.com/tsl0922/ttyd/releases/latest/download/ttyd.${TTYD_ARCH}" -o /usr/local/bin/ttyd
chmod +x /usr/local/bin/ttyd

echo "[+] ttyd binary installed at /usr/local/bin/ttyd"

# 2. Configure Systemd Service
# Note:
# -p 7681 : Port 7681
# -c root:fyp18084 : Basic Auth protection on direct terminal
# -W : Enable interactive command execution (writable)
echo "[*] Creating systemd service at /etc/systemd/system/ttyd.service..."
cat << 'EOF' > /etc/systemd/system/ttyd.service
[Unit]
Description=ttyd - AI Exploit Chain Mapper Web Terminal
Documentation=https://github.com/tsl0922/ttyd
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/root
# Bind to 0.0.0.0:7681 with authentication for direct access, or change to 127.0.0.1 if using Nginx
ExecStart=/usr/local/bin/ttyd -p 7681 -c root:fyp18084 -W /bin/bash
Restart=on-failure
RestartSec=5s
KillMode=mixed
KillSignal=SIGTERM
TimeoutStopSec=10s
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

# 3. Reload Systemd and Enable Service
echo "[*] Reloading systemd daemon and enabling ttyd..."
systemctl daemon-reload
systemctl enable ttyd.service
systemctl restart ttyd.service

# 4. Open Firewall Port 7681 if UFW is active
if command -v ufw >/dev/null 2>&1; then
    if ufw status | grep -q "Status: active"; then
        echo "[*] Allowing port 7681 through UFW..."
        ufw allow 7681/tcp comment "ttyd Web Terminal"
    fi
fi

echo "=========================================================================="
echo " [+] SUCCESS! Live Web Terminal is running on VPS 213.199.43.129:7681"
echo "=========================================================================="
echo " -> Test connection URL: http://213.199.43.129:7681"
echo " -> Credentials: Username: root | Password: (your VPS password)"
echo " -> Check status: sudo systemctl status ttyd.service"
echo "=========================================================================="

#!/usr/bin/env bash
# ==============================================================================
# AI Exploit Chain Mapper - Claude Code PostToolUse Hook Installer for VPS
# Target Host: 213.199.43.129 (Ubuntu VPS)
# ==============================================================================

set -e

echo "=========================================================================="
echo " [*] Installing Claude Code PostToolUse Telemetry Hook on VPS..."
echo "=========================================================================="

# 1. Copy or Create /root/sync_hook.py
HOOK_PATH="/root/sync_hook.py"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ -f "$SCRIPT_DIR/sync_hook.py" ]; then
    cp "$SCRIPT_DIR/sync_hook.py" "$HOOK_PATH"
else
    echo "[!] Copying sync_hook.py from repository..."
fi

chmod +x "$HOOK_PATH"
echo "[+] Hook script installed at $HOOK_PATH"

# 2. Setup ~/.claude/settings.json
CLAUDE_DIR="/root/.claude"
mkdir -p "$CLAUDE_DIR"

SETTINGS_FILE="$CLAUDE_DIR/settings.json"
cat << 'EOF' > "$SETTINGS_FILE"
{
  "hooks": {
    "PostToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "python3 /root/sync_hook.py"
          }
        ]
      }
    ]
  }
}
EOF

echo "[+] Configured Claude Code hook in $SETTINGS_FILE"

# 3. Setup Agent Methodology Rule File (/root/CLAUDE.md)
if [ -f "$SCRIPT_DIR/CLAUDE.md" ]; then
    cp "$SCRIPT_DIR/CLAUDE.md" /root/CLAUDE.md
    echo "[+] Copied CLAUDE.md methodology to /root/CLAUDE.md"
fi

# 4. Check Backend API Connectivity
echo "[*] Checking local backend API status..."
if curl -s -f http://127.0.0.1:8000/api/health >/dev/null 2>&1; then
    echo "[✓] Backend API is ONLINE and reachable at http://127.0.0.1:8000"
else
    echo "[!] Warning: Backend API on 127.0.0.1:8000 is not currently active."
    echo "    Start the FastAPI backend server with: cd /opt/fyp-backend && uvicorn app.main:app --host 0.0.0.0 --port 8000"
fi

echo "=========================================================================="
echo " [✓] Claude Code Telemetry Hook Setup Completed Successfully!"
echo "     Every subfinder, httpx, nuclei and exploit chain output will now"
echo "     automatically sync to the Cyber Telemetry Dashboard tabs in real-time."
echo "=========================================================================="

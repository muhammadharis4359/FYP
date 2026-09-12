"""
Standalone Live Cyber Terminal Monitor.
Streams live tool execution logs, reconnaissance discovery, and scanner events
in real time in a dedicated terminal window.
"""

import os
import sys
import time
from pathlib import Path

# Enable ANSI escape sequences on Windows
if sys.platform == "win32":
    os.system("color")

LOG_FILE = Path(__file__).resolve().parent / "logs" / "scanner_live.log"

MAGENTA = "\033[38;5;201m"
GREEN = "\033[38;5;46m"
CYAN = "\033[38;5;51m"
YELLOW = "\033[38;5;226m"
RED = "\033[38;5;196m"
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"


def colorize_line(line: str) -> str:
    """Adds color formatting to log lines."""
    if "LAUNCHED REAL PIPELINE" in line or "===" in line:
        return f"{CYAN}{BOLD}{line}{RESET}"
    elif "STAGE" in line:
        return f"{YELLOW}{BOLD}{line}{RESET}"
    elif "CRITICAL:" in line:
        return f"{RED}{BOLD}{line}{RESET}"
    elif "HIGH:" in line:
        return f"{YELLOW}{BOLD}{line}{RESET}"
    elif "INFERRED ATTACK CHAIN:" in line:
        return f"{MAGENTA if 'MAGENTA' in globals() else CYAN}{BOLD}{line}{RESET}"
    elif "Host Verified:" in line or "COMPLETED for" in line:
        return f"{GREEN}{BOLD}{line}{RESET}"
    elif "[+]" in line:
        return f"{GREEN}{line}{RESET}"
    elif "[-]" in line or "ERROR" in line:
        return f"{RED}{line}{RESET}"
    return line


def main():
    print(f"{CYAN}{BOLD}")
    print("=========================================================================")
    print("      AI EXPLOIT CHAIN MAPPER -- LIVE TERMINAL TELEMETRY MONITOR")
    print("=========================================================================")
    print(f"{RESET}{DIM}Streaming real-time execution logs from backend scanner engines...{RESET}\n")

    LOG_FILE.parent.mkdir(exist_ok=True)
    if not LOG_FILE.exists():
        with open(LOG_FILE, "w", encoding="utf-8") as f:
            f.write(f"[{time.strftime('%H:%M:%S')}] Live Telemetry Monitor initialized. Awaiting scan runs...\n")

    with open(LOG_FILE, "r", encoding="utf-8", errors="ignore") as f:
        # Print initial lines
        lines = f.readlines()
        for line in lines[-25:]:
            print(colorize_line(line.rstrip()))

        # Tail file continuously
        while True:
            line = f.readline()
            if line:
                print(colorize_line(line.rstrip()))
            else:
                time.sleep(0.3)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{YELLOW}Telemetry monitor stopped.{RESET}")

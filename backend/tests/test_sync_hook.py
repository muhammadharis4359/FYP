"""
Test script for sync_hook.py simulating Claude Code PostToolUse hook execution.
"""

import subprocess
import sys
import os
import json

def test_sync_hook_stdin():
    root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    hook_script = os.path.join(root_dir, "sync_hook.py")
    assert os.path.exists(hook_script), f"Hook not found: {hook_script}"

    # Simulated Claude Code PostToolUse payload
    sample_event = {
        "event": "PostToolUse",
        "tool_name": "Bash",
        "tool_input": {
            "command": "subfinder -d telemetry-test.io -silent"
        },
        "tool_response": "hook-node1.telemetry-test.io\nhook-node2.telemetry-test.io"
    }

    input_json = json.dumps(sample_event)
    python_exe = sys.executable

    # Note: Backend server is not running on port 8000 in this unit test,
    # so sync_hook will safely fail silently and exit 0 without crashing.
    proc = subprocess.Popen(
        [python_exe, hook_script],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    stdout, stderr = proc.communicate(input=input_json, timeout=5)

    print("Exit code:", proc.returncode)
    print("Stdout:", stdout)
    print("Stderr:", stderr)
    assert proc.returncode == 0, "Hook should always exit with code 0"
    print("[OK] sync_hook.py executed cleanly with zero exit code!")

if __name__ == "__main__":
    test_sync_hook_stdin()

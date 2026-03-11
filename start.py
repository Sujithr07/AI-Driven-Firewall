"""
Startup script — launches both the FL server and the main Flask app.

Usage:
    python start.py
"""

import subprocess
import sys
import time
import signal
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PYTHON = sys.executable


def main():
    procs = []

    def shutdown(*_args):
        print("\n[start] Shutting down...")
        for p in procs:
            if p.poll() is None:
                p.terminate()
        for p in procs:
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    # 1. Start FL server
    print("[start] Launching FL server (fl_server.py) on port 6000...")
    fl_proc = subprocess.Popen(
        [PYTHON, os.path.join(BASE_DIR, "fl_server.py")],
        stdout=sys.stdout,
        stderr=sys.stderr,
    )
    procs.append(fl_proc)

    # 2. Wait for it to be ready
    time.sleep(2)
    if fl_proc.poll() is not None:
        print("[start] ERROR: FL server exited immediately. Check fl_server.py for errors.")
        sys.exit(1)

    # 3. Start main app
    print("[start] Launching main app (app.py)...")
    app_proc = subprocess.Popen(
        [PYTHON, os.path.join(BASE_DIR, "app.py")],
        stdout=sys.stdout,
        stderr=sys.stderr,
    )
    procs.append(app_proc)

    print("[start] Both servers running. Press Ctrl+C to stop.")

    # Wait for either process to exit
    try:
        while True:
            for p in procs:
                if p.poll() is not None:
                    print(f"[start] Process {p.args} exited with code {p.returncode}")
                    shutdown()
            time.sleep(1)
    except KeyboardInterrupt:
        shutdown()


if __name__ == "__main__":
    main()

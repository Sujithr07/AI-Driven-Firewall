"""
Startup script — launches the FL server and the main Flask app.
Optionally also starts the MLflow UI.

Usage (from backend/):
    python start.py                 # FL server + Flask app
    python start.py --mlflow-ui     # FL server + Flask app + MLflow UI
"""

import argparse
import subprocess
import sys
import time
import signal
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PYTHON   = sys.executable

_DB_PATH     = os.path.join(BASE_DIR, "data", "mlflow.db").replace("\\", "/")
_MLFLOW_URI  = os.getenv("MLFLOW_TRACKING_URI", f"sqlite:///{_DB_PATH}")
_MLFLOW_PORT = int(os.getenv("MLFLOW_UI_PORT", "5001"))


def main():
    parser = argparse.ArgumentParser(description="Firewall stack launcher")
    parser.add_argument("--mlflow-ui", action="store_true",
                        help=f"Also launch the MLflow UI on port {_MLFLOW_PORT}")
    args = parser.parse_args()

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
    fl_server = os.path.join(BASE_DIR, "app", "federation", "fl_server.py")
    print("[start] Launching FL server on port 6000...")
    fl_proc = subprocess.Popen([PYTHON, fl_server], stdout=sys.stdout, stderr=sys.stderr)
    procs.append(fl_proc)

    # 2. Wait for it to be ready
    time.sleep(2)
    if fl_proc.poll() is not None:
        print("[start] ERROR: FL server exited immediately.")
        sys.exit(1)

    # 3. Start Flask app (run from backend/ so `app` package is on sys.path)
    print("[start] Launching Flask app (run.py)...")
    app_proc = subprocess.Popen([PYTHON, os.path.join(BASE_DIR, "run.py")],
                                 stdout=sys.stdout, stderr=sys.stderr, cwd=BASE_DIR)
    procs.append(app_proc)

    # 4. Optionally start MLflow UI
    if args.mlflow_ui:
        os.makedirs(os.path.join(BASE_DIR, "data"), exist_ok=True)
        print(f"[start] Launching MLflow UI on http://localhost:{_MLFLOW_PORT} ...")
        mlflow_proc = subprocess.Popen(
            [PYTHON, "-m", "mlflow", "ui", "--port", str(_MLFLOW_PORT),
             "--backend-store-uri", _MLFLOW_URI],
            stdout=sys.stdout, stderr=sys.stderr)
        procs.append(mlflow_proc)

    print("[start] All servers running. Press Ctrl+C to stop.")
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

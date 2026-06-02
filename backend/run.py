"""Run the Flask/SocketIO development server.

Usage (from backend/):
    python run.py
"""

import os
from dotenv import load_dotenv

load_dotenv()

from app import create_app
from app.core.extensions import socketio

app = create_app()

if __name__ == '__main__':
    print("=======================================================================")
    print("FLASK BACKEND RUNNING: Access the API at http://127.0.0.1:5000")
    print(f"Admin user: {os.getenv('ADMIN_USERNAME', 'admin')} (password in .env)")
    print("=======================================================================")
    print("Detection Agent: Use POST /api/agent/start to begin packet inspection")
    print("=======================================================================")
    debug = os.getenv("FLASK_DEBUG", "0") == "1"
    socketio.run(app, host="0.0.0.0", port=5000, debug=debug)

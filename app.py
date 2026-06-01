"""
Application entrypoint.

Thin Flask bootstrap: loads configuration, initializes extensions and the
database, registers the API blueprints, and runs the SocketIO server. All
endpoint logic lives in the ``routes`` package; persistence in ``db``; shared
service singletons in ``services``.
"""

import os
import secrets
from datetime import timedelta

from flask import Flask
from flask_cors import CORS
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

from extensions import socketio, jwt
from db.models import init_db
from log_embedder import embedder
from routes import register_blueprints


def _get_jwt_secret():
    """Load JWT secret from env or generate and persist one."""
    secret = os.getenv('JWT_SECRET_KEY')
    if secret:
        return secret
    # Auto-generate and persist to .env so it stays stable across restarts
    secret = secrets.token_hex(32)
    env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env')
    with open(env_path, 'r') as f:
        content = f.read()
    if 'JWT_SECRET_KEY=' in content:
        lines = content.splitlines()
        for i, line in enumerate(lines):
            if line.startswith('JWT_SECRET_KEY='):
                lines[i] = f'JWT_SECRET_KEY={secret}'
                break
        with open(env_path, 'w') as f:
            f.write('\n'.join(lines) + '\n')
    else:
        with open(env_path, 'a') as f:
            f.write(f'\nJWT_SECRET_KEY={secret}\n')
    os.environ['JWT_SECRET_KEY'] = secret
    print(f'[Security] Generated new JWT secret and saved to .env')
    return secret


def create_app():
    """Build and configure the Flask application."""
    app = Flask(__name__)
    app.config['JWT_SECRET_KEY'] = _get_jwt_secret()
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)
    app.config['JWT_ALGORITHM'] = 'HS256'

    # Enable CORS for the frontend running on a different port
    CORS(app, supports_credentials=True)

    # Bind extensions to the app
    jwt.init_app(app)
    socketio.init_app(app, cors_allowed_origins="*", async_mode="eventlet")

    # Database + embedder startup
    init_db()
    embedder.load()

    # Register all API blueprints
    register_blueprints(app)

    return app


app = create_app()


if __name__ == '__main__':
    print("=======================================================================")
    print("FLASK BACKEND RUNNING: Access the API at http://127.0.0.1:5000")
    print(f"Admin user: {os.getenv('ADMIN_USERNAME', 'admin')} (password in .env)")
    print("=======================================================================")
    print("Detection Agent: Use POST /api/agent/start to begin packet inspection")
    print("=======================================================================")
    socketio.run(app, debug=True, port=5000)

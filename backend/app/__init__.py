"""
Application factory.

Thin Flask bootstrap: loads configuration, initialises extensions and the
database, registers API blueprints, and exposes the SocketIO-wrapped app.
All endpoint logic lives in ``app.api``; persistence in ``app.db``;
shared singletons in ``app.services``.
"""

import os
import secrets
from datetime import timedelta

from flask import Flask
from flask_cors import CORS
from dotenv import load_dotenv

load_dotenv()

from app.core.extensions import socketio, jwt
from app.db.models import init_db
from app.rag.log_embedder import embedder
from app.api import register_blueprints


def _get_jwt_secret():
    secret = os.getenv('JWT_SECRET_KEY')
    if secret:
        return secret
    secret = secrets.token_hex(32)
    # .env lives at backend/
    env_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), '.env')
    if os.path.exists(env_path):
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
    print('[Security] Generated new JWT secret and saved to .env')
    return secret


def create_app():
    app = Flask(__name__)
    app.config['JWT_SECRET_KEY'] = _get_jwt_secret()
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)
    app.config['JWT_ALGORITHM'] = 'HS256'

    CORS(app, supports_credentials=True)

    jwt.init_app(app)
    socketio.init_app(app, cors_allowed_origins="*", async_mode="eventlet")

    init_db()
    embedder.load()

    register_blueprints(app)

    return app

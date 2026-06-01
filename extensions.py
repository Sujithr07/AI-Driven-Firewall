"""
Flask extension singletons.

These are instantiated without an application and bound to the app via
``init_app()`` in the application entrypoint, so that blueprints and service
modules can import them without creating circular dependencies on ``app.py``.
"""

from flask_jwt_extended import JWTManager
from flask_socketio import SocketIO

socketio = SocketIO(cors_allowed_origins="*", async_mode="eventlet")
jwt = JWTManager()

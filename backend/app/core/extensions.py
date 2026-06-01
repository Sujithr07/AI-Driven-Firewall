"""Flask extension singletons (initialised without an app, bound via init_app)."""

from flask_jwt_extended import JWTManager
from flask_socketio import SocketIO

socketio = SocketIO(cors_allowed_origins="*", async_mode="eventlet")
jwt = JWTManager()

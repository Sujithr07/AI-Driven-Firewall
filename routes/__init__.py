"""
Route blueprints.

``register_blueprints(app)`` attaches every API blueprint to the Flask app.
"""

from routes.auth import auth_bp
from routes.dashboard import dashboard_bp
from routes.detection import detection_bp
from routes.xai import xai_bp
from routes.federation import federation_bp
from routes.logs import logs_bp

ALL_BLUEPRINTS = (
    auth_bp,
    dashboard_bp,
    detection_bp,
    xai_bp,
    federation_bp,
    logs_bp,
)


def register_blueprints(app):
    """Register all API blueprints on the given Flask app."""
    for bp in ALL_BLUEPRINTS:
        app.register_blueprint(bp)

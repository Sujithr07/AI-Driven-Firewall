"""API blueprint registry."""

from app.auth.routes import auth_bp
from app.api.dashboard.routes import dashboard_bp
from app.api.detection.routes import detection_bp
from app.api.xai.routes import xai_bp
from app.api.federation.routes import federation_bp
from app.api.logs.routes import logs_bp

ALL_BLUEPRINTS = (auth_bp, dashboard_bp, detection_bp, xai_bp, federation_bp, logs_bp)


def register_blueprints(app):
    for bp in ALL_BLUEPRINTS:
        app.register_blueprint(bp)

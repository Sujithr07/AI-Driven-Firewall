"""
Centralised path and configuration constants.

All other modules should import paths from here rather than computing them
with ad-hoc ``os.path.dirname(__file__)`` chains.
"""

import os

# backend/ directory (three levels up from core/)
_BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

DATA_DIR    = os.path.join(_BACKEND_DIR, 'data')
DB_PATH     = os.path.join(DATA_DIR, 'firewall.db')
MODELS_DIR  = os.path.join(DATA_DIR, 'models')
CHROMA_DIR  = os.path.join(DATA_DIR, 'chroma_db')
MLFLOW_URI  = f"sqlite:///{os.path.join(DATA_DIR, 'mlflow.db').replace(chr(92), '/')}"

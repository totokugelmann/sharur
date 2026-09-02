"""
Sharur SAIC - app/api/deps.py

Dependencias comunes de FastAPI: sesion de DB y helpers de
autorizacion re-exportados para uso directo en los endpoints.
"""

from app.core.config import get_settings
from app.core.security import get_current_user, require_role
from app.models.base import get_db

settings = get_settings()

__all__ = ["get_db", "get_current_user", "require_role", "settings"]

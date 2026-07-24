"""Compatibility ASGI entrypoint.

Run with: ``uvicorn main:app --reload``
The industrial application factory lives in :mod:`app.main`.
"""

from app.core.config import get_settings
from app.main import app, create_app

APP_VERSION = get_settings().app_version

__all__ = ["APP_VERSION", "app", "create_app"]

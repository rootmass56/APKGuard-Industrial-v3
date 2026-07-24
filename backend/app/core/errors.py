"""Standard API exceptions and response handlers."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.context import get_request_id

log = logging.getLogger("apkguard.errors")


class ErrorCode(str, Enum):
    INVALID_REQUEST = "INVALID_REQUEST"
    INVALID_UPLOAD = "INVALID_UPLOAD"
    PAYLOAD_TOO_LARGE = "PAYLOAD_TOO_LARGE"
    ANALYSIS_FAILED = "ANALYSIS_FAILED"
    MODULE_UNAVAILABLE = "MODULE_UNAVAILABLE"
    EXTERNAL_SERVICE_ERROR = "EXTERNAL_SERVICE_ERROR"
    NOT_FOUND = "NOT_FOUND"
    INTERNAL_ERROR = "INTERNAL_ERROR"


class AppError(Exception):
    def __init__(
        self,
        message: str,
        *,
        code: ErrorCode = ErrorCode.INVALID_REQUEST,
        status_code: int = 400,
        details: Any = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.code = code
        self.status_code = status_code
        self.details = details


class InvalidUploadError(AppError):
    def __init__(self, message: str, *, too_large: bool = False, details: Any = None) -> None:
        super().__init__(
            message,
            code=ErrorCode.PAYLOAD_TOO_LARGE if too_large else ErrorCode.INVALID_UPLOAD,
            status_code=413 if too_large else 400,
            details=details,
        )


class AnalysisFailedError(AppError):
    def __init__(self, message: str = "APK analysis failed.", *, details: Any = None) -> None:
        super().__init__(
            message,
            code=ErrorCode.ANALYSIS_FAILED,
            status_code=500,
            details=details,
        )


def _json_safe(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_json_safe(item) for item in value]
    return str(value)


def _payload(code: str, message: str, details: Any = None) -> dict[str, Any]:
    request_id = get_request_id()
    return {
        "detail": message,
        "error": {
            "code": code,
            "message": message,
            "details": _json_safe(details),
        },
        "request_id": request_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(AppError)
    async def handle_app_error(_: Request, exc: AppError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content=_payload(exc.code.value, exc.message, exc.details),
        )

    @app.exception_handler(RequestValidationError)
    async def handle_validation_error(_: Request, exc: RequestValidationError) -> JSONResponse:
        return JSONResponse(
            status_code=422,
            content=_payload(
                ErrorCode.INVALID_REQUEST.value,
                "Request validation failed.",
                exc.errors(),
            ),
        )

    @app.exception_handler(StarletteHTTPException)
    async def handle_http_error(_: Request, exc: StarletteHTTPException) -> JSONResponse:
        detail = exc.detail
        message = detail if isinstance(detail, str) else "Request failed."
        code = ErrorCode.NOT_FOUND.value if exc.status_code == 404 else ErrorCode.INVALID_REQUEST.value
        return JSONResponse(
            status_code=exc.status_code,
            content=_payload(code, message, detail if not isinstance(detail, str) else None),
        )

    @app.exception_handler(Exception)
    async def handle_unexpected_error(_: Request, exc: Exception) -> JSONResponse:
        log.exception("Unhandled API exception", exc_info=exc)
        return JSONResponse(
            status_code=500,
            content=_payload(
                ErrorCode.INTERNAL_ERROR.value,
                "An unexpected internal error occurred. Check server logs using the request ID.",
            ),
        )

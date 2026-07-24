"""Request schemas for non-file API endpoints."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, model_validator


class ScanUrlRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    message: str | None = None
    url: str | None = None

    @model_validator(mode="after")
    def require_content(self) -> "ScanUrlRequest":
        if not (self.message or self.url):
            raise ValueError("Provide either 'message' or 'url'.")
        return self

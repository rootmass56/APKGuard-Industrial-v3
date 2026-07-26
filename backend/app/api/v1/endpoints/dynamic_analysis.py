"""Phase 4 sandbox capability, policy, session, and event endpoints."""

from fastapi import APIRouter

from app.dependencies import get_dynamic_analysis_service
from app.schemas.dynamic import (
    SandboxCapabilityResponse,
    SandboxEventListResponse,
    SandboxPolicyResponse,
    SandboxSessionResponse,
)

router = APIRouter(prefix="/dynamic-analysis", tags=["Dynamic Analysis"])


@router.get("/capabilities", response_model=SandboxCapabilityResponse)
async def capabilities() -> SandboxCapabilityResponse:
    return get_dynamic_analysis_service().capabilities()


@router.get("/policy", response_model=SandboxPolicyResponse)
async def policy() -> SandboxPolicyResponse:
    return get_dynamic_analysis_service().policy()


@router.get("/sessions/{scan_id}", response_model=SandboxSessionResponse)
async def session(scan_id: str) -> SandboxSessionResponse:
    return get_dynamic_analysis_service().session_for_scan(scan_id)


@router.get("/sessions/{scan_id}/events", response_model=SandboxEventListResponse)
async def events(scan_id: str) -> SandboxEventListResponse:
    return get_dynamic_analysis_service().events_for_scan(scan_id)

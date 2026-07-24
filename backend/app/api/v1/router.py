from fastapi import APIRouter

from app.api.v1.endpoints import health, history, integrations, reports, scans

router = APIRouter()
router.include_router(health.router)
router.include_router(scans.router)
router.include_router(history.router)
router.include_router(integrations.router)
router.include_router(reports.router)

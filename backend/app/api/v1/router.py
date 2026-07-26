from fastapi import APIRouter

from app.api.v1.endpoints import dynamic_analysis, health, history, integrations, jobs, reports, scans, static_analysis

router = APIRouter()
router.include_router(health.router)
router.include_router(jobs.router)
router.include_router(scans.router)
router.include_router(history.router)
router.include_router(integrations.router)
router.include_router(reports.router)

router.include_router(static_analysis.router)
router.include_router(dynamic_analysis.router)

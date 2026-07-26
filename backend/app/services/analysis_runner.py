"""Analysis execution isolation and timeout controls."""

from __future__ import annotations

import logging
import multiprocessing
import queue
from dataclasses import dataclass
from pathlib import Path
from time import monotonic, sleep
from typing import Callable

from app.schemas.scan import ScanResponse
from app.services.upload_service import UploadArtifact

log = logging.getLogger("apkguard.analysis_runner")


class AnalysisTimedOutError(TimeoutError):
    pass


class AnalysisCancelledError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class AnalysisRequest:
    scan_id: str
    request_id: str
    filename: str
    artifact_path: Path
    sha256: str
    size_bytes: int
    zip_entry_count: int
    total_uncompressed_bytes: int
    execution_mode: str


def _run_analysis_child(request: AnalysisRequest, output_queue) -> None:
    try:
        from app.dependencies import get_scan_service

        artifact = UploadArtifact(
            original_filename=request.filename,
            temporary_path=request.artifact_path,
            sha256=request.sha256,
            size_bytes=request.size_bytes,
            zip_entry_count=request.zip_entry_count,
            total_uncompressed_bytes=request.total_uncompressed_bytes,
        )
        result = get_scan_service().analyze(
            artifact,
            request.request_id,
            scan_id=request.scan_id,
            execution_mode=request.execution_mode,
            allow_cache=False,
            record_legacy_history=False,
        )
        output_queue.put({"ok": True, "result": result.model_dump(mode="json")})
    except Exception as exc:
        output_queue.put({"ok": False, "error_type": type(exc).__name__, "message": str(exc)})


def _recover_dynamic_session(scan_id: str) -> None:
    """Best-effort emulator teardown after forcibly stopping an analysis child."""
    try:
        from app.dependencies import get_dynamic_analysis_service

        get_dynamic_analysis_service().recover_scan_session(scan_id)
    except Exception as exc:
        # The scan job state still records cancellation/timeout; stale-session
        # recovery on worker startup is the second cleanup boundary.
        log.warning("Immediate sandbox recovery failed scan_id=%s: %s", scan_id, exc)


class InlineAnalysisRunner:
    def __init__(self, scan_service) -> None:
        self.scan_service = scan_service

    def run(
        self,
        request: AnalysisRequest,
        *,
        timeout_seconds: int,
        cancel_check: Callable[[], bool],
        heartbeat: Callable[[], None],
    ) -> ScanResponse:
        del timeout_seconds
        if cancel_check():
            raise AnalysisCancelledError("Analysis cancelled before execution.")
        heartbeat()
        artifact = UploadArtifact(
            original_filename=request.filename,
            temporary_path=request.artifact_path,
            sha256=request.sha256,
            size_bytes=request.size_bytes,
            zip_entry_count=request.zip_entry_count,
            total_uncompressed_bytes=request.total_uncompressed_bytes,
        )
        result = self.scan_service.analyze(
            artifact,
            request.request_id,
            scan_id=request.scan_id,
            execution_mode=request.execution_mode,
            allow_cache=False,
            record_legacy_history=False,
        )
        heartbeat()
        if cancel_check():
            raise AnalysisCancelledError("Cancellation requested before result persistence.")
        return result


class SubprocessAnalysisRunner:
    """Hard timeout/cancellation boundary used by the Redis worker deployment."""

    def run(
        self,
        request: AnalysisRequest,
        *,
        timeout_seconds: int,
        cancel_check: Callable[[], bool],
        heartbeat: Callable[[], None],
    ) -> ScanResponse:
        context = multiprocessing.get_context("spawn")
        output_queue = context.Queue(maxsize=1)
        process = context.Process(target=_run_analysis_child, args=(request, output_queue), daemon=True)
        process.start()
        deadline = monotonic() + timeout_seconds
        payload = None
        try:
            while process.is_alive() and payload is None:
                if cancel_check():
                    process.terminate()
                    process.join(timeout=5)
                    _recover_dynamic_session(request.scan_id)
                    raise AnalysisCancelledError("Analysis subprocess terminated after cancellation request.")
                if monotonic() >= deadline:
                    process.terminate()
                    process.join(timeout=5)
                    _recover_dynamic_session(request.scan_id)
                    raise AnalysisTimedOutError(f"Analysis exceeded {timeout_seconds} seconds.")
                heartbeat()
                try:
                    payload = output_queue.get(timeout=0.25)
                except queue.Empty:
                    sleep(0.05)
            process.join(timeout=5)
            if payload is None:
                try:
                    payload = output_queue.get(timeout=2)
                except queue.Empty as exc:
                    raise RuntimeError("Analysis subprocess exited without a result.") from exc
            if not payload.get("ok"):
                raise RuntimeError(
                    f"{payload.get('error_type', 'AnalysisError')}: {payload.get('message', 'Unknown failure')}"
                )
            return ScanResponse.model_validate(payload["result"])
        finally:
            if process.is_alive():
                process.terminate()
                process.join(timeout=5)
            output_queue.close()

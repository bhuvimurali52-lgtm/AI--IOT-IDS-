"""HTTP routes for the IoT IDS API (Phase 1–8)."""

from __future__ import annotations

import logging
from typing import Any, Literal

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from app.core.errors import filter_public_mapping, sanitize_public_message
from app.services.runtime import get_runtime

logger = logging.getLogger(__name__)

router = APIRouter()


def _safe_http(
    status_code: int,
    message: str,
    *,
    fallback: str,
) -> HTTPException:
    logger.warning("API error status=%s", status_code)
    return HTTPException(
        status_code=status_code,
        detail=sanitize_public_message(str(message), fallback=fallback),
    )


class CaptureStartRequest(BaseModel):
    """Optional overrides for a capture session (validated; no shell execution)."""

    mode: Literal["synthetic", "live"] | None = None
    duration: float | None = Field(default=None, ge=0.1, le=300.0)
    packet_count: int | None = Field(default=None, ge=1, le=100000)
    interface: str | None = Field(default=None, max_length=128)
    bpf_filter: str | None = Field(default=None, max_length=256)
    flow_timeout_seconds: float | None = Field(default=None, ge=0.5, le=300.0)


@router.get("/health")
def health() -> dict[str, str]:
    """Liveness probe (process is up). Does not check model or database."""
    return {"status": "ok", "service": "iot-ids"}


@router.get("/ready")
def ready() -> JSONResponse:
    """Readiness: model loadable and database reachable. Does not retrain."""
    payload = filter_public_mapping(get_runtime().readiness())
    status_code = 200 if payload.get("ready") else 503
    return JSONResponse(status_code=status_code, content=payload)


@router.get("/api/status")
def api_status() -> dict[str, Any]:
    """Return IDS runtime status and counters."""
    return filter_public_mapping(get_runtime().status())


@router.get("/api/model")
def api_model() -> dict[str, Any]:
    """Return loaded model metadata and the exact 11-feature contract."""
    return get_runtime().model_info()


@router.get("/api/alerts")
def api_alerts(
    limit: int = Query(default=50, ge=1, le=500),
    mode: Literal["LIVE", "SYNTHETIC"] | None = None,
) -> dict[str, Any]:
    """Return recent alerts (optional mode filter)."""
    runtime = get_runtime()
    return {"alerts": runtime.db.list_alerts(limit=limit, mode=mode)}


@router.get("/api/flows")
def api_flows(
    limit: int = Query(default=50, ge=1, le=500),
    mode: Literal["LIVE", "SYNTHETIC"] | None = None,
) -> dict[str, Any]:
    """Return recent scored flows (optional mode filter)."""
    runtime = get_runtime()
    return {"flows": runtime.db.list_flows(limit=limit, mode=mode)}


@router.get("/api/explanation/{flow_id}")
def api_explanation(flow_id: int) -> dict[str, Any]:
    """Explain a persisted flow's IsolationForest anomaly score (local XAI).

    Uses the loaded model without retraining. Contributions are a local
    baseline-occlusion approximation — not causal attack attribution.
    """
    if flow_id < 1:
        raise HTTPException(status_code=422, detail="flow_id must be >= 1")
    runtime = get_runtime()
    try:
        return runtime.explain_flow(flow_id)
    except KeyError as exc:
        raise _safe_http(404, str(exc), fallback="Flow not found") from exc
    except ValueError as exc:
        raise _safe_http(400, str(exc), fallback="Invalid explanation request") from exc
    except RuntimeError as exc:
        raise _safe_http(503, str(exc), fallback="Model is not available") from exc
    except Exception:  # noqa: BLE001
        logger.exception("Explanation failed")
        raise HTTPException(status_code=500, detail="Explanation failed") from None


@router.get("/api/evaluation")
def api_evaluation(
    force: bool = Query(
        default=False,
        description="If true, recompute evaluation instead of returning cache.",
    ),
) -> dict[str, Any]:
    """Return controlled synthetic offline evaluation metrics (no retrain)."""
    runtime = get_runtime()
    try:
        return runtime.run_controlled_evaluation(force=force)
    except FileNotFoundError as exc:
        raise _safe_http(503, str(exc), fallback="Model is not available") from exc
    except Exception:  # noqa: BLE001
        logger.exception("Evaluation failed")
        raise HTTPException(status_code=500, detail="Evaluation failed") from None


@router.post("/api/capture/start")
def api_capture_start(body: CaptureStartRequest | None = None) -> dict[str, Any]:
    """Start capture/detection according to IDS_MODE (or request override)."""
    runtime = get_runtime()
    if body is not None:
        if body.mode is not None:
            runtime.settings.ids_mode = body.mode
        if body.duration is not None:
            runtime.settings.capture_duration = body.duration
        if body.packet_count is not None:
            runtime.settings.capture_packet_count = body.packet_count
        if body.interface is not None:
            runtime.settings.capture_interface = body.interface or None
        if body.bpf_filter is not None:
            runtime.settings.capture_bpf_filter = body.bpf_filter or None
        if body.flow_timeout_seconds is not None:
            runtime.settings.flow_timeout_seconds = body.flow_timeout_seconds
    try:
        return runtime.start_capture()
    except Exception as exc:  # noqa: BLE001
        logger.exception("Capture start failed")
        raise _safe_http(500, str(exc), fallback="Capture start failed") from exc


@router.post("/api/capture/stop")
def api_capture_stop() -> dict[str, Any]:
    """Stop an active capture session and flush open flows."""
    return get_runtime().stop_capture()


@router.post("/api/detection/test")
def api_detection_test() -> dict[str, Any]:
    """Run detection on synthetic fixtures (never claims live traffic)."""
    try:
        return get_runtime().run_detection_test()
    except Exception as exc:  # noqa: BLE001
        logger.exception("Detection test failed")
        raise _safe_http(500, str(exc), fallback="Detection test failed") from exc

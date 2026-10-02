"""HTTP client for the IDS FastAPI service (dashboard → API)."""

from __future__ import annotations

import logging
from typing import Any

import httpx

from app.core.config import Settings, get_settings

logger = logging.getLogger(__name__)


class DashboardAPIClient:
    """Thin client over existing Phase 4 API endpoints."""

    def __init__(
        self,
        base_url: str | None = None,
        *,
        settings: Settings | None = None,
        timeout: float = 5.0,
    ) -> None:
        cfg = settings or get_settings()
        self.base_url = (base_url or cfg.resolved_dashboard_api_url()).rstrip("/")
        self.timeout = timeout

    def _get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        url = f"{self.base_url}{path}"
        try:
            with httpx.Client(timeout=self.timeout) as client:
                response = client.get(url, params=params)
                response.raise_for_status()
                data = response.json()
                if not isinstance(data, dict):
                    raise ValueError("Malformed API response (expected object)")
                return data
        except Exception as exc:  # noqa: BLE001
            logger.warning("API GET %s failed: %s", path, exc)
            raise

    def _post(
        self, path: str, json_body: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        url = f"{self.base_url}{path}"
        try:
            with httpx.Client(timeout=max(self.timeout, 30.0)) as client:
                response = client.post(url, json=json_body or {})
                response.raise_for_status()
                data = response.json()
                if not isinstance(data, dict):
                    raise ValueError("Malformed API response (expected object)")
                return data
        except Exception as exc:  # noqa: BLE001
            logger.warning("API POST %s failed: %s", path, exc)
            raise

    def health(self) -> tuple[bool, dict[str, Any]]:
        try:
            data = self._get("/health")
            online = str(data.get("status", "")).lower() == "ok"
            return online, data
        except Exception:  # noqa: BLE001
            return False, {}

    def status(self) -> dict[str, Any]:
        return self._get("/api/status")

    def model(self) -> dict[str, Any]:
        return self._get("/api/model")

    def flows(
        self, *, limit: int = 200, mode: str | None = None
    ) -> list[dict[str, Any]]:
        params: dict[str, Any] = {"limit": int(limit)}
        if mode in {"LIVE", "SYNTHETIC"}:
            params["mode"] = mode
        data = self._get("/api/flows", params=params)
        flows = data.get("flows", [])
        return flows if isinstance(flows, list) else []

    def alerts(
        self, *, limit: int = 200, mode: str | None = None
    ) -> list[dict[str, Any]]:
        params: dict[str, Any] = {"limit": int(limit)}
        if mode in {"LIVE", "SYNTHETIC"}:
            params["mode"] = mode
        data = self._get("/api/alerts", params=params)
        alerts = data.get("alerts", [])
        return alerts if isinstance(alerts, list) else []

    def start_capture(self, body: dict[str, Any] | None = None) -> dict[str, Any]:
        return self._post("/api/capture/start", body)

    def stop_capture(self) -> dict[str, Any]:
        return self._post("/api/capture/stop")

    def run_synthetic_test(self) -> dict[str, Any]:
        return self._post("/api/detection/test")

    def explanation(self, flow_id: int) -> dict[str, Any]:
        return self._get(f"/api/explanation/{int(flow_id)}")

    def evaluation(self, *, force: bool = False) -> dict[str, Any]:
        return self._get("/api/evaluation", params={"force": bool(force)})

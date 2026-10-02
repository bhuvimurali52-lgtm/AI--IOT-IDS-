"""Shared IDS runtime for API and dashboard (Phase 3 + Phase 4)."""

from __future__ import annotations

import logging
import queue
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from app.capture.packet_capture import CapturedPacket, CaptureError, PacketCapture
from app.capture.synthetic import (
    generate_synthetic_flow_records,
    generate_synthetic_packets,
)
from app.core.config import Settings, get_settings
from app.database.models import IDSDatabase
from app.detection.anomaly_detector import AnomalyDetector
from app.detection.live_detector import LiveDetector
from app.detection.predictor import Predictor
from app.features.extractor import MODEL_FEATURE_ORDER
from app.features.flow_aggregator import FlowAggregator

logger = logging.getLogger(__name__)

LIVE_CAPTURE_BANNER = "LIVE CAPTURE MODE"
LIVE_AUTH_NOTICE = (
    "Live capture monitors traffic visible to the selected local network "
    "interface. Use only on systems/networks you are authorized to monitor."
)


@dataclass
class RuntimeState:
    capture_running: bool = False
    capture_mode_active: str | None = None  # "LIVE" while sniffing
    last_capture_mode: str = "synthetic"
    last_capture_error: str | None = None
    last_packet_count: int = 0
    last_flow_count: int = 0
    live_packets_queued: int = 0
    live_flows_processed: int = 0
    live_flows_rejected: int = 0


class IDSRuntime:
    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self.db = IDSDatabase(self.settings.database_path)
        self.state = RuntimeState(last_capture_mode=self.settings.ids_mode)
        self._lock = threading.Lock()
        self._capture: PacketCapture | None = None
        self._predictor: Predictor | None = None
        self._live_detector: LiveDetector | None = None
        self._packet_queue: queue.Queue[CapturedPacket | None] = queue.Queue()
        self._worker_thread: threading.Thread | None = None
        self._worker_stop = threading.Event()
        self._aggregator: FlowAggregator | None = None
        self._last_evaluation: dict[str, Any] | None = None

    def get_predictor(self) -> Predictor:
        if self._predictor is None:
            detector = None
            model_path = Path(self.settings.model_path)
            if model_path.exists():
                detector = AnomalyDetector.load(model_path)
            self._predictor = Predictor(
                detector=detector,
                settings=self.settings,
                database=self.db,
            )
        return self._predictor

    def get_live_detector(self) -> LiveDetector:
        if self._live_detector is None:
            self._live_detector = LiveDetector(
                settings=self.settings,
                database=self.db,
            )
            model_path = Path(self.settings.model_path)
            if model_path.exists():
                self._live_detector.load_model(model_path)
        return self._live_detector

    def model_info(self) -> dict[str, Any]:
        path = Path(self.settings.model_path)
        loaded = False
        n_samples = 0
        feature_names: list[str] = list(MODEL_FEATURE_ORDER)
        contamination = float(self.settings.anomaly_contamination)
        n_estimators = int(self.settings.n_estimators)
        random_state = int(self.settings.random_state)
        try:
            predictor = self.get_predictor()
            if predictor.detector is not None and predictor.detector.is_fitted:
                loaded = True
                det = predictor.detector
                n_samples = int(det.n_training_samples or 0)
                if det.feature_names:
                    feature_names = list(det.feature_names)
                contamination = float(det.contamination)
                n_estimators = int(det.n_estimators)
                random_state = int(det.random_state)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Model info load issue: %s", exc)
        return {
            "model_loaded": loaded and path.exists(),
            "model_path": str(path),
            "model_exists": path.exists(),
            "model_type": "Isolation Forest",
            "n_training_samples": n_samples,
            "n_features": len(feature_names),
            "feature_order": feature_names,
            "model_feature_order": list(MODEL_FEATURE_ORDER),
            "contamination": contamination,
            "n_estimators": n_estimators,
            "random_state": random_state,
            "limitation": (
                "The IsolationForest was trained on a synthetic normal baseline. "
                "It detects deviations from that learned flow-behavior baseline — "
                "not named real-world attack classes."
            ),
        }

    def status(self) -> dict[str, Any]:
        stats = self.db.stats()
        model = self.model_info()
        capture_display = "Running" if self.state.capture_running else "Stopped"
        active_mode = self.state.capture_mode_active
        if active_mode is None:
            active_mode = str(self.settings.ids_mode).upper()
        return {
            "app": self.settings.app_name,
            "version": self.settings.app_version,
            "ids_mode": self.settings.ids_mode,
            "capture_running": self.state.capture_running,
            "capture_status": capture_display,
            "capture_mode": active_mode,
            "live_capture_banner": LIVE_CAPTURE_BANNER
            if self.state.capture_mode_active == "LIVE"
            else None,
            "last_capture_mode": self.state.last_capture_mode,
            "last_capture_error": self.state.last_capture_error,
            "last_packet_count": self.state.last_packet_count,
            "last_flow_count": self.state.last_flow_count,
            "live_packets_queued": self.state.live_packets_queued,
            "live_flows_processed": self.state.live_flows_processed,
            "live_flows_rejected": self.state.live_flows_rejected,
            "flow_timeout_seconds": self.settings.flow_timeout_seconds,
            "capture_interface": self.settings.capture_interface,
            "risk_low_max": self.settings.risk_low_max,
            "risk_medium_max": self.settings.risk_medium_max,
            "risk_high_max": self.settings.risk_high_max,
            "database_status": "ok",
            "database_path": str(self.settings.database_path),
            "privilege_note": PacketCapture.PRIVILEGE_HELP,
            "authorization_notice": LIVE_AUTH_NOTICE,
            "model_loaded": model["model_loaded"],
            "model_path": model["model_path"],
            "flows_count": stats["total_flows"],
            "alerts_count": stats["alert_count"],
            **stats,
            **{k: v for k, v in model.items() if k not in {"model_loaded", "model_path"}},
        }

    def start_capture(self) -> dict[str, Any]:
        with self._lock:
            if self.state.capture_running:
                return {
                    "ok": False,
                    "error": "Capture already running",
                    **self.status(),
                }

            mode = self.settings.ids_mode
            self.state.capture_running = True
            self.state.last_capture_mode = mode
            self.state.last_capture_error = None

            try:
                if mode == "synthetic":
                    return self._start_synthetic()
                return self._start_live()
            except Exception as exc:  # noqa: BLE001
                logger.exception("Capture failed")
                self.state.capture_running = False
                self.state.capture_mode_active = None
                self.state.last_capture_error = str(exc)
                return {"ok": False, "error": str(exc), **self.status()}

    def _start_synthetic(self) -> dict[str, Any]:
        self.state.capture_mode_active = "SYNTHETIC"
        packets = generate_synthetic_packets()
        flows = generate_synthetic_flow_records(n_normal=20, n_anomalous=5)
        self.state.last_packet_count = len(packets)
        self.state.last_flow_count = len(flows)
        detector = self.get_live_detector()
        # Ensure synthetic flows carry mode markers.
        for flow in flows:
            flow.setdefault("data_source", "synthetic")
            flow.setdefault("mode", "SYNTHETIC")
        predictions = detector.process_flows(flows)
        self.state.capture_running = False
        self.state.capture_mode_active = None
        return {
            "ok": True,
            "mode": "synthetic",
            "capture_mode": "SYNTHETIC",
            "warning": (
                "SYNTHETIC MODE: results are local fixtures, "
                "not real captured packets."
            ),
            "packets": len(packets),
            "flows": len(flows),
            "predictions": predictions,
            **self.status(),
        }

    def _enqueue_packet(self, packet: CapturedPacket) -> None:
        """Lightweight sniff callback — queue only, no ML/DB."""
        try:
            self._packet_queue.put_nowait(packet)
            self.state.live_packets_queued += 1
            self.state.last_packet_count += 1
        except queue.Full:
            logger.warning("Packet queue full; dropping packet")

    def _live_worker_loop(self) -> None:
        assert self._aggregator is not None
        timeout = float(self.settings.flow_timeout_seconds)
        detector = self.get_live_detector()
        logger.info(
            "%s worker started | flow_timeout=%.2fs", LIVE_CAPTURE_BANNER, timeout
        )
        while not self._worker_stop.is_set():
            try:
                item = self._packet_queue.get(timeout=0.25)
            except queue.Empty:
                item = None
            if item is None and self._worker_stop.is_set():
                break
            if isinstance(item, CapturedPacket):
                self._aggregator.add_packet(item)
            # Complete idle flows without waiting forever.
            completed = self._aggregator.pop_idle_flows(timeout)
            if completed:
                results = detector.process_flows([f.to_dict() for f in completed])
                self.state.live_flows_processed += len(results)
                self.state.live_flows_rejected = detector.rejected_flows
                self.state.last_flow_count += len(results)

        # Drain remaining queued packets then flush open flows.
        while True:
            try:
                item = self._packet_queue.get_nowait()
            except queue.Empty:
                break
            if isinstance(item, CapturedPacket):
                self._aggregator.add_packet(item)
        flushed = self._aggregator.flush_all()
        if flushed:
            results = detector.process_flows([f.to_dict() for f in flushed])
            self.state.live_flows_processed += len(results)
            self.state.last_flow_count += len(results)
        logger.info("%s worker stopped", LIVE_CAPTURE_BANNER)

    def _start_live(self) -> dict[str, Any]:
        # Clear queue leftovers from prior sessions.
        while not self._packet_queue.empty():
            try:
                self._packet_queue.get_nowait()
            except queue.Empty:
                break

        self._aggregator = FlowAggregator(data_source="live")
        self._worker_stop.clear()
        self.state.live_packets_queued = 0
        self.state.live_flows_processed = 0
        self.state.last_packet_count = 0
        self.state.last_flow_count = 0
        self.state.capture_mode_active = "LIVE"

        # Ensure model is loaded once before sniffing starts.
        try:
            self.get_live_detector()._ensure_ready()
        except Exception as exc:  # noqa: BLE001
            self.state.capture_running = False
            self.state.capture_mode_active = None
            self.state.last_capture_error = str(exc)
            return {
                "ok": False,
                "mode": "live",
                "error": f"Model not available for live detection: {exc}",
                "authorization_notice": LIVE_AUTH_NOTICE,
                **self.status(),
            }

        capture = PacketCapture(
            mode="live",
            interface=self.settings.capture_interface,
            duration=self.settings.capture_duration,
            packet_count=self.settings.capture_packet_count,
            bpf_filter=self.settings.capture_bpf_filter,
        )
        self._capture = capture

        self._worker_thread = threading.Thread(
            target=self._live_worker_loop,
            name="iot-ids-live-worker",
            daemon=True,
        )
        self._worker_thread.start()

        try:
            capture.start_async(on_packet=self._enqueue_packet)
        except CaptureError as exc:
            self.state.last_capture_error = str(exc)
            self._stop_capture_unlocked()
            return {
                "ok": False,
                "mode": "live",
                "error": str(exc),
                "authorization_notice": LIVE_AUTH_NOTICE,
                "privilege_note": PacketCapture.PRIVILEGE_HELP,
                **self.status(),
            }

        # Poll briefly so immediate Npcap/permission/interface failures surface.
        deadline = time.time() + 1.5
        while time.time() < deadline:
            if capture.last_error:
                break
            thread = getattr(capture, "_thread", None)
            if thread is None:
                # No sniffer thread (e.g. unit-test mock of start_async).
                break
            if not thread.is_alive() and not capture.is_running:
                if capture.last_error is None and self.state.last_packet_count == 0:
                    capture.last_error = (
                        "Live capture thread exited immediately without packets. "
                        + PacketCapture.PRIVILEGE_HELP
                    )
                break
            time.sleep(0.1)

        if capture.last_error:
            self.state.last_capture_error = capture.last_error
            self._stop_capture_unlocked()
            return {
                "ok": False,
                "mode": "live",
                "error": capture.last_error,
                "authorization_notice": LIVE_AUTH_NOTICE,
                "privilege_note": PacketCapture.PRIVILEGE_HELP,
                "live_capture_banner": LIVE_CAPTURE_BANNER,
                **self.status(),
            }

        logger.info("%s session active (background)", LIVE_CAPTURE_BANNER)
        return {
            "ok": True,
            "mode": "live",
            "capture_mode": "LIVE",
            "live_capture_banner": LIVE_CAPTURE_BANNER,
            "authorization_notice": LIVE_AUTH_NOTICE,
            "privilege_note": PacketCapture.PRIVILEGE_HELP,
            "message": (
                f"{LIVE_CAPTURE_BANNER} started. Flows complete after "
                f"{self.settings.flow_timeout_seconds}s idle timeout. "
                "Call /api/capture/stop to flush remaining flows."
            ),
            "warning": (
                "Baseline was trained on synthetic normal traffic; live labels "
                "mean deviation from that baseline, not named attack types."
            ),
            **self.status(),
        }

    def _stop_capture_unlocked(self) -> dict[str, Any]:
        """Stop capture/worker. Caller must hold ``self._lock`` when needed."""
        capture_err = None
        if self._capture is not None:
            capture_err = self._capture.last_error
            self._capture.stop()
        if capture_err:
            self.state.last_capture_error = capture_err
        self._worker_stop.set()
        try:
            self._packet_queue.put_nowait(None)
        except queue.Full:
            pass
        if self._worker_thread is not None and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=8.0)
        self._worker_thread = None
        self._capture = None
        self.state.capture_running = False
        self.state.capture_mode_active = None
        return {
            "ok": True,
            "message": "Capture stop requested; open flows flushed for analysis",
            "last_capture_error": self.state.last_capture_error,
            **self.status(),
        }

    def stop_capture(self) -> dict[str, Any]:
        with self._lock:
            return self._stop_capture_unlocked()

    def run_detection_test(self) -> dict[str, Any]:
        flows = generate_synthetic_flow_records(n_normal=5, n_anomalous=5)
        for flow in flows:
            flow.setdefault("data_source", "synthetic")
            flow.setdefault("mode", "SYNTHETIC")
        detector = self.get_live_detector()
        predictions = detector.process_flows(flows)
        anomalous = [p for p in predictions if p.get("is_anomaly")]
        return {
            "ok": True,
            "mode": "synthetic",
            "warning": (
                "DETECTION TEST uses SYNTHETIC fixtures only — "
                "not real network packets."
            ),
            "flows_scored": len(predictions),
            "anomalies_flagged": len(anomalous),
            "predictions": predictions,
            **self.status(),
        }

    def _score_flows(self, flows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Legacy helper used by older call sites; routes through LiveDetector."""
        return self.get_live_detector().process_flows(flows)

    def explain_flow(self, flow_id: int) -> dict[str, Any]:
        """Explain a persisted flow using the loaded IsolationForest (no retrain)."""
        from app.dashboard.services.metrics import parse_features
        from app.explainability.explainer import ExplanationError, explain_anomaly
        from app.features.extractor import MODEL_FEATURE_ORDER, flow_record_to_feature_dict

        row = self.db.get_flow(int(flow_id))
        if row is None:
            raise KeyError(f"Flow id {flow_id} not found")

        stored = parse_features(row)
        merged = dict(row)
        merged.update(stored)
        feats = flow_record_to_feature_dict(merged)
        # Ensure exact model keys exist.
        for name in MODEL_FEATURE_ORDER:
            feats.setdefault(name, 0.0)

        predictor = self.get_predictor()
        if predictor.detector is None or not predictor.detector.is_fitted:
            raise RuntimeError(
                "No fitted IsolationForest is loaded. Cannot explain this flow."
            )

        from app.core.timing import log_duration

        try:
            with log_duration("xai_explain_flow"):
                explanation = explain_anomaly(predictor.detector, feats)
        except ExplanationError as exc:
            raise ValueError(str(exc)) from exc

        return {
            "flow_id": int(flow_id),
            "source_ip": row.get("source_ip"),
            "destination_ip": row.get("destination_ip"),
            "protocol": row.get("protocol"),
            "mode": row.get("mode"),
            "is_anomaly": bool(row.get("is_anomaly")),
            "stored_anomaly_score": row.get("anomaly_score"),
            "risk_score": row.get("risk_score"),
            "severity": row.get("severity"),
            "explanation": explanation,
        }

    def readiness(self) -> dict[str, Any]:
        """Runtime readiness without retraining or capturing packets."""
        from pathlib import Path

        model_path = Path(self.settings.model_path)
        model_exists = model_path.exists()
        model_loaded = False
        database_available = False
        try:
            info = self.model_info()
            model_loaded = bool(info.get("model_loaded")) and model_exists
        except Exception:  # noqa: BLE001
            logger.exception("Readiness model check failed")
        try:
            self.db.stats()
            database_available = True
        except Exception:  # noqa: BLE001
            logger.warning("Readiness database check failed")

        live_mode = str(self.settings.ids_mode).lower() == "live"
        live_capture_required = live_mode
        live_capture_available = False
        if live_mode:
            from app.capture.packet_capture import PacketCapture

            live_preflight = PacketCapture.preflight_live()
            live_capture_available = live_preflight is None
        ready = bool(model_loaded and database_available)
        return {
            "ready": ready,
            "alive": True,
            "model_loaded": model_loaded,
            "model_exists": model_exists,
            "database_available": database_available,
            "ids_mode": self.settings.ids_mode,
            "live_capture_available": live_capture_available,
            "live_capture_required": live_capture_required,
            "note": (
                "GET /ready checks whether the existing IsolationForest artifact "
                "can be loaded and the database is reachable. It does not retrain. "
                "GET /health is liveness only. Live capture is optional in synthetic mode."
            ),
        }

    def run_controlled_evaluation(self, *, force: bool = False) -> dict[str, Any]:
        """Run deterministic offline evaluation without retraining.

        Results are cached on the runtime so dashboards can fetch without
        regenerating on every refresh unless ``force=True``.
        """
        from app.core.timing import log_duration
        from app.evaluation.evaluator import run_offline_evaluation

        if (
            not force
            and getattr(self, "_last_evaluation", None) is not None
        ):
            return dict(self._last_evaluation)

        with log_duration("offline_evaluation"):
            result = run_offline_evaluation(model_path=self.settings.model_path)
        self._last_evaluation = result
        return dict(result)


_RUNTIME: IDSRuntime | None = None


def get_runtime() -> IDSRuntime:
    global _RUNTIME
    if _RUNTIME is None:
        _RUNTIME = IDSRuntime()
    return _RUNTIME

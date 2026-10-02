"""SQLite persistence for flows, alerts, and model metadata."""

from __future__ import annotations

import json
import logging
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Mapping

logger = logging.getLogger(__name__)

SCHEMA = """
CREATE TABLE IF NOT EXISTS flows (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    source_ip TEXT,
    destination_ip TEXT,
    source_port INTEGER,
    destination_port INTEGER,
    protocol TEXT,
    is_anomaly INTEGER NOT NULL,
    anomaly_score REAL,
    risk_score INTEGER,
    severity TEXT,
    data_source TEXT,
    mode TEXT,
    features_json TEXT
);
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    source_ip TEXT,
    destination_ip TEXT,
    protocol TEXT,
    risk_score INTEGER,
    anomaly_score REAL,
    severity TEXT,
    message TEXT,
    data_source TEXT,
    mode TEXT,
    is_synthetic INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS model_metadata (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    model_path TEXT,
    training_mode TEXT,
    n_samples INTEGER,
    n_features INTEGER,
    contamination REAL,
    random_state INTEGER,
    notes TEXT
);
"""

_FLOW_COLUMNS = {
    "source_port": "INTEGER",
    "destination_port": "INTEGER",
    "severity": "TEXT",
    "mode": "TEXT",
}
_ALERT_COLUMNS = {
    "mode": "TEXT",
}


class IDSDatabase:
    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.initialize()

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def initialize(self) -> None:
        with self.connect() as conn:
            conn.executescript(SCHEMA)
            self._migrate(conn)
        logger.info("Database ready: %s", self.path.resolve())

    def _migrate(self, conn: sqlite3.Connection) -> None:
        """Add Phase 4 columns to existing Phase 3 databases."""
        flow_cols = {
            row[1] for row in conn.execute("PRAGMA table_info(flows)").fetchall()
        }
        for name, coltype in _FLOW_COLUMNS.items():
            if name not in flow_cols:
                conn.execute(f"ALTER TABLE flows ADD COLUMN {name} {coltype}")
                logger.info("Migrated flows.%s", name)
        alert_cols = {
            row[1] for row in conn.execute("PRAGMA table_info(alerts)").fetchall()
        }
        for name, coltype in _ALERT_COLUMNS.items():
            if name not in alert_cols:
                conn.execute(f"ALTER TABLE alerts ADD COLUMN {name} {coltype}")
                logger.info("Migrated alerts.%s", name)

    @staticmethod
    def _resolve_mode(record: Mapping[str, Any]) -> str:
        mode = record.get("mode")
        if mode:
            return str(mode).upper()
        source = str(record.get("data_source", "synthetic")).lower()
        return "SYNTHETIC" if source == "synthetic" else "LIVE"

    def insert_flow(self, record: Mapping[str, Any]) -> int:
        mode = self._resolve_mode(record)
        data_source = str(record.get("data_source") or mode.lower())
        with self.connect() as conn:
            cur = conn.execute(
                """
                INSERT INTO flows (
                    timestamp, source_ip, destination_ip,
                    source_port, destination_port, protocol,
                    is_anomaly, anomaly_score, risk_score, severity,
                    data_source, mode, features_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.get("timestamp") or datetime.now(timezone.utc).isoformat(),
                    record.get("source_ip"),
                    record.get("destination_ip"),
                    int(float(record.get("source_port", 0) or 0)),
                    int(float(record.get("destination_port", 0) or 0)),
                    record.get("protocol"),
                    1 if record.get("is_anomaly") else 0,
                    record.get("anomaly_score"),
                    record.get("risk_score"),
                    record.get("severity"),
                    data_source,
                    mode,
                    json.dumps(record.get("features") or {}),
                ),
            )
            return int(cur.lastrowid)

    def insert_alert(self, record: Mapping[str, Any]) -> int:
        mode = self._resolve_mode(record)
        data_source = str(record.get("data_source") or mode.lower())
        is_synthetic = record.get("is_synthetic")
        if is_synthetic is None:
            is_synthetic = mode == "SYNTHETIC"
        with self.connect() as conn:
            cur = conn.execute(
                """
                INSERT INTO alerts (
                    timestamp, source_ip, destination_ip, protocol,
                    risk_score, anomaly_score, severity, message,
                    data_source, mode, is_synthetic
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.get("timestamp") or datetime.now(timezone.utc).isoformat(),
                    record.get("source_ip"),
                    record.get("destination_ip"),
                    record.get("protocol"),
                    record.get("risk_score"),
                    record.get("anomaly_score"),
                    record.get("severity"),
                    record.get("message"),
                    data_source,
                    mode,
                    1 if is_synthetic else 0,
                ),
            )
            return int(cur.lastrowid)

    def insert_model_metadata(self, record: Mapping[str, Any]) -> int:
        with self.connect() as conn:
            cur = conn.execute(
                """
                INSERT INTO model_metadata (
                    created_at, model_path, training_mode, n_samples,
                    n_features, contamination, random_state, notes
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.get("created_at") or datetime.now(timezone.utc).isoformat(),
                    record.get("model_path"),
                    record.get("training_mode"),
                    record.get("n_samples"),
                    record.get("n_features"),
                    record.get("contamination"),
                    record.get("random_state"),
                    record.get("notes"),
                ),
            )
            return int(cur.lastrowid)

    def get_flow(self, flow_id: int) -> dict[str, Any] | None:
        """Return a single flow by primary key, or None if missing."""
        with self.connect() as conn:
            row = conn.execute(
                "SELECT * FROM flows WHERE id = ?", (int(flow_id),)
            ).fetchone()
        if row is None:
            return None
        return self._normalize_flow_row(dict(row))

    def list_flows(
        self, limit: int = 100, *, mode: str | None = None
    ) -> list[dict[str, Any]]:
        with self.connect() as conn:
            if mode:
                rows = conn.execute(
                    "SELECT * FROM flows WHERE UPPER(COALESCE(mode, data_source)) = ? "
                    "ORDER BY id DESC LIMIT ?",
                    (str(mode).upper(), int(limit)),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM flows ORDER BY id DESC LIMIT ?", (int(limit),)
                ).fetchall()
        return [self._normalize_flow_row(dict(r)) for r in rows]

    def list_alerts(
        self, limit: int = 100, *, mode: str | None = None
    ) -> list[dict[str, Any]]:
        with self.connect() as conn:
            if mode:
                rows = conn.execute(
                    "SELECT * FROM alerts WHERE UPPER(COALESCE(mode, data_source)) = ? "
                    "ORDER BY id DESC LIMIT ?",
                    (str(mode).upper(), int(limit)),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (int(limit),)
                ).fetchall()
        return [self._normalize_alert_row(dict(r)) for r in rows]

    @staticmethod
    def _normalize_flow_row(row: dict[str, Any]) -> dict[str, Any]:
        mode = row.get("mode")
        if not mode:
            src = str(row.get("data_source", "")).lower()
            mode = "SYNTHETIC" if src == "synthetic" else "LIVE" if src else ""
        else:
            mode = str(mode).upper()
        row["mode"] = mode
        return row

    @staticmethod
    def _normalize_alert_row(row: dict[str, Any]) -> dict[str, Any]:
        mode = row.get("mode")
        if not mode:
            if row.get("is_synthetic"):
                mode = "SYNTHETIC"
            else:
                src = str(row.get("data_source", "")).lower()
                mode = "SYNTHETIC" if src == "synthetic" else "LIVE" if src else ""
        else:
            mode = str(mode).upper()
        row["mode"] = mode
        return row

    def stats(self) -> dict[str, Any]:
        with self.connect() as conn:
            total = conn.execute("SELECT COUNT(*) AS c FROM flows").fetchone()["c"]
            anomalous = conn.execute(
                "SELECT COUNT(*) AS c FROM flows WHERE is_anomaly=1"
            ).fetchone()["c"]
            alerts = conn.execute("SELECT COUNT(*) AS c FROM alerts").fetchone()["c"]
            max_risk = conn.execute(
                "SELECT COALESCE(MAX(risk_score),0) AS m FROM flows"
            ).fetchone()["m"]
            live_flows = conn.execute(
                "SELECT COUNT(*) AS c FROM flows WHERE UPPER(COALESCE(mode, data_source)) IN ('LIVE')"
            ).fetchone()["c"]
            synthetic_flows = conn.execute(
                "SELECT COUNT(*) AS c FROM flows WHERE UPPER(COALESCE(mode, data_source)) IN ('SYNTHETIC')"
            ).fetchone()["c"]
        return {
            "total_flows": int(total),
            "anomalous_flows": int(anomalous),
            "normal_flows": int(total) - int(anomalous),
            "alert_count": int(alerts),
            "max_risk_score": int(max_risk),
            "live_flows": int(live_flows),
            "synthetic_flows": int(synthetic_flows),
        }


def init_db(path: Path | str | None = None) -> IDSDatabase:
    if path is None:
        from app.core.config import get_settings

        path = get_settings().database_path
    return IDSDatabase(path)

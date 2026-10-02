"""Orchestrate read-only firewall collection and analysis."""

from __future__ import annotations

import logging
from typing import Any

from app.core.errors import filter_public_mapping, sanitize_public_message
from app.core.timing import log_duration
from app.firewall.analyzer import analyze_snapshot
from app.firewall.collector import FirewallCollector
from app.firewall.models import FirewallAssessment, FirewallSnapshot

logger = logging.getLogger(__name__)

_RAW_OUTPUT_MARKERS = (
    "profile settings",
    "firewall policy",
    "calledprocesserror",
    "completedprocess",
    "traceback",
    "stdout",
    "stderr",
)


def _looks_like_command_dump(text: str) -> bool:
    lowered = str(text or "").lower()
    return any(marker in lowered for marker in _RAW_OUTPUT_MARKERS)


def _public_text(value: str, *, fallback: str) -> str:
    raw = str(value or "")
    if _looks_like_command_dump(raw):
        return fallback
    return sanitize_public_message(raw, fallback=fallback)


def assessment_to_public_dict(assessment: FirewallAssessment) -> dict[str, Any]:
    """Serialize an assessment without raw command output or filesystem paths."""
    payload = filter_public_mapping(assessment.to_dict())
    payload["read_only"] = True
    payload["collection_errors"] = [
        _public_text(err, fallback="Firewall collection details omitted.")
        for err in payload.get("collection_errors") or []
    ]
    public_findings = []
    for finding in payload.get("findings") or []:
        if not isinstance(finding, dict):
            continue
        public_findings.append(
            {
                key: (
                    _public_text(str(val), fallback="Finding details omitted.")
                    if isinstance(val, str)
                    else val
                )
                for key, val in finding.items()
            }
        )
    payload["findings"] = public_findings
    if isinstance(payload.get("disclaimer"), str):
        payload["disclaimer"] = _public_text(
            payload["disclaimer"],
            fallback="Read-only security posture assessment.",
        )
    return payload


class FirewallChecker:
    """Read-only Windows firewall security posture checker."""

    def __init__(self, collector: FirewallCollector | None = None) -> None:
        self.collector = collector or FirewallCollector()

    def assess(self) -> FirewallAssessment:
        with log_duration("firewall_posture_assess"):
            snapshot = self.collector.collect()
            if not isinstance(snapshot, FirewallSnapshot):
                logger.warning("Collector returned unexpected payload type")
                snapshot = FirewallSnapshot(
                    platform="unknown",
                    assessed_at="",
                    collection_status="parse_failed",
                    firewall_available=False,
                    collection_errors=["Malformed firewall collector data."],
                )
            assessment = analyze_snapshot(snapshot)
        logger.info(
            "Firewall posture assessment | status=%s severity=%s findings=%d",
            assessment.status,
            assessment.overall_severity,
            assessment.finding_count,
        )
        return assessment

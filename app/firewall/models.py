"""Typed models for read-only Windows firewall posture assessment."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


SEVERITY_ORDER = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "INFORMATIONAL": 1,
    "NONE": 0,
}


@dataclass
class FirewallProfileStatus:
    name: str
    enabled: bool | None
    inbound_default: str | None
    outbound_default: str | None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class FirewallSnapshot:
    platform: str
    assessed_at: str
    collection_status: str
    firewall_available: bool
    profiles: list[FirewallProfileStatus] = field(default_factory=list)
    collection_errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "platform": self.platform,
            "assessed_at": self.assessed_at,
            "collection_status": self.collection_status,
            "firewall_available": self.firewall_available,
            "profiles": [p.to_dict() for p in self.profiles],
            "collection_errors": list(self.collection_errors),
        }


@dataclass
class FirewallFinding:
    id: str
    title: str
    severity: str
    category: str
    description: str
    observed_value: str
    expected_or_recommended_value: str
    remediation: str
    evidence_source: str
    explanation: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class FirewallAssessment:
    status: str
    assessed_at: str
    platform: str
    firewall_available: bool
    overall_severity: str
    profiles: list[FirewallProfileStatus]
    findings: list[FirewallFinding]
    finding_count: int
    collection_errors: list[str]
    read_only: bool = True
    disclaimer: str = (
        "Read-only security posture assessment. No firewall rules were created, "
        "modified, enabled, or disabled. This is not a replacement for enterprise "
        "firewall management, SIEM, EDR, or a certified vulnerability assessment."
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "assessed_at": self.assessed_at,
            "platform": self.platform,
            "firewall_available": self.firewall_available,
            "overall_severity": self.overall_severity,
            "profiles": [p.to_dict() for p in self.profiles],
            "findings": [f.to_dict() for f in self.findings],
            "finding_count": self.finding_count,
            "collection_errors": list(self.collection_errors),
            "read_only": self.read_only,
            "disclaimer": self.disclaimer,
        }

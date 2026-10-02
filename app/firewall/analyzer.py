"""Deterministic firewall posture analysis and AI-assisted explanations.

No LLM and no API keys. Explanations are rule-generated templates.
"""

from __future__ import annotations

from app.firewall.models import (
    SEVERITY_ORDER,
    FirewallAssessment,
    FirewallFinding,
    FirewallSnapshot,
)

_EVIDENCE = "netsh advfirewall show allprofiles"


def analyze_snapshot(snapshot: FirewallSnapshot) -> FirewallAssessment:
    """Produce deterministic findings from a structured snapshot."""
    findings: list[FirewallFinding] = []
    collected = snapshot.collection_status == "ok" and snapshot.firewall_available

    if not collected:
        findings.append(
            _finding(
                finding_id="FW-COLLECT-001",
                title="Unable to complete firewall status collection",
                severity="MEDIUM",
                category="collection",
                observed=snapshot.collection_status,
                expected="Successful local read of Windows firewall profile state",
                description=(
                    "The read-only collector could not obtain a complete Windows "
                    "firewall snapshot. Assessment is incomplete and must not be "
                    "interpreted as evidence that the host is secure."
                ),
                remediation=(
                    "Confirm this is a Windows host, that netsh is available, "
                    "and that the process may query firewall status. Re-run the "
                    "audit. Do not assume a failed collection means a safe posture."
                ),
            )
        )
    else:
        findings.extend(_profile_findings(snapshot))

    findings = _dedupe(findings)
    overall = _overall_severity(findings)
    if not collected:
        status = "incomplete"
    elif findings:
        status = "findings"
    else:
        status = "ok"

    return FirewallAssessment(
        status=status,
        assessed_at=snapshot.assessed_at,
        platform=snapshot.platform,
        firewall_available=snapshot.firewall_available,
        overall_severity=overall,
        profiles=list(snapshot.profiles),
        findings=findings,
        finding_count=len(findings),
        collection_errors=list(snapshot.collection_errors),
    )


def _profile_findings(snapshot: FirewallSnapshot) -> list[FirewallFinding]:
    findings: list[FirewallFinding] = []
    profiles = snapshot.profiles
    disabled = [p for p in profiles if p.enabled is False]
    enabled = [p for p in profiles if p.enabled is True]

    if profiles and len(disabled) == len(profiles) and not enabled:
        findings.append(
            _finding(
                finding_id="FW-DISABLED-001",
                title="Windows Firewall appears disabled on all profiles",
                severity="CRITICAL",
                category="availability",
                observed="All inspected profiles: disabled",
                expected="Firewall enabled on Domain, Private, and Public profiles",
                description=(
                    "Every inspected Windows firewall profile reports as disabled. "
                    "This is a potentially risky configuration: host filtering may "
                    "not be enforced."
                ),
                remediation=(
                    "Review why all profiles are off. A defender should restore "
                    "firewall enablement per organizational policy using the "
                    "Windows Firewall MMC or approved configuration management. "
                    "This checker does not enable the firewall."
                ),
            )
        )
    else:
        for profile in disabled:
            key = profile.name.lower()
            finding_id = {
                "public": "FW-PUBLIC-OFF-001",
                "private": "FW-PRIVATE-OFF-001",
                "domain": "FW-DOMAIN-OFF-001",
            }.get(key, f"FW-PROFILE-OFF-{profile.name.upper()}-001")
            findings.append(
                _finding(
                    finding_id=finding_id,
                    title=f"{profile.name} profile firewall is disabled",
                    severity="HIGH",
                    category="availability",
                    observed=f"{profile.name} state: disabled",
                    expected=f"{profile.name} profile firewall enabled",
                    description=(
                        f"The {profile.name} firewall profile is disabled. This is "
                        "a security posture finding: traffic on that profile may "
                        "not be filtered by the Windows firewall."
                    ),
                    remediation=(
                        f"Review the {profile.name} profile enablement against "
                        "policy. Re-enable via approved change control if required. "
                        "This checker does not change firewall settings."
                    ),
                )
            )

    inbound_allow = [
        p for p in profiles if (p.inbound_default or "").lower() == "allow"
    ]
    if inbound_allow:
        names = ", ".join(p.name for p in inbound_allow)
        findings.append(
            _finding(
                finding_id="FW-INBOUND-ALLOW-001",
                title="Inbound default policy permits traffic",
                severity="HIGH",
                category="default_policy",
                observed=f"Inbound default allow on: {names}",
                expected="Inbound default block (explicit allow rules only)",
                description=(
                    "One or more profiles use an inbound default policy of allow. "
                    "This is a potentially risky configuration because unsolicited "
                    "inbound traffic may be permitted unless other controls exist."
                ),
                remediation=(
                    "Review inbound defaults. Typical hardened Windows posture uses "
                    "BlockInbound with explicit allow rules. Confirm compensating "
                    "controls before changing production policy. This checker does "
                    "not modify rules."
                ),
            )
        )

    outbound_allow = [
        p for p in profiles if (p.outbound_default or "").lower() == "allow"
    ]
    if outbound_allow:
        names = ", ".join(p.name for p in outbound_allow)
        findings.append(
            _finding(
                finding_id="FW-OUTBOUND-ALLOW-001",
                title="Outbound default policy permits traffic",
                severity="INFORMATIONAL",
                category="default_policy",
                observed=f"Outbound default allow on: {names}",
                expected="Documented outbound policy (allow is common on Windows)",
                description=(
                    "One or more profiles use an outbound default of allow. This is "
                    "the common Windows default and is not by itself evidence of "
                    "compromise. Treat as a configuration requiring review if "
                    "policy expects outbound restriction."
                ),
                remediation=(
                    "If policy requires egress filtering, review outbound defaults "
                    "and explicit allow lists. Do not change production outbound "
                    "policy without an approved design. This checker does not "
                    "modify the firewall."
                ),
            )
        )

    return findings


def _finding(
    *,
    finding_id: str,
    title: str,
    severity: str,
    category: str,
    observed: str,
    expected: str,
    description: str,
    remediation: str,
) -> FirewallFinding:
    explanation = _ai_assisted_explanation(
        observed=observed,
        why=description,
        review=expected,
        remediation=remediation,
    )
    return FirewallFinding(
        id=finding_id,
        title=title,
        severity=severity,
        category=category,
        description=description,
        observed_value=observed,
        expected_or_recommended_value=expected,
        remediation=remediation,
        evidence_source=_EVIDENCE,
        explanation=explanation,
    )


def _ai_assisted_explanation(
    *, observed: str, why: str, review: str, remediation: str
) -> str:
    return (
        "AI-assisted security explanation (deterministic rules; no LLM): "
        f"Observed: {observed}. Why it matters: {why} "
        f"Defender review: {review}. Recommended remediation: {remediation}"
    )


def _dedupe(findings: list[FirewallFinding]) -> list[FirewallFinding]:
    seen: set[str] = set()
    out: list[FirewallFinding] = []
    for item in findings:
        if item.id in seen:
            continue
        seen.add(item.id)
        out.append(item)
    return out


def _overall_severity(findings: list[FirewallFinding]) -> str:
    if not findings:
        return "NONE"
    return max(findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 0)).severity

"""Read-only Windows firewall state collection.

Uses a fixed ``netsh advfirewall show allprofiles`` invocation.
Never accepts user-supplied command strings. Never modifies the firewall.
"""

from __future__ import annotations

import logging
import platform
import shutil
import subprocess
import sys
from datetime import datetime, timezone

from app.core.errors import sanitize_public_message
from app.firewall.models import FirewallProfileStatus, FirewallSnapshot

logger = logging.getLogger(__name__)

# Fixed argv \u2014 never interpolated with API input.
_NETSH_ALLPROFILES: tuple[str, ...] = (
    "netsh",
    "advfirewall",
    "show",
    "allprofiles",
)
_TIMEOUT_SECONDS = 15.0


class FirewallCollector:
    """Collect a structured snapshot without exposing raw command output."""

    def collect(self) -> FirewallSnapshot:
        assessed_at = datetime.now(timezone.utc).isoformat()
        plat = platform.system()
        if plat.lower() != "windows":
            return FirewallSnapshot(
                platform=plat,
                assessed_at=assessed_at,
                collection_status="unsupported_platform",
                firewall_available=False,
                collection_errors=[
                    sanitize_public_message(
                        f"Firewall posture collection is implemented for Windows. "
                        f"Detected platform: {plat}.",
                        fallback="Firewall collection is not available on this platform.",
                    )
                ],
            )
        return self._collect_windows(assessed_at, plat)

    def _collect_windows(self, assessed_at: str, plat: str) -> FirewallSnapshot:
        executable = shutil.which("netsh")
        if not executable:
            logger.warning("netsh is not available on PATH")
            return FirewallSnapshot(
                platform=plat,
                assessed_at=assessed_at,
                collection_status="command_unavailable",
                firewall_available=False,
                collection_errors=[
                    "Windows firewall inspection command is not available."
                ],
            )

        kwargs: dict[str, object] = {
            "args": list(_NETSH_ALLPROFILES),
            "capture_output": True,
            "text": True,
            "timeout": _TIMEOUT_SECONDS,
            "check": False,
        }
        if sys.platform == "win32":
            kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)

        try:
            completed = subprocess.run(**kwargs)  # noqa: S603  # fixed argv
        except subprocess.TimeoutExpired:
            logger.warning("netsh advfirewall timed out")
            return FirewallSnapshot(
                platform=plat,
                assessed_at=assessed_at,
                collection_status="timeout",
                firewall_available=False,
                collection_errors=["Firewall inspection timed out."],
            )
        except PermissionError:
            logger.warning("netsh permission denied")
            return FirewallSnapshot(
                platform=plat,
                assessed_at=assessed_at,
                collection_status="permission_denied",
                firewall_available=False,
                collection_errors=[
                    "Insufficient permission to read Windows firewall status."
                ],
            )
        except FileNotFoundError:
            logger.warning("netsh executable not found")
            return FirewallSnapshot(
                platform=plat,
                assessed_at=assessed_at,
                collection_status="command_unavailable",
                firewall_available=False,
                collection_errors=[
                    "Windows firewall inspection command is not available."
                ],
            )
        except OSError as exc:
            logger.warning("netsh OS error: %s", type(exc).__name__)
            return FirewallSnapshot(
                platform=plat,
                assessed_at=assessed_at,
                collection_status="collection_failed",
                firewall_available=False,
                collection_errors=["Unable to inspect Windows firewall status."],
            )

        stdout = completed.stdout or ""
        if completed.returncode != 0 and not stdout.strip():
            logger.warning("netsh returned code %s", completed.returncode)
            return FirewallSnapshot(
                platform=plat,
                assessed_at=assessed_at,
                collection_status="collection_failed",
                firewall_available=False,
                collection_errors=["Unable to inspect Windows firewall status."],
            )

        profiles = parse_netsh_allprofiles(stdout)
        if not profiles:
            return FirewallSnapshot(
                platform=plat,
                assessed_at=assessed_at,
                collection_status="parse_failed",
                firewall_available=False,
                collection_errors=[
                    "Firewall status was returned but could not be interpreted."
                ],
            )

        return FirewallSnapshot(
            platform=plat,
            assessed_at=assessed_at,
            collection_status="ok",
            firewall_available=True,
            profiles=profiles,
        )


def parse_netsh_allprofiles(text: str) -> list[FirewallProfileStatus]:
    """Parse ``netsh advfirewall show allprofiles`` into profile records.

    Raw text is not stored. Unknown layouts yield an empty list.
    """
    if not isinstance(text, str) or not text.strip():
        return []

    profiles: list[FirewallProfileStatus] = []
    current_name: str | None = None
    enabled: bool | None = None
    inbound: str | None = None
    outbound: str | None = None

    def _flush() -> None:
        nonlocal current_name, enabled, inbound, outbound
        if current_name:
            profiles.append(
                FirewallProfileStatus(
                    name=current_name,
                    enabled=enabled,
                    inbound_default=inbound,
                    outbound_default=outbound,
                )
            )
        current_name = None
        enabled = None
        inbound = None
        outbound = None

    for raw_line in text.splitlines():
        line = raw_line.strip()
        lower = line.lower()
        if "profile settings" in lower:
            _flush()
            name = line.split("Profile", 1)[0].strip().title()
            if not name:
                name = "Unknown"
            current_name = name
            continue
        if current_name is None:
            continue
        if lower.startswith("state"):
            value = _value_after_label(line, "state")
            enabled = _parse_on_off(value)
        elif lower.startswith("firewall policy"):
            value = _value_after_label(line, "firewall policy")
            inbound, outbound = _parse_firewall_policy(value)

    _flush()
    return profiles


def _value_after_label(line: str, label: str) -> str:
    idx = line.lower().find(label.lower())
    if idx < 0:
        return ""
    return line[idx + len(label) :].strip(" :\t")


def _parse_on_off(value: str) -> bool | None:
    token = value.strip().split()[0].upper() if value.strip() else ""
    if token in {"ON", "ENABLE", "ENABLED", "TRUE", "1"}:
        return True
    if token in {"OFF", "DISABLE", "DISABLED", "FALSE", "0"}:
        return False
    return None


def _parse_firewall_policy(value: str) -> tuple[str | None, str | None]:
    compact = value.replace(" ", "")
    inbound: str | None = None
    outbound: str | None = None
    lower = compact.lower()
    if "blockinbound" in lower:
        inbound = "block"
    elif "allowinbound" in lower:
        inbound = "allow"
    if "blockoutbound" in lower:
        outbound = "block"
    elif "allowoutbound" in lower:
        outbound = "allow"
    return inbound, outbound

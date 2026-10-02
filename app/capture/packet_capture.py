"""Local-lab packet capture using Scapy (Phase 3).

Live mode observes traffic available on this host.
Synthetic mode does not sniff; use fixtures for privilege-free tests.

Privilege notes:
    Windows: Npcap/WinPcap; Administrator often required for live sniffing.
    Linux: CAP_NET_RAW or root often required for live sniffing.
The application starts without elevated rights; live capture failures are
handled gracefully.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


class CaptureError(Exception):
    """Raised when capture is used incorrectly (e.g. already running)."""


@dataclass
class CapturedPacket:
    """Normalized packet summary for flow aggregation."""

    timestamp: float
    length: int
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    protocol: str = "OTHER"
    tcp_flags: str = ""


@dataclass
class CaptureResult:
    """Outcome of a capture attempt."""

    mode: str
    packets: list[CapturedPacket] = field(default_factory=list)
    interface: str | None = None
    duration_seconds: float = 0.0
    error: str | None = None
    privilege_note: str | None = None


def normalize_scapy_packet(pkt: Any) -> CapturedPacket | None:
    """Convert a Scapy packet to CapturedPacket, or None if not IP."""
    try:
        from scapy.all import ICMP, IP, IPv6, TCP, UDP  # type: ignore
    except Exception:  # noqa: BLE001
        return None

    try:
        length = int(len(pkt))
        timestamp = float(getattr(pkt, "time", time.time()))
        src_ip = dst_ip = ""
        src_port = dst_port = 0
        protocol = "OTHER"
        tcp_flags = ""

        if pkt.haslayer(IP):
            src_ip, dst_ip = str(pkt[IP].src), str(pkt[IP].dst)
        elif pkt.haslayer(IPv6):
            src_ip, dst_ip = str(pkt[IPv6].src), str(pkt[IPv6].dst)
        else:
            return None

        if pkt.haslayer(TCP):
            protocol = "TCP"
            src_port, dst_port = int(pkt[TCP].sport), int(pkt[TCP].dport)
            tcp_flags = str(pkt[TCP].flags)
        elif pkt.haslayer(UDP):
            protocol = "UDP"
            src_port, dst_port = int(pkt[UDP].sport), int(pkt[UDP].dport)
        elif pkt.haslayer(ICMP):
            protocol = "ICMP"

        return CapturedPacket(
            timestamp=timestamp,
            length=length,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            tcp_flags=tcp_flags,
        )
    except Exception as exc:  # noqa: BLE001
        logger.debug("Skipping unparseable packet: %s", exc)
        return None


class PacketCapture:
    """Live Scapy capture or synthetic no-sniff mode."""

    PRIVILEGE_HELP = (
        "Live capture often requires elevated privileges. "
        "Windows: install Npcap and run as Administrator. "
        "Linux: CAP_NET_RAW/root, or set IDS_MODE=synthetic."
    )

    @classmethod
    def preflight_live(cls) -> str | None:
        """Return an error string if live sniffing is unlikely to work.

        Does not require admin for the check itself. Returns None when OK.
        """
        try:
            from scapy.config import conf  # type: ignore
        except Exception as exc:  # noqa: BLE001
            return f"Scapy unavailable for live capture: {exc}"

        # Windows without Npcap/WinPcap typically has use_pcap=False.
        use_pcap = bool(getattr(conf, "use_pcap", False))
        if not use_pcap:
            return (
                "No libpcap/Npc provider available for layer-2 sniffing. "
                + cls.PRIVILEGE_HELP
            )
        return None

    def __init__(
        self,
        *,
        mode: str = "synthetic",
        interface: str | None = None,
        duration: float = 10.0,
        packet_count: int = 100,
        bpf_filter: str | None = None,
    ) -> None:
        if mode not in {"synthetic", "live"}:
            raise ValueError("mode must be 'synthetic' or 'live'")
        self.mode = mode
        self.interface = interface
        self.duration = float(duration)
        self.packet_count = int(packet_count)
        self.bpf_filter = bpf_filter
        self._stop_event = threading.Event()
        self._running = False
        self._packets: list[CapturedPacket] = []
        self._lock = threading.Lock()
        self.last_error: str | None = None

    @property
    def is_running(self) -> bool:
        return self._running

    def get_packets(self) -> list[CapturedPacket]:
        with self._lock:
            return list(self._packets)

    def start(self) -> CaptureResult:
        """Start capture for the configured mode (blocking for live sniff)."""
        if self._running:
            raise CaptureError("Capture is already running.")
        self._stop_event.clear()
        self.last_error = None
        with self._lock:
            self._packets = []

        if self.mode == "synthetic":
            logger.info("PacketCapture SYNTHETIC mode — no network sniffing")
            return CaptureResult(
                mode="synthetic",
                privilege_note=(
                    "Synthetic mode does not capture real packets. "
                    "Use app.capture.synthetic fixtures for tests."
                ),
            )
        return self._run_live()

    def start_async(self, on_packet: Any | None = None) -> None:
        """Start live sniffing in a background thread.

        The optional ``on_packet`` callback receives each :class:`CapturedPacket`
        and must remain lightweight (no ML / DB work).

        Raises:
            CaptureError: If already running or mode is not live.
        """
        if self.mode != "live":
            raise CaptureError("start_async is only valid for live mode.")
        if self._running:
            raise CaptureError("Capture is already running.")
        preflight = self.preflight_live()
        if preflight:
            self.last_error = preflight
            raise CaptureError(preflight)
        self._stop_event.clear()
        self.last_error = None
        with self._lock:
            self._packets = []
        self._on_packet = on_packet
        self._thread = threading.Thread(
            target=self._run_live_async_target,
            name="iot-ids-live-capture",
            daemon=True,
        )
        self._running = True
        self._thread.start()
        logger.info(
            "LIVE CAPTURE MODE started asynchronously | interface=%s duration=%.1fs",
            self.interface,
            self.duration,
        )

    def _run_live_async_target(self) -> None:
        result = self._run_live(on_packet=getattr(self, "_on_packet", None))
        if result.error:
            self.last_error = result.error
        self._running = False

    def stop(self) -> None:
        logger.info("Capture stop requested")
        self._stop_event.set()
        self._running = False
        thread = getattr(self, "_thread", None)
        if thread is not None and thread.is_alive() and threading.current_thread() is not thread:
            thread.join(timeout=5.0)

    def _run_live(self, on_packet: Any | None = None) -> CaptureResult:
        preflight = self.preflight_live()
        if preflight:
            logger.error(preflight)
            self.last_error = preflight
            self._running = False
            return CaptureResult(
                mode="live",
                interface=self.interface,
                error=preflight,
                privilege_note=self.PRIVILEGE_HELP,
            )
        try:
            from scapy.all import sniff  # type: ignore
        except Exception as exc:  # noqa: BLE001
            msg = f"Scapy unavailable for live capture: {exc}"
            logger.error(msg)
            self.last_error = msg
            self._running = False
            return CaptureResult(
                mode="live",
                interface=self.interface,
                error=msg,
                privilege_note=self.PRIVILEGE_HELP,
            )

        logger.info(
            "LIVE CAPTURE MODE | interface=%s duration=%.1fs count=%d filter=%s",
            self.interface,
            self.duration,
            self.packet_count,
            self.bpf_filter,
        )
        self._running = True
        started = time.time()

        def _store(pkt: Any) -> None:
            if self._stop_event.is_set():
                return
            normalized = normalize_scapy_packet(pkt)
            if normalized is None:
                return
            with self._lock:
                self._packets.append(normalized)
            if on_packet is not None:
                try:
                    on_packet(normalized)
                except Exception as exc:  # noqa: BLE001
                    logger.debug("on_packet callback error: %s", exc)

        try:
            sniff(
                iface=self.interface,
                timeout=self.duration if self.duration > 0 else None,
                count=self.packet_count if self.packet_count > 0 else 0,
                filter=self.bpf_filter or None,
                prn=_store,
                store=False,
                stop_filter=lambda _: self._stop_event.is_set(),
            )
        except PermissionError as exc:
            msg = f"Permission denied: {exc}. {self.PRIVILEGE_HELP}"
            logger.error(msg)
            self.last_error = msg
            self._running = False
            return CaptureResult(
                mode="live",
                packets=self.get_packets(),
                interface=self.interface,
                duration_seconds=time.time() - started,
                error=msg,
                privilege_note=self.PRIVILEGE_HELP,
            )
        except OSError as exc:
            msg = f"Live capture OS/interface error: {exc}"
            logger.error(msg)
            self.last_error = msg
            self._running = False
            return CaptureResult(
                mode="live",
                packets=self.get_packets(),
                interface=self.interface,
                duration_seconds=time.time() - started,
                error=msg,
                privilege_note=self.PRIVILEGE_HELP,
            )
        except Exception as exc:  # noqa: BLE001
            msg = f"Unexpected live capture failure: {exc}"
            logger.exception(msg)
            self.last_error = msg
            self._running = False
            return CaptureResult(
                mode="live",
                packets=self.get_packets(),
                interface=self.interface,
                duration_seconds=time.time() - started,
                error=msg,
                privilege_note=self.PRIVILEGE_HELP,
            )

        elapsed = time.time() - started
        packets = self.get_packets()
        self._running = False
        logger.info("LIVE capture done | packets=%d elapsed=%.2fs", len(packets), elapsed)
        return CaptureResult(
            mode="live",
            packets=packets,
            interface=self.interface,
            duration_seconds=elapsed,
        )

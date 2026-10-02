"""Aggregate packets into network flows."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Iterable

from app.capture.packet_capture import CapturedPacket

logger = logging.getLogger(__name__)

FlowKey = tuple[str, str, int, int, str]


@dataclass
class FlowRecord:
    """Aggregated flow statistics."""

    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    protocol: str
    start_time: float
    end_time: float
    packet_count: int = 0
    byte_count: int = 0
    min_packet_size: int = 0
    max_packet_size: int = 0
    tcp_flag_syn: int = 0
    tcp_flag_ack: int = 0
    tcp_flag_fin: int = 0
    tcp_flag_rst: int = 0
    data_source: str = "live"

    @property
    def duration(self) -> float:
        return max(self.end_time - self.start_time, 1e-6)

    @property
    def packets_per_second(self) -> float:
        return self.packet_count / self.duration

    @property
    def bytes_per_second(self) -> float:
        return self.byte_count / self.duration

    @property
    def average_packet_size(self) -> float:
        if self.packet_count == 0:
            return 0.0
        return self.byte_count / float(self.packet_count)

    def to_dict(self) -> dict[str, float | int | str]:
        return {
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "source_port": self.source_port,
            "destination_port": self.destination_port,
            "protocol": self.protocol,
            "duration": float(self.duration),
            "packet_count": float(self.packet_count),
            "byte_count": float(self.byte_count),
            "packets_per_second": float(self.packets_per_second),
            "bytes_per_second": float(self.bytes_per_second),
            "average_packet_size": float(self.average_packet_size),
            "min_packet_size": float(self.min_packet_size),
            "max_packet_size": float(self.max_packet_size),
            "tcp_flag_syn": float(self.tcp_flag_syn),
            "tcp_flag_ack": float(self.tcp_flag_ack),
            "tcp_flag_fin": float(self.tcp_flag_fin),
            "tcp_flag_rst": float(self.tcp_flag_rst),
            "data_source": self.data_source,
            "mode": str(self.data_source).upper(),
        }


def _key(pkt: CapturedPacket) -> FlowKey | None:
    if not pkt.src_ip or not pkt.dst_ip:
        return None
    return (
        pkt.src_ip,
        pkt.dst_ip,
        int(pkt.src_port),
        int(pkt.dst_port),
        (pkt.protocol or "OTHER").upper(),
    )


def _flags(flow: FlowRecord, flags: str) -> None:
    if not flags:
        return
    u = str(flags).upper()
    if "S" in u:
        flow.tcp_flag_syn += 1
    if "A" in u:
        flow.tcp_flag_ack += 1
    if "F" in u:
        flow.tcp_flag_fin += 1
    if "R" in u:
        flow.tcp_flag_rst += 1


class FlowAggregator:
    """Packet → flow aggregation with safe handling of incomplete packets."""

    def __init__(self, *, data_source: str = "live") -> None:
        self.data_source = data_source
        self._flows: dict[FlowKey, FlowRecord] = {}
        self.skipped_packets = 0

    def add_packet(self, packet: CapturedPacket) -> None:
        key = _key(packet)
        if key is None:
            self.skipped_packets += 1
            return
        length = max(int(packet.length), 0)
        flow = self._flows.get(key)
        if flow is None:
            flow = FlowRecord(
                source_ip=key[0],
                destination_ip=key[1],
                source_port=key[2],
                destination_port=key[3],
                protocol=key[4],
                start_time=float(packet.timestamp),
                end_time=float(packet.timestamp),
                packet_count=1,
                byte_count=length,
                min_packet_size=length,
                max_packet_size=length,
                data_source=self.data_source,
            )
            _flags(flow, packet.tcp_flags)
            self._flows[key] = flow
            return
        flow.packet_count += 1
        flow.byte_count += length
        flow.end_time = max(flow.end_time, float(packet.timestamp))
        flow.start_time = min(flow.start_time, float(packet.timestamp))
        flow.min_packet_size = min(flow.min_packet_size, length)
        flow.max_packet_size = max(flow.max_packet_size, length)
        _flags(flow, packet.tcp_flags)

    def add_packets(self, packets: Iterable[CapturedPacket]) -> None:
        for p in packets:
            self.add_packet(p)

    def get_flows(self) -> list[FlowRecord]:
        flows = list(self._flows.values())
        logger.info(
            "Flows aggregated=%d skipped=%d source=%s",
            len(flows),
            self.skipped_packets,
            self.data_source,
        )
        return flows

    def get_flow_dicts(self) -> list[dict[str, float | int | str]]:
        return [f.to_dict() for f in self.get_flows()]

    def pop_idle_flows(
        self,
        timeout_seconds: float,
        *,
        now: float | None = None,
    ) -> list[FlowRecord]:
        """Remove and return flows idle for at least ``timeout_seconds``."""
        current = time.time() if now is None else float(now)
        timeout = max(float(timeout_seconds), 0.0)
        completed: list[FlowRecord] = []
        for key, flow in list(self._flows.items()):
            if current - float(flow.end_time) >= timeout:
                completed.append(self._flows.pop(key))
        if completed:
            logger.info(
                "Completed %d idle flows (timeout=%.2fs, source=%s)",
                len(completed),
                timeout,
                self.data_source,
            )
        return completed

    def flush_all(self) -> list[FlowRecord]:
        """Force-complete all open flows (e.g. on capture stop)."""
        flows = list(self._flows.values())
        self._flows.clear()
        if flows:
            logger.info(
                "Flushed %d open flows (source=%s)", len(flows), self.data_source
            )
        return flows

    @property
    def open_flow_count(self) -> int:
        return len(self._flows)


def aggregate_packets(
    packets: Iterable[CapturedPacket],
    *,
    data_source: str = "live",
) -> list[dict[str, float | int | str]]:
    agg = FlowAggregator(data_source=data_source)
    agg.add_packets(packets)
    return agg.get_flow_dicts()

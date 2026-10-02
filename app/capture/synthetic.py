"""Synthetic local fixtures for privilege-free IDS testing.

Records are labelled data_source=synthetic and are NOT real traffic.
"""

from __future__ import annotations

import logging
import time
from typing import Any

from app.capture.packet_capture import CapturedPacket

logger = logging.getLogger(__name__)


def generate_synthetic_packets(
    *,
    n_normal: int = 40,
    n_anomalous: int = 10,
    base_time: float | None = None,
) -> list[CapturedPacket]:
    """Generate deterministic synthetic packets (nothing is transmitted)."""
    t0 = base_time if base_time is not None else 1_700_000_000.0
    packets: list[CapturedPacket] = []
    for i in range(n_normal):
        packets.append(
            CapturedPacket(
                timestamp=t0 + i * 0.05,
                length=60 + (i % 10) * 8,
                src_ip="10.0.0.10",
                dst_ip="10.0.0.20",
                src_port=40000 + (i % 20),
                dst_port=443,
                protocol="TCP",
                tcp_flags="A",
            )
        )
    for i in range(n_anomalous):
        packets.append(
            CapturedPacket(
                timestamp=t0 + n_normal * 0.05 + i * 0.001,
                length=1400 + i * 50,
                src_ip="10.0.0.99",
                dst_ip="10.0.0.20",
                src_port=55555,
                dst_port=80,
                protocol="TCP",
                tcp_flags="S",
            )
        )
    logger.info(
        "Generated SYNTHETIC packets | normal=%d anomalous=%d",
        n_normal,
        n_anomalous,
    )
    return packets


def generate_synthetic_flow_records(
    *,
    n_normal: int = 80,
    n_anomalous: int = 20,
) -> list[dict[str, Any]]:
    """Generate deterministic synthetic flow feature records."""
    records: list[dict[str, Any]] = []
    now = time.time()
    for i in range(n_normal):
        pkt_count = 8 + (i % 12)
        avg = 200.0 + (i % 5) * 10.0
        duration = 0.5 + (i % 10) * 0.1
        byte_count = avg * pkt_count
        records.append(
            {
                "source_ip": f"10.0.0.{(i % 50) + 1}",
                "destination_ip": "10.0.0.100",
                "source_port": 41000 + (i % 30),
                "destination_port": 443 if i % 2 == 0 else 80,
                "protocol": "TCP" if i % 3 else "UDP",
                "duration": duration,
                "packet_count": float(pkt_count),
                "byte_count": float(byte_count),
                "packets_per_second": pkt_count / duration,
                "bytes_per_second": byte_count / duration,
                "average_packet_size": avg,
                "min_packet_size": avg - 20.0,
                "max_packet_size": avg + 20.0,
                "data_source": "synthetic",
                "traffic_profile": "normal",
                "created_at": now,
            }
        )
    for i in range(n_anomalous):
        pkt_count = 400 + i * 25
        avg = 1200.0
        duration = 0.05 + (i % 5) * 0.01
        byte_count = avg * pkt_count
        records.append(
            {
                "source_ip": f"10.0.1.{(i % 20) + 1}",
                "destination_ip": "10.0.0.100",
                "source_port": 50000 + i,
                "destination_port": 22,
                "protocol": "TCP",
                "duration": duration,
                "packet_count": float(pkt_count),
                "byte_count": float(byte_count),
                "packets_per_second": pkt_count / duration,
                "bytes_per_second": byte_count / duration,
                "average_packet_size": avg,
                "min_packet_size": 1000.0,
                "max_packet_size": 1500.0,
                "data_source": "synthetic",
                "traffic_profile": "anomalous",
                "created_at": now,
            }
        )
    logger.info(
        "Generated SYNTHETIC flows | normal=%d anomalous=%d",
        n_normal,
        n_anomalous,
    )
    return records

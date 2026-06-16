from pathlib import Path

import pytest

scapy = pytest.importorskip("scapy")

from scapy.layers.inet import IP, TCP  # noqa: E402
from scapy.layers.l2 import Ether  # noqa: E402
from scapy.packet import Raw  # noqa: E402
from scapy.utils import rdpcap, wrpcap  # noqa: E402

from packetscrubber.scrubber import (  # noqa: E402
    AddressMode,
    PayloadMode,
    PortMode,
    ScrubOptions,
    scrub_capture,
)


def test_scrub_capture_rewrites_addresses_ports_and_payload(tmp_path: Path) -> None:
    source = tmp_path / "input.pcap"
    target = tmp_path / "output.pcap"
    packet = (
        Ether(src="aa:bb:cc:dd:ee:ff", dst="11:22:33:44:55:66")
        / IP(src="192.168.1.10", dst="8.8.8.8")
        / TCP(sport=12345, dport=80)
        / Raw(b"secret payload")
    )
    wrpcap(str(source), [packet])

    report = scrub_capture(
        source,
        target,
        ScrubOptions(
            ip_mode=AddressMode.DETERMINISTIC,
            mac_mode=AddressMode.DETERMINISTIC,
            port_mode=PortMode.DETERMINISTIC,
            payload_mode=PayloadMode.TRUNCATE,
            payload_bytes=6,
        ),
    )

    packets = rdpcap(str(target))
    scrubbed = packets[0]
    assert scrubbed[IP].src == "10.0.0.1"
    assert scrubbed[IP].dst == "10.0.0.2"
    assert scrubbed[Ether].src == "02:00:00:00:00:01"
    assert scrubbed[Ether].dst == "02:00:00:00:00:02"
    assert scrubbed[TCP].sport == 49152
    assert scrubbed[TCP].dport == 49153
    assert bytes(scrubbed[Raw].load) == b"secret"
    assert report.payload_bytes_removed == len(b" payload")

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from ipaddress import ip_address
from pathlib import Path
from typing import Any, Iterable


class AddressMode(str, Enum):
    KEEP = "keep"
    DETERMINISTIC = "deterministic"


class PortMode(str, Enum):
    KEEP = "keep"
    DETERMINISTIC = "deterministic"


class PayloadMode(str, Enum):
    KEEP = "keep"
    REMOVE = "remove"
    TRUNCATE = "truncate"
    ZERO = "zero"


@dataclass(frozen=True)
class ScrubOptions:
    ip_mode: AddressMode = AddressMode.KEEP
    mac_mode: AddressMode = AddressMode.KEEP
    port_mode: PortMode = PortMode.KEEP
    payload_mode: PayloadMode = PayloadMode.KEEP
    payload_bytes: int = 0
    port_base: int = 49152
    ip_map: dict[str, str] = field(default_factory=dict)
    mac_map: dict[str, str] = field(default_factory=dict)
    port_map: dict[int, int] = field(default_factory=dict)
    output_pcapng: bool = False


@dataclass
class ScrubReport:
    packets_read: int = 0
    packets_written: int = 0
    ipv4_changed: int = 0
    ipv6_changed: int = 0
    mac_changed: int = 0
    ports_changed: int = 0
    payload_packets_changed: int = 0
    payload_bytes_removed: int = 0


@dataclass
class CaptureSummary:
    packet_count: int
    ipv4_addresses: list[str]
    ipv6_addresses: list[str]
    mac_addresses: list[str]
    tcp_ports: list[int]
    udp_ports: list[int]
    raw_payload_packets: int


def summarize_capture(path: str | Path, limit: int | None = None) -> CaptureSummary:
    scapy = _load_scapy()
    Ether = scapy["Ether"]
    IP = scapy["IP"]
    IPv6 = scapy["IPv6"]
    Raw = scapy["Raw"]
    TCP = scapy["TCP"]
    UDP = scapy["UDP"]
    rdpcap = scapy["rdpcap"]

    packets = rdpcap(str(path), count=limit or -1)
    ipv4: set[str] = set()
    ipv6: set[str] = set()
    macs: set[str] = set()
    tcp_ports: set[int] = set()
    udp_ports: set[int] = set()
    raw_payload_packets = 0

    for pkt in packets:
        if Ether in pkt:
            macs.update([pkt[Ether].src.lower(), pkt[Ether].dst.lower()])
        if IP in pkt:
            ipv4.update([pkt[IP].src, pkt[IP].dst])
        if IPv6 in pkt:
            ipv6.update([pkt[IPv6].src, pkt[IPv6].dst])
        if TCP in pkt:
            tcp_ports.update([int(pkt[TCP].sport), int(pkt[TCP].dport)])
        if UDP in pkt:
            udp_ports.update([int(pkt[UDP].sport), int(pkt[UDP].dport)])
        if Raw in pkt:
            raw_payload_packets += 1

    return CaptureSummary(
        packet_count=len(packets),
        ipv4_addresses=sorted(ipv4),
        ipv6_addresses=sorted(ipv6),
        mac_addresses=sorted(macs),
        tcp_ports=sorted(tcp_ports),
        udp_ports=sorted(udp_ports),
        raw_payload_packets=raw_payload_packets,
    )


def scrub_capture(input_path: str | Path, output_path: str | Path, options: ScrubOptions) -> ScrubReport:
    scapy = _load_scapy()
    PcapNgWriter = scapy["PcapNgWriter"]
    rdpcap = scapy["rdpcap"]
    wrpcap = scapy["wrpcap"]

    packets = rdpcap(str(input_path))
    report = ScrubReport(packets_read=len(packets))
    mapper = DeterministicMapper(options)

    for pkt in packets:
        scrub_packet(pkt, options, mapper, report, scapy=scapy)

    if options.output_pcapng or str(output_path).lower().endswith(".pcapng"):
        writer = PcapNgWriter(str(output_path))
        try:
            for pkt in packets:
                writer.write(pkt)
        finally:
            writer.close()
    else:
        wrpcap(str(output_path), packets)

    report.packets_written = len(packets)
    return report


def scrub_packet(
    pkt: Any,
    options: ScrubOptions,
    mapper: "DeterministicMapper",
    report: ScrubReport,
    scapy: dict[str, Any] | None = None,
) -> None:
    scapy = scapy or _load_scapy()
    Ether = scapy["Ether"]
    IP = scapy["IP"]
    IPv6 = scapy["IPv6"]
    TCP = scapy["TCP"]
    UDP = scapy["UDP"]

    if Ether in pkt and options.mac_mode == AddressMode.DETERMINISTIC:
        eth = pkt[Ether]
        src = mapper.mac(eth.src)
        dst = mapper.mac(eth.dst)
        if src != eth.src:
            report.mac_changed += 1
            eth.src = src
        if dst != eth.dst:
            report.mac_changed += 1
            eth.dst = dst

    if IP in pkt and options.ip_mode == AddressMode.DETERMINISTIC:
        ip = pkt[IP]
        src = mapper.ip(ip.src)
        dst = mapper.ip(ip.dst)
        if src != ip.src:
            report.ipv4_changed += 1
            ip.src = src
        if dst != ip.dst:
            report.ipv4_changed += 1
            ip.dst = dst

    if IPv6 in pkt and options.ip_mode == AddressMode.DETERMINISTIC:
        ip6 = pkt[IPv6]
        src = mapper.ip(ip6.src)
        dst = mapper.ip(ip6.dst)
        if src != ip6.src:
            report.ipv6_changed += 1
            ip6.src = src
        if dst != ip6.dst:
            report.ipv6_changed += 1
            ip6.dst = dst

    if options.port_mode == PortMode.DETERMINISTIC:
        if TCP in pkt:
            report.ports_changed += _rewrite_ports(pkt[TCP], mapper)
        if UDP in pkt:
            report.ports_changed += _rewrite_ports(pkt[UDP], mapper)

    _scrub_payload(pkt, options, report, scapy=scapy)
    _invalidate_checksums(pkt, scapy=scapy)


class DeterministicMapper:
    def __init__(self, options: ScrubOptions) -> None:
        self.options = options
        self._ipv4: dict[str, str] = {}
        self._ipv6: dict[str, str] = {}
        self._mac: dict[str, str] = {}
        self._port: dict[int, int] = {}

    def ip(self, value: str) -> str:
        if value in self.options.ip_map:
            return self.options.ip_map[value]

        parsed = ip_address(value)
        if parsed.version == 4:
            if value not in self._ipv4:
                index = len(self._ipv4) + 1
                second = (index // 65536) % 256
                third = (index // 256) % 256
                fourth = index % 256 or 1
                self._ipv4[value] = f"10.{second}.{third}.{fourth}"
            return self._ipv4[value]

        if value not in self._ipv6:
            index = len(self._ipv6) + 1
            self._ipv6[value] = f"2001:db8::{index:x}"
        return self._ipv6[value]

    def mac(self, value: str) -> str:
        key = value.lower()
        if key in self.options.mac_map:
            return self.options.mac_map[key].lower()
        if key not in self._mac:
            index = len(self._mac) + 1
            self._mac[key] = "02:00:%02x:%02x:%02x:%02x" % (
                (index >> 24) & 0xFF,
                (index >> 16) & 0xFF,
                (index >> 8) & 0xFF,
                index & 0xFF,
            )
        return self._mac[key]

    def port(self, value: int) -> int:
        if value in self.options.port_map:
            return self.options.port_map[value]
        if value not in self._port:
            next_port = self.options.port_base + len(self._port)
            if next_port > 65535:
                next_port = 1024 + (len(self._port) % (65535 - 1024))
            self._port[value] = next_port
        return self._port[value]


def _rewrite_ports(layer: Any, mapper: DeterministicMapper) -> int:
    changed = 0
    sport = mapper.port(int(layer.sport))
    dport = mapper.port(int(layer.dport))
    if sport != int(layer.sport):
        layer.sport = sport
        changed += 1
    if dport != int(layer.dport):
        layer.dport = dport
        changed += 1
    return changed


def _scrub_payload(
    pkt: Any,
    options: ScrubOptions,
    report: ScrubReport,
    scapy: dict[str, Any] | None = None,
) -> None:
    Raw = (scapy or _load_scapy())["Raw"]

    if options.payload_mode == PayloadMode.KEEP or Raw not in pkt:
        return

    raw = pkt[Raw]
    original = bytes(raw.load)
    if options.payload_mode == PayloadMode.REMOVE:
        replacement = b""
    elif options.payload_mode == PayloadMode.TRUNCATE:
        replacement = original[: max(0, options.payload_bytes)]
    elif options.payload_mode == PayloadMode.ZERO:
        replacement = b"\x00" * min(len(original), max(0, options.payload_bytes or len(original)))
    else:
        return

    if replacement != original:
        raw.load = replacement
        report.payload_packets_changed += 1
        report.payload_bytes_removed += max(0, len(original) - len(replacement))


def _invalidate_checksums(pkt: Any, scapy: dict[str, Any] | None = None) -> None:
    scapy = scapy or _load_scapy()
    IP = scapy["IP"]
    IPv6 = scapy["IPv6"]
    TCP = scapy["TCP"]
    UDP = scapy["UDP"]
    ICMP = scapy["ICMP"]

    if IP in pkt:
        for field_name in ("len", "chksum"):
            if hasattr(pkt[IP], field_name):
                delattr(pkt[IP], field_name)
    if IPv6 in pkt and hasattr(pkt[IPv6], "plen"):
        delattr(pkt[IPv6], "plen")
    for layer_type in (TCP, UDP, ICMP):
        if layer_type in pkt and hasattr(pkt[layer_type], "chksum"):
            delattr(pkt[layer_type], "chksum")


def _load_scapy() -> dict[str, Any]:
    from scapy.layers.inet import ICMP, IP, TCP, UDP
    from scapy.layers.inet6 import IPv6
    from scapy.layers.l2 import Ether
    from scapy.packet import Raw
    from scapy.utils import PcapNgWriter, rdpcap, wrpcap

    return {
        "Ether": Ether,
        "ICMP": ICMP,
        "IP": IP,
        "IPv6": IPv6,
        "PcapNgWriter": PcapNgWriter,
        "Raw": Raw,
        "TCP": TCP,
        "UDP": UDP,
        "rdpcap": rdpcap,
        "wrpcap": wrpcap,
    }


def parse_mapping_lines(lines: Iterable[str]) -> dict[str, str]:
    mapping: dict[str, str] = {}
    for line in lines:
        clean = line.strip()
        if not clean or clean.startswith("#"):
            continue
        if "=" not in clean:
            raise ValueError(f"Invalid mapping line {clean!r}; expected old=new")
        old, new = clean.split("=", 1)
        mapping[old.strip()] = new.strip()
    return mapping


def parse_port_mapping_lines(lines: Iterable[str]) -> dict[int, int]:
    raw = parse_mapping_lines(lines)
    mapping: dict[int, int] = {}
    for old, new in raw.items():
        old_port = int(old)
        new_port = int(new)
        if not (0 <= old_port <= 65535 and 0 <= new_port <= 65535):
            raise ValueError("Ports must be between 0 and 65535")
        mapping[old_port] = new_port
    return mapping

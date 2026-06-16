from __future__ import annotations

import argparse
from pathlib import Path

from .scrubber import (
    AddressMode,
    PayloadMode,
    PortMode,
    ScrubOptions,
    parse_mapping_lines,
    parse_port_mapping_lines,
    scrub_capture,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Anonymize PCAP and PCAPNG files.")
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--ip", action="store_true", help="Deterministically rewrite IPv4/IPv6 addresses.")
    parser.add_argument("--mac", action="store_true", help="Deterministically rewrite Ethernet MAC addresses.")
    parser.add_argument("--ports", action="store_true", help="Deterministically rewrite TCP/UDP ports.")
    parser.add_argument("--port-base", type=int, default=49152)
    parser.add_argument(
        "--payload",
        choices=[mode.value for mode in PayloadMode],
        default=PayloadMode.KEEP.value,
        help="Payload scrub mode.",
    )
    parser.add_argument("--payload-bytes", type=int, default=0)
    parser.add_argument("--ip-map", action="append", default=[], metavar="OLD=NEW")
    parser.add_argument("--mac-map", action="append", default=[], metavar="OLD=NEW")
    parser.add_argument("--port-map", action="append", default=[], metavar="OLD=NEW")
    parser.add_argument("--pcapng", action="store_true", help="Write PCAPNG output.")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    options = ScrubOptions(
        ip_mode=AddressMode.DETERMINISTIC if args.ip or args.ip_map else AddressMode.KEEP,
        mac_mode=AddressMode.DETERMINISTIC if args.mac or args.mac_map else AddressMode.KEEP,
        port_mode=PortMode.DETERMINISTIC if args.ports or args.port_map else PortMode.KEEP,
        payload_mode=PayloadMode(args.payload),
        payload_bytes=args.payload_bytes,
        port_base=args.port_base,
        ip_map=parse_mapping_lines(args.ip_map),
        mac_map=parse_mapping_lines(args.mac_map),
        port_map=parse_port_mapping_lines(args.port_map),
        output_pcapng=args.pcapng or args.output.suffix.lower() == ".pcapng",
    )

    report = scrub_capture(args.input, args.output, options)
    print(f"Read {report.packets_read} packets; wrote {report.packets_written}.")
    print(
        "Changed "
        f"{report.ipv4_changed} IPv4 fields, {report.ipv6_changed} IPv6 fields, "
        f"{report.mac_changed} MAC fields, {report.ports_changed} port fields."
    )
    print(
        f"Payload changed in {report.payload_packets_changed} packets; "
        f"removed {report.payload_bytes_removed} bytes."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

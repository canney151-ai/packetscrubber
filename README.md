# PacketScrubber

PacketScrubber is a standalone desktop application for anonymizing packet captures.
It can open `.pcap` and `.pcapng` files, rewrite addresses and ports, and remove or
truncate packet payload bytes before writing a sanitized capture.

## Current features

- Cross-platform GUI built with PySide6.
- PCAP and PCAPNG input through Scapy.
- Deterministic IPv4, IPv6, and MAC anonymization.
- Optional explicit mappings for IPs, MACs, and TCP/UDP ports.
- TCP/UDP port remapping into a configurable high-port range.
- Payload handling modes:
  - keep payloads unchanged
  - remove payloads
  - truncate payloads to a byte limit
  - replace payload bytes with zeroes
- Automatic recalculation of IP, TCP, UDP, and ICMP length/checksum fields.
- CLI entry point for repeatable jobs and automation.

## Install for development

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

On Windows PowerShell:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
```

## Run the GUI

```bash
packetscrubber
```

or:

```bash
python -m packetscrubber.gui
```

On Windows, double-click `launch-gui.bat` or run:

```cmd
launch-gui.bat
```

The first run creates `.venv`, installs the required Python packages, and starts
the GUI. Later runs reuse the same environment.

## Run from the CLI

```bash
packetscrubber-cli input.pcapng output.pcap --ip --mac --ports --payload truncate --payload-bytes 64
```

Explicit mappings use `old=new` pairs:

```bash
packetscrubber-cli in.pcapng out.pcap --ip-map 192.168.1.25=10.10.0.25 --port-map 8080=443
```

## Packaging notes

PyInstaller is the most direct route for a self-contained desktop executable.

On Windows, run this from PowerShell:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\scripts\build-windows.ps1
```

Or double-click/run:

```cmd
build-windows-exe.bat
```

The portable executable will be written to:

```text
dist\PacketScrubber.exe
```

For a manual build:

```bash
pip install pyinstaller
pyinstaller --clean --noconfirm PacketScrubber.spec
```

Windows executables should be built on Windows. PyInstaller does not reliably
cross-compile a Windows `.exe` from Linux.

## Product ideas worth adding next

- A packet preview table with before/after values for selected packets.
- Named anonymization profiles for repeatable customer or lab workflows.
- A reversible mapping manifest encrypted with a user-provided passphrase.
- Protocol-aware redaction for HTTP headers, DNS names, TLS SNI, DHCP hostnames,
  and other metadata that may identify users even after address scrubbing.
- Capture integrity report showing changed fields, payload bytes removed, and
  protocols observed.
- Batch mode for processing folders of captures.

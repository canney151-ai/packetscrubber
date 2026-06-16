from __future__ import annotations

import sys
from importlib.resources import as_file, files
from pathlib import Path

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QPixmap
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFrame,
    QFormLayout,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QPlainTextEdit,
    QProgressBar,
    QVBoxLayout,
    QWidget,
)

from .scrubber import (
    AddressMode,
    CaptureSummary,
    PayloadMode,
    PortMode,
    ScrubOptions,
    parse_mapping_lines,
    parse_port_mapping_lines,
    scrub_capture,
    summarize_capture,
)


class ScrubWorker(QThread):
    completed = Signal(object)
    failed = Signal(str)

    def __init__(self, input_path: Path, output_path: Path, options: ScrubOptions) -> None:
        super().__init__()
        self.input_path = input_path
        self.output_path = output_path
        self.options = options

    def run(self) -> None:
        try:
            self.completed.emit(scrub_capture(self.input_path, self.output_path, self.options))
        except Exception as exc:  # noqa: BLE001 - surface GUI errors cleanly.
            self.failed.emit(str(exc))


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("SignalVault PacketScrubber")
        self.setMinimumSize(1120, 760)
        self.worker: ScrubWorker | None = None

        self.input_edit = QLineEdit()
        self.output_edit = QLineEdit()
        self.input_button = QPushButton("Browse")
        self.output_button = QPushButton("Save As")
        self.preview_button = QPushButton("Preview")
        self.run_button = QPushButton("Scrub Capture")
        self.run_button.setObjectName("primaryButton")
        self.progress = QProgressBar()
        self.progress.setRange(0, 1)
        self.progress.setValue(0)
        self.progress.setFixedWidth(180)

        self.ip_check = QCheckBox("Rewrite IP addresses")
        self.mac_check = QCheckBox("Rewrite MAC addresses")
        self.port_check = QCheckBox("Rewrite TCP/UDP ports")
        self.port_base = QSpinBox()
        self.port_base.setRange(1024, 65535)
        self.port_base.setValue(49152)

        self.payload_combo = QComboBox()
        for label, mode in [
            ("Keep payloads", PayloadMode.KEEP),
            ("Remove payloads", PayloadMode.REMOVE),
            ("Truncate payloads", PayloadMode.TRUNCATE),
            ("Zero payload bytes", PayloadMode.ZERO),
        ]:
            self.payload_combo.addItem(label, mode.value)

        self.payload_bytes = QSpinBox()
        self.payload_bytes.setRange(0, 10_000_000)
        self.payload_bytes.setValue(64)
        self.payload_bytes.setSuffix(" bytes")

        self.output_pcapng = QCheckBox("Write PCAPNG")

        self.ip_map = QPlainTextEdit()
        self.mac_map = QPlainTextEdit()
        self.port_map = QPlainTextEdit()
        for edit in (self.ip_map, self.mac_map, self.port_map):
            edit.setPlaceholderText("old=new, one mapping per line")
            edit.setMaximumHeight(90)

        self.summary = QPlainTextEdit()
        self.summary.setReadOnly(True)
        self.summary.setPlaceholderText("Open a capture and click Preview to inspect discovered fields.")

        self._build_layout()
        self._connect_signals()

    def _build_layout(self) -> None:
        root = QWidget()
        main = QVBoxLayout(root)
        main.setContentsMargins(0, 0, 0, 0)
        main.setSpacing(0)

        header = QFrame()
        header.setObjectName("appHeader")
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(28, 22, 28, 22)
        header_layout.setSpacing(24)

        logo = QLabel()
        logo.setObjectName("brandLogo")
        pixmap = _load_logo()
        if pixmap and not pixmap.isNull():
            logo.setPixmap(pixmap.scaledToHeight(54, Qt.TransformationMode.SmoothTransformation))
        else:
            logo.setText("SignalVault")

        title_block = QVBoxLayout()
        title_block.setSpacing(4)
        title = QLabel("PacketScrubber")
        title.setObjectName("appTitle")
        subtitle = QLabel("Sanitize packet captures before sharing, triage, or evidence handoff.")
        subtitle.setObjectName("appSubtitle")
        title_block.addWidget(title)
        title_block.addWidget(subtitle)

        header_layout.addWidget(logo)
        header_layout.addLayout(title_block)
        header_layout.addStretch(1)
        main.addWidget(header)

        content = QFrame()
        content.setObjectName("contentFrame")
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(28, 24, 28, 24)
        content_layout.setSpacing(18)

        files = QGroupBox("Capture files")
        grid = QGridLayout(files)
        grid.setHorizontalSpacing(14)
        grid.setVerticalSpacing(12)
        grid.addWidget(QLabel("Input"), 0, 0)
        grid.addWidget(self.input_edit, 0, 1)
        grid.addWidget(self.input_button, 0, 2)
        grid.addWidget(QLabel("Output"), 1, 0)
        grid.addWidget(self.output_edit, 1, 1)
        grid.addWidget(self.output_button, 1, 2)
        grid.addWidget(self.output_pcapng, 2, 1)
        content_layout.addWidget(files)

        middle = QHBoxLayout()
        middle.setSpacing(18)

        options = QGroupBox("Scrub options")
        form = QFormLayout(options)
        form.setContentsMargins(18, 24, 18, 18)
        form.setHorizontalSpacing(16)
        form.setVerticalSpacing(12)
        form.addRow(self.ip_check)
        form.addRow(self.mac_check)
        form.addRow(self.port_check)
        form.addRow("First anonymized port", self.port_base)
        form.addRow("Payload handling", self.payload_combo)
        form.addRow("Payload byte limit", self.payload_bytes)
        middle.addWidget(options, 1)

        mappings = QGroupBox("Explicit mappings")
        mapping_layout = QGridLayout(mappings)
        mapping_layout.setContentsMargins(18, 24, 18, 18)
        mapping_layout.setHorizontalSpacing(12)
        mapping_layout.setVerticalSpacing(10)
        mapping_layout.addWidget(QLabel("IP mappings"), 0, 0)
        mapping_layout.addWidget(QLabel("MAC mappings"), 0, 1)
        mapping_layout.addWidget(QLabel("Port mappings"), 0, 2)
        mapping_layout.addWidget(self.ip_map, 1, 0)
        mapping_layout.addWidget(self.mac_map, 1, 1)
        mapping_layout.addWidget(self.port_map, 1, 2)
        middle.addWidget(mappings, 2)
        content_layout.addLayout(middle)

        result_label = QLabel("Preview / Result")
        result_label.setObjectName("sectionLabel")
        content_layout.addWidget(result_label)
        content_layout.addWidget(self.summary, stretch=1)

        actions = QHBoxLayout()
        actions.setSpacing(12)
        actions.addWidget(self.preview_button)
        actions.addStretch(1)
        actions.addWidget(self.progress)
        actions.addWidget(self.run_button)
        content_layout.addLayout(actions)
        main.addWidget(content, stretch=1)

        self.setCentralWidget(root)
        self.setStyleSheet(APP_STYLESHEET)

    def _connect_signals(self) -> None:
        self.input_button.clicked.connect(self.select_input)
        self.output_button.clicked.connect(self.select_output)
        self.preview_button.clicked.connect(self.preview)
        self.run_button.clicked.connect(self.run_scrub)
        self.payload_combo.currentIndexChanged.connect(self.update_payload_controls)
        self.update_payload_controls()

    def select_input(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Open capture",
            "",
            "Packet captures (*.pcap *.pcapng);;All files (*)",
        )
        if path:
            self.input_edit.setText(path)
            if not self.output_edit.text():
                source = Path(path)
                self.output_edit.setText(str(source.with_name(f"{source.stem}.scrubbed.pcap")))

    def select_output(self) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Save scrubbed capture",
            self.output_edit.text() or "",
            "PCAP (*.pcap);;PCAPNG (*.pcapng);;All files (*)",
        )
        if path:
            self.output_edit.setText(path)
            self.output_pcapng.setChecked(path.lower().endswith(".pcapng"))

    def update_payload_controls(self) -> None:
        mode = PayloadMode(self.payload_combo.currentData())
        self.payload_bytes.setEnabled(mode in {PayloadMode.TRUNCATE, PayloadMode.ZERO})

    def preview(self) -> None:
        try:
            summary = summarize_capture(self._input_path())
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(self, "Preview failed", str(exc))
            return
        self.summary.setPlainText(format_summary(summary))

    def run_scrub(self) -> None:
        try:
            input_path = self._input_path()
            output_path = self._output_path()
            options = self._options()
        except Exception as exc:  # noqa: BLE001
            QMessageBox.warning(self, "Invalid settings", str(exc))
            return

        self.run_button.setEnabled(False)
        self.preview_button.setEnabled(False)
        self.progress.setRange(0, 0)
        self.summary.setPlainText("Scrubbing capture...")

        self.worker = ScrubWorker(input_path, output_path, options)
        self.worker.completed.connect(self.scrub_completed)
        self.worker.failed.connect(self.scrub_failed)
        self.worker.finished.connect(self.worker_finished)
        self.worker.start()

    def scrub_completed(self, report: object) -> None:
        self.summary.setPlainText(
            "Scrub complete.\n\n"
            f"Packets read: {report.packets_read}\n"
            f"Packets written: {report.packets_written}\n"
            f"IPv4 fields changed: {report.ipv4_changed}\n"
            f"IPv6 fields changed: {report.ipv6_changed}\n"
            f"MAC fields changed: {report.mac_changed}\n"
            f"Port fields changed: {report.ports_changed}\n"
            f"Payload packets changed: {report.payload_packets_changed}\n"
            f"Payload bytes removed: {report.payload_bytes_removed}\n"
        )

    def scrub_failed(self, message: str) -> None:
        QMessageBox.critical(self, "Scrub failed", message)
        self.summary.setPlainText("Scrub failed.")

    def worker_finished(self) -> None:
        self.progress.setRange(0, 1)
        self.progress.setValue(1)
        self.run_button.setEnabled(True)
        self.preview_button.setEnabled(True)
        self.worker = None

    def _input_path(self) -> Path:
        path = Path(self.input_edit.text()).expanduser()
        if not path.is_file():
            raise ValueError("Choose an existing input capture.")
        return path

    def _output_path(self) -> Path:
        path = Path(self.output_edit.text()).expanduser()
        if not path.name:
            raise ValueError("Choose an output path.")
        return path

    def _options(self) -> ScrubOptions:
        return ScrubOptions(
            ip_mode=AddressMode.DETERMINISTIC if self.ip_check.isChecked() or self.ip_map.toPlainText().strip() else AddressMode.KEEP,
            mac_mode=AddressMode.DETERMINISTIC if self.mac_check.isChecked() or self.mac_map.toPlainText().strip() else AddressMode.KEEP,
            port_mode=PortMode.DETERMINISTIC if self.port_check.isChecked() or self.port_map.toPlainText().strip() else PortMode.KEEP,
            payload_mode=PayloadMode(self.payload_combo.currentData()),
            payload_bytes=self.payload_bytes.value(),
            port_base=self.port_base.value(),
            ip_map=parse_mapping_lines(self.ip_map.toPlainText().splitlines()),
            mac_map=parse_mapping_lines(self.mac_map.toPlainText().splitlines()),
            port_map=parse_port_mapping_lines(self.port_map.toPlainText().splitlines()),
            output_pcapng=self.output_pcapng.isChecked(),
        )


def format_summary(summary: CaptureSummary) -> str:
    return (
        f"Packets: {summary.packet_count}\n"
        f"Raw payload packets: {summary.raw_payload_packets}\n\n"
        f"IPv4 addresses ({len(summary.ipv4_addresses)}): {', '.join(summary.ipv4_addresses[:40])}\n"
        f"IPv6 addresses ({len(summary.ipv6_addresses)}): {', '.join(summary.ipv6_addresses[:40])}\n"
        f"MAC addresses ({len(summary.mac_addresses)}): {', '.join(summary.mac_addresses[:40])}\n"
        f"TCP ports ({len(summary.tcp_ports)}): {', '.join(map(str, summary.tcp_ports[:80]))}\n"
        f"UDP ports ({len(summary.udp_ports)}): {', '.join(map(str, summary.udp_ports[:80]))}\n"
    )


def _load_logo() -> QPixmap | None:
    try:
        logo = files("packetscrubber").joinpath("assets/signalvault-logo-white.svg")
        with as_file(logo) as logo_path:
            return QPixmap(str(logo_path))
    except Exception:  # noqa: BLE001 - logo is decorative; the app can run without it.
        return None


APP_STYLESHEET = """
QMainWindow, QWidget {
    background: #101820;
    color: #e8eef4;
    font-family: "Segoe UI", "Inter", "Arial";
    font-size: 13px;
}

#appHeader {
    background: #111c26;
    border-bottom: 1px solid #263544;
}

#brandLogo {
    min-width: 230px;
}

#appTitle {
    color: #f8fbfd;
    font-size: 28px;
    font-weight: 700;
}

#appSubtitle {
    color: #92a4b6;
    font-size: 13px;
}

#contentFrame {
    background: #16212b;
}

QGroupBox {
    background: #1b2935;
    border: 1px solid #2f4354;
    border-radius: 8px;
    margin-top: 14px;
    padding-top: 10px;
    font-weight: 700;
}

QGroupBox::title {
    subcontrol-origin: margin;
    subcontrol-position: top left;
    left: 14px;
    padding: 0 7px;
    color: #f2f7fb;
}

QLabel {
    color: #cbd6df;
}

#sectionLabel {
    color: #f2f7fb;
    font-size: 14px;
    font-weight: 700;
}

QLineEdit, QPlainTextEdit, QComboBox, QSpinBox {
    background: #0f171f;
    border: 1px solid #314758;
    border-radius: 6px;
    color: #f0f5f8;
    selection-background-color: #1f8f9a;
    padding: 8px 10px;
}

QPlainTextEdit {
    font-family: "Cascadia Mono", "Consolas", monospace;
    font-size: 12px;
}

QLineEdit:focus, QPlainTextEdit:focus, QComboBox:focus, QSpinBox:focus {
    border: 1px solid #2fb7c4;
}

QCheckBox {
    spacing: 9px;
    color: #dbe5ec;
}

QCheckBox::indicator {
    width: 17px;
    height: 17px;
    border-radius: 4px;
    border: 1px solid #506578;
    background: #0f171f;
}

QCheckBox::indicator:checked {
    background: #2fb7c4;
    border: 1px solid #2fb7c4;
}

QPushButton {
    background: #253746;
    border: 1px solid #3b5365;
    border-radius: 7px;
    color: #edf5f8;
    font-weight: 700;
    padding: 9px 16px;
}

QPushButton:hover {
    background: #30485b;
}

QPushButton:pressed {
    background: #1d2c39;
}

QPushButton:disabled {
    background: #1c2832;
    color: #697987;
}

#primaryButton {
    background: #20a7b3;
    border: 1px solid #3ed0dc;
    color: #061216;
}

#primaryButton:hover {
    background: #37c4cf;
}

QProgressBar {
    background: #0f171f;
    border: 1px solid #314758;
    border-radius: 6px;
    color: #cbd6df;
    height: 16px;
    text-align: center;
}

QProgressBar::chunk {
    background: #2fb7c4;
    border-radius: 5px;
}
"""


def main() -> int:
    app = QApplication(sys.argv)
    app.setApplicationName("PacketScrubber")
    window = MainWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())

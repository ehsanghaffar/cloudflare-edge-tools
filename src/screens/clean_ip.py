from __future__ import annotations

import asyncio
import os
import time
from typing import ClassVar, Optional

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical, Container
from textual.screen import ModalScreen
from textual.widget import Widget
from textual.widgets import Static, Label, Button, DataTable, ProgressBar, RichLog, Input
from textual.binding import Binding
from textual import work
from textual.message import Message

from src.constants import CLEAN_MODES, CF_SUBNETS, RESULTS_DIR
from src.clean_finder import generate_cf_ips, scan_clean_ips
from src.models import CleanScanState
from src.utils import _results_path, _fmt_elapsed


class CleanIPSaver(ModalScreen[str]):
    def compose(self) -> ComposeResult:
        with Vertical(id="clean-save-dialog"):
            yield Label("[bold]Save Clean IPs[/]", classes="dialog-title")
            yield Label(f"[dim]Enter filename (saved to {RESULTS_DIR}/):[/]", classes="dialog-hint")
            yield Input(value="clean_ips.txt", id="clean-save-path")
            with Horizontal(classes="dialog-buttons"):
                yield Button("Save", id="btn-save-confirm", variant="primary")
                yield Button("Cancel", id="btn-save-cancel", variant="default")

    def on_button_pressed(self, event: Button.Pressed):
        if event.button.id == "btn-save-confirm":
            name = self.query_one("#clean-save-path", Input).value.strip()
            if name:
                self.dismiss(name)
        elif event.button.id == "btn-save-cancel":
            self.dismiss("")


class CleanTempScreen(ModalScreen[str]):
    def compose(self) -> ComposeResult:
        with Vertical(id="clean-template-dialog"):
            yield Label("[bold]Speed Test with Clean IPs[/]", classes="dialog-title")
            yield Label("[dim]Paste a VLESS/VMess config URI. The address will be[/]", classes="dialog-hint")
            yield Label("[dim]replaced with each clean IP for speed testing.[/]", classes="dialog-hint")
            yield Input(placeholder="vless://...", id="clean-template-uri")
            with Horizontal(classes="dialog-buttons"):
                yield Button("Start Test", id="btn-tpl-start", variant="primary")
                yield Button("Cancel", id="btn-tpl-cancel", variant="default")

    def on_button_pressed(self, event: Button.Pressed):
        if event.button.id == "btn-tpl-start":
            uri = self.query_one("#clean-template-uri", Input).value.strip()
            if uri:
                self.dismiss(uri)
        elif event.button.id == "btn-tpl-cancel":
            self.dismiss("")


class CleanIPScreen(Widget):
    BINDINGS: ClassVar = [
        Binding("escape", "stop", "Stop"),
    ]

    scan_running = False

    def __init__(self):
        super().__init__()
        self.scan_state: Optional[CleanScanState] = None
        self.results: list = []
        self._update_task: Optional[asyncio.Task] = None

    def compose(self) -> ComposeResult:
        with Horizontal():
            with Vertical(classes="pane-left"):
                yield Label("SCAN SCOPE", classes="section-title")
                yield Button("Quick (~4K IPs)", id="mode-quick", variant="default")
                yield Button("Normal (~12K IPs)", id="mode-normal", variant="primary")
                yield Button("Full (~1.5M IPs)", id="mode-full", variant="default")
                yield Button("Mega (~3M probes)", id="mode-mega", variant="default")
                yield Label("CONTROLS", classes="section-title")
                yield Button("▶ Start Search", id="btn-start-clean", variant="success")
                yield Button("⏹ Stop", id="btn-stop-clean", variant="error", classes="hidden")
                yield Button("💾 Save IPs", id="btn-save-clean", variant="primary", classes="hidden")
                yield Button("📋 Template Test", id="btn-template-test", variant="default", classes="hidden")
                yield ProgressBar(id="clean-progress", show_percentage=True, show_eta=False)
            with Vertical(classes="pane-right"):
                yield Label("DISCOVERED IPS", classes="section-title")
                yield DataTable(id="clean-results-table", cursor_type="row")
                yield RichLog(id="clean-log", max_lines=20, highlight=True, markup=True)

    def on_mount(self):
        table = self.query_one("#clean-results-table", DataTable)
        table.add_columns("#", "IP Address", "Latency")

    def on_button_pressed(self, event: Button.Pressed):
        btn_id = event.button.id or ""
        if btn_id in ("mode-quick", "mode-normal", "mode-full", "mode-mega"):
            self._set_mode(btn_id.replace("mode-", ""))
        elif btn_id == "btn-start-clean":
            self._start_scan()
        elif btn_id == "btn-stop-clean":
            self.action_stop()
        elif btn_id == "btn-save-clean":
            self._save_results()
        elif btn_id == "btn-template-test":
            self.app.push_screen(CleanTempScreen(), self._on_template_uri)

    def _set_mode(self, mode: str):
        for m in ("quick", "normal", "full", "mega"):
            btn = self.query_one(f"#mode-{m}", Button)
            btn.variant = "primary" if m == mode else "default"
        self._active_mode = mode

    @work(thread=False, exclusive=True)
    async def _start_scan(self):
        if self.scan_running:
            return

        mode = getattr(self, "_active_mode", "normal")
        scan_cfg = CLEAN_MODES.get(mode, CLEAN_MODES["normal"])

        self.scan_running = True
        self.query_one("#btn-start-clean", Button).add_class("hidden")
        self.query_one("#btn-stop-clean", Button).remove_class("hidden")
        self.query_one("#btn-save-clean", Button).add_class("hidden")
        self.query_one("#btn-template-test", Button).add_class("hidden")
        self.query_one("#clean-log", RichLog).clear()

        self._log(f"Generating IPs from {len(CF_SUBNETS)} Cloudflare ranges...")
        ips = generate_cf_ips(CF_SUBNETS, scan_cfg["sample"])
        ports = scan_cfg.get("ports", [443])
        self._log(f"Testing {len(ips):,} IPs across {len(ports)} port(s)")

        scan_state = CleanScanState(total=len(ips))
        scan_state.start_time = time.monotonic()
        self.scan_state = scan_state

        self._update_task = asyncio.ensure_future(self._progress_updater(scan_state))

        try:
            await scan_clean_ips(
                ips,
                workers=scan_cfg["workers"],
                timeout=5.0,
                validate=scan_cfg["validate"],
                scan_state=scan_state,
                ports=ports,
            )
        except asyncio.CancelledError:
            scan_state.interrupted = True
        finally:
            if self._update_task:
                self._update_task.cancel()
            self._on_scan_done(scan_state)

    async def _progress_updater(self, scan_state: CleanScanState):
        pb = self.query_one("#clean-progress", ProgressBar)
        table = self.query_one("#clean-results-table", DataTable)
        while not scan_state.interrupted and (scan_state.done < scan_state.total):
            pb.update(total=scan_state.total, progress=scan_state.done)
            table.clear()
            for i, (ip, lat) in enumerate(scan_state.results[:100], 1):
                lat_color = "green" if lat < 100 else "yellow" if lat < 200 else "red"
                table.add_row(str(i), ip, f"[{lat_color}]{lat:.0f}ms[/]")
            await asyncio.sleep(0.3)

    def _on_scan_done(self, scan_state: CleanScanState):
        self.scan_running = False
        self.results = sorted(
            scan_state.all_results or scan_state.results, key=lambda x: x[1]
        )

        self.query_one("#btn-start-clean", Button).remove_class("hidden")
        self.query_one("#btn-stop-clean", Button).add_class("hidden")

        elapsed = _fmt_elapsed(time.monotonic() - scan_state.start_time) if scan_state.start_time else "0s"

        if self.results:
            self.query_one("#btn-save-clean", Button).remove_class("hidden")
            self.query_one("#btn-template-test", Button).remove_class("hidden")
            self._log(f"[green]Found {len(self.results):,} clean IPs in {elapsed}[/]")
            self.app.notify(f"Found {len(self.results):,} clean IPs", severity="information")
        else:
            self._log("[yellow]No clean IPs found[/]")
            self.app.notify("No clean IPs found", severity="warning")

        table = self.query_one("#clean-results-table", DataTable)
        table.clear()
        for i, (ip, lat) in enumerate(self.results[:300], 1):
            lat_color = "green" if lat < 100 else "yellow" if lat < 200 else "red"
            table.add_row(str(i), ip, f"[{lat_color}]{lat:.0f}ms[/]")

        dash = self.app.get_dashboard()
        if dash:
            dash.update_stats(clean_ips=len(self.results))

    def action_stop(self):
        if self.scan_state:
            self.scan_state.interrupted = True

    def _save_results(self):
        self.app.push_screen(CleanIPSaver(), self._on_save_name)

    def _on_save_name(self, name: str):
        if not name or not self.results:
            return
        try:
            os.makedirs(RESULTS_DIR, exist_ok=True)
            path = _results_path(name)
            with open(path, "w") as f:
                for ip, lat in self.results:
                    f.write(f"{ip}\n")
            self._log(f"[green]Saved {len(self.results):,} IPs to {path}[/]")
            self.app.notify(f"Saved {len(self.results):,} IPs", severity="information")
        except OSError as e:
            self._log(f"[red]Save error: {e}[/]")
            self.app.notify(f"Save error: {e}", severity="error")

    def _on_template_uri(self, uri: str):
        if not uri or not self.results:
            return
        from src.config_parse import parse_config
        if not parse_config(uri):
            self.app.notify("Invalid VLESS/VMess URI", severity="error")
            return
        os.makedirs(RESULTS_DIR, exist_ok=True)
        path = _results_path("clean_ips.txt")
        with open(path, "w") as f:
            for ip, lat in self.results:
                f.write(f"{ip}\n")
        self._log(f"[green]Saved IPs, starting template scan...[/]")
        self.app.notify("Template scan ready - use Scanner tab", severity="information")
        self.app.switch_mode("scanner")

    def _log(self, msg: str):
        try:
            log = self.query_one("#clean-log", RichLog)
            log.write(f"[dim][{time.strftime('%H:%M:%S')}][/] {msg}")
        except Exception:
            pass

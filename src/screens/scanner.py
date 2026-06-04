from __future__ import annotations

import asyncio
import glob
import os
import signal
import time
from typing import ClassVar, Optional

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical, Container
from textual.reactive import reactive
from textual.screen import ModalScreen
from textual.widget import Widget
from textual.widgets import (
    Static, Label, Button, ListView, ListItem, DataTable,
    ProgressBar, Input, RadioSet, RadioButton, RichLog, Footer,
)
from textual import work
from textual.message import Message
from textual.binding import Binding

from src.models import State
from src.config_parse import load_input, parse_config
from src.core import resolve_all, run_scan, do_export


def find_config_files() -> list[str]:
    results: list[str] = []
    for ext in ["*.txt", "*.json", "*.conf", "*.lst"]:
        for path in glob.glob(ext):
            results.append(path)
    return sorted(set(results))


class FilePickerScreen(ModalScreen[str]):
    def compose(self) -> ComposeResult:
        with Vertical(id="file-picker-dialog"):
            yield Label("[bold]Enter file path:[/]", classes="dialog-title")
            yield Input(placeholder="/path/to/config.txt", id="file-path-input")
            with Horizontal(classes="dialog-buttons"):
                yield Button("Load", id="btn-file-load", variant="primary")
                yield Button("Cancel", id="btn-file-cancel", variant="default")

    def on_button_pressed(self, event: Button.Pressed):
        if event.button.id == "btn-file-load":
            path = self.query_one("#file-path-input", Input).value.strip()
            if path and os.path.isfile(path):
                self.dismiss(path)
            else:
                self.app.notify("File not found", title="Error", severity="error")
        elif event.button.id == "btn-file-cancel":
            self.dismiss("")


class SubURLScreen(ModalScreen[str]):
    def compose(self) -> ComposeResult:
        with Vertical(id="sub-dialog"):
            yield Label("[bold]Subscription URL:[/]", classes="dialog-title")
            yield Label("[dim]Paste a URL containing VLESS/VMess configs[/]", classes="dialog-hint")
            yield Input(placeholder="https://example.com/sub", id="sub-url-input")
            with Horizontal(classes="dialog-buttons"):
                yield Button("Fetch", id="btn-sub-fetch", variant="primary")
                yield Button("Cancel", id="btn-sub-cancel", variant="default")

    def on_button_pressed(self, event: Button.Pressed):
        if event.button.id == "btn-sub-fetch":
            url = self.query_one("#sub-url-input", Input).value.strip()
            if url and url.lower().startswith(("http://", "https://")):
                self.dismiss(url)
            else:
                self.app.notify("URL must start with http:// or https://", title="Error", severity="error")
        elif event.button.id == "btn-sub-cancel":
            self.dismiss("")


class TemplateScreen(ModalScreen[str]):
    def compose(self) -> ComposeResult:
        with Vertical(id="template-dialog"):
            yield Label("[bold]Template + Address List[/]", classes="dialog-title")
            yield Label("[dim]Paste your VLESS/VMess config URI:[/]", classes="dialog-hint")
            yield Input(placeholder="vless://...", id="template-uri-input")
            yield Label("[dim]Enter path to address list file:[/]", classes="dialog-hint")
            yield Input(placeholder="/path/to/addresses.txt", id="template-path-input")
            with Horizontal(classes="dialog-buttons"):
                yield Button("Start", id="btn-template-start", variant="primary")
                yield Button("Cancel", id="btn-template-cancel", variant="default")

    def on_button_pressed(self, event: Button.Pressed):
        if event.button.id == "btn-template-start":
            uri = self.query_one("#template-uri-input", Input).value.strip()
            path = self.query_one("#template-path-input", Input).value.strip()
            if not parse_config(uri):
                self.app.notify("Invalid VLESS/VMess URI", title="Error", severity="error")
                return
            if not os.path.isfile(path):
                self.app.notify("Address file not found", title="Error", severity="error")
                return
            self.dismiss(f"{uri}|||{path}")
        elif event.button.id == "btn-template-cancel":
            self.dismiss("")


class ScannerScreen(Widget):
    BINDINGS: ClassVar = [
        Binding("r", "refresh_files", "Refresh"),
        Binding("escape", "stop_scan", "Stop"),
    ]

    scan_running = reactive(False)

    def __init__(self):
        super().__init__()
        self.active_st: Optional[State] = None
        self._scan_task: Optional[asyncio.Task] = None

    def compose(self) -> ComposeResult:
        with Horizontal():
            with Vertical(classes="pane-left"):
                yield Label("SOURCE", classes="section-title")
                yield Static("[dim]Local Files[/]", classes="pane-label")
                yield ListView(id="file-list")
                with Horizontal(classes="btn-row"):
                    yield Button("🔄 Refresh", id="btn-refresh", variant="default")
                    yield Button("📁 Path", id="btn-path", variant="default")
                    yield Button("🔗 Sub URL", id="btn-sub", variant="default")
                yield Button("📋 Template", id="btn-template", variant="default")
                yield Label("MODE", classes="section-title")
                with RadioSet(id="mode-select"):
                    yield RadioButton("Quick", value=False)
                    yield RadioButton("Normal", value=True, id="mode-normal")
                    yield RadioButton("Thorough", value=False)
                yield Label("CONTROLS", classes="section-title")
                yield Button("▶ Start Scan", id="btn-start-scan", variant="success")
                yield Button("⏹ Stop", id="btn-stop-scan", variant="error", classes="hidden")
                yield Button("💾 Export", id="btn-export", variant="primary", classes="hidden")
                yield ProgressBar(id="scan-progress", show_percentage=True, show_eta=False)
            with Vertical(classes="pane-right"):
                yield Label("LIVE RESULTS", classes="section-title")
                yield DataTable(id="results-table", cursor_type="row")
                yield RichLog(id="scan-log", max_lines=50, highlight=True, markup=True)

    def on_mount(self):
        table = self.query_one("#results-table", DataTable)
        table.add_columns("Rank", "IP", "Domains", "Ping", "TLS", "Speed", "Score")
        self._refresh_file_list()

    def _refresh_file_list(self):
        files = find_config_files()
        flist = self.query_one("#file-list", ListView)
        flist.clear()
        if files:
            for f in files:
                name = os.path.basename(f)
                flist.append(ListItem(Label(f"[$accent]{name}[/] [$text-dim]{os.path.getsize(f)}B[/]")))
        else:
            flist.append(ListItem(Label("[dim]No config files found[/]")))

    @work(thread=False, exclusive=True)
    async def action_refresh_files(self):
        self._refresh_file_list()
        self.app.notify("File list refreshed")

    def on_list_view_selected(self, event: ListView.Selected):
        files = find_config_files()
        if event.list_view.id == "file-list" and files:
            idx = event.list_view.index
            if idx is not None and 0 <= idx < len(files):
                self._start_scan(files[idx])

    def on_button_pressed(self, event: Button.Pressed):
        btn_id = event.button.id or ""
        if btn_id == "btn-refresh":
            self._refresh_file_list()
        elif btn_id == "btn-path":
            self.push_screen(FilePickerScreen(), self._on_file_picked)
        elif btn_id == "btn-sub":
            self.push_screen(SubURLScreen(), self._on_sub_url)
        elif btn_id == "btn-template":
            self.push_screen(TemplateScreen(), self._on_template)
        elif btn_id == "btn-start-scan":
            self._start_scan()
        elif btn_id == "btn-stop-scan":
            self.action_stop_scan()
        elif btn_id == "btn-export":
            self._export_results()

    def _on_file_picked(self, path: str):
        if path:
            self._start_scan(source=path)

    def _on_sub_url(self, url: str):
        if url:
            self._start_scan(source=url, source_type="sub")

    def _on_template(self, data: str):
        if data:
            self._start_scan(source=data, source_type="template")

    def _get_selected_file(self) -> Optional[str]:
        files = find_config_files()
        flist = self.query_one("#file-list", ListView)
        if flist.index is not None and 0 <= flist.index < len(files):
            return files[flist.index]
        return None

    def _get_mode(self) -> str:
        rset = self.query_one("#mode-select", RadioSet)
        pressed = rset.pressed_index
        return ["quick", "normal", "thorough"][pressed] if pressed is not None else "normal"

    @work(thread=False, exclusive=True)
    async def _start_scan(self, source: Optional[str] = None, source_type: str = "file"):
        if self.scan_running:
            return

        if source_type == "file" and not source:
            source = self._get_selected_file()
        if not source:
            self.app.notify("No config source selected", title="Warning", severity="warning")
            return

        self.scan_running = True
        self.query_one("#btn-start-scan", Button).add_class("hidden")
        self.query_one("#btn-stop-scan", Button).remove_class("hidden")
        self.query_one("#btn-export", Button).add_class("hidden")
        self.query_one("#scan-log", RichLog).clear()

        st = State()
        self.active_st = st

        if source_type == "sub":
            from src.config_parse import fetch_sub
            st.configs = fetch_sub(source)
            st.input_file = source
        elif source_type == "template":
            from src.config_parse import load_addresses, generate_from_template
            parts = source.split("|||", 1)
            template_uri = parts[0]
            addr_path = parts[1] if len(parts) > 1 else ""
            addrs = load_addresses(addr_path) if addr_path else []
            st.configs = generate_from_template(template_uri, addrs)
            st.input_file = addr_path
        else:
            st.configs = load_input(source)
            st.input_file = source

        if not st.configs:
            self.app.notify("No configs loaded", title="Error", severity="error")
            self.scan_running = False
            self.query_one("#btn-start-scan", Button).remove_class("hidden")
            self.query_one("#btn-stop-scan", Button).add_class("hidden")
            return

        st.mode = self._get_mode()
        self._log(f"Loaded [bold]{len(st.configs)}[/] configs")
        self._log(f"Mode: [bold]{st.mode}[/]")
        self._log("Resolving DNS...")

        await resolve_all(st)

        if not st.ips:
            self.app.notify("No IPs resolved", title="Error", severity="error")
            self.scan_running = False
            self.query_one("#btn-start-scan", Button).remove_class("hidden")
            self.query_one("#btn-stop-scan", Button).add_class("hidden")
            return

        self._log(f"Resolved [bold]{len(st.ips)}[/] unique IPs")

        update_task = asyncio.ensure_future(self._progress_updater(st))
        try:
            await run_scan(st, 100, 10, 3.0, 10.0)
        except asyncio.CancelledError:
            st.interrupted = True
            st.finished = True
        finally:
            update_task.cancel()
            self._on_scan_done(st)

    async def _progress_updater(self, st: State):
        pb = self.query_one("#scan-progress", ProgressBar)
        while not st.finished:
            if st.total > 0:
                pb.update(total=st.total, progress=st.done_count)
            self._update_table(st)
            await asyncio.sleep(0.3)

    def _on_scan_done(self, st: State):
        self.scan_running = False
        self._scan_task = None
        self.query_one("#btn-start-scan", Button).remove_class("hidden")
        self.query_one("#btn-stop-scan", Button).add_class("hidden")
        self.query_one("#btn-export", Button).remove_class("hidden")

        if st.interrupted:
            self._log("[yellow]Scan interrupted[/]")
            self.app.notify("Scan interrupted", severity="warning")
        else:
            self._log("[green]Scan complete[/]")
            self.app.notify("Scan complete", severity="information")

        self._update_table(st)
        self._log(f"Alive: [green]{st.alive_n}[/]  Dead: [red]{st.dead_n}[/]")
        dash = self.app.get_dashboard()
        if dash:
            scores = [r.score for r in st.res.values() if r.alive and r.score > 0]
            best = max(st.res[r].best_mbps for r in st.res if st.res[r].alive and st.res[r].best_mbps > 0) if st.res else 0
            dash.update_stats(
                configs=len(st.configs),
                last_scan=time.strftime("%H:%M:%S"),
                best_speed=f"{best:.2f} MB/s" if best else "-",
            )

    def _update_table(self, st: State):
        from src.models import sorted_alive
        table = self.query_one("#results-table", DataTable)
        table.clear()
        results = sorted_alive(st, "score")
        for i, r in enumerate(results[:200], 1):
            score_color = "green" if r.score >= 70 else "yellow" if r.score >= 40 else "red"
            domains = ", ".join(r.domains[:2]) if r.domains else "-"
            speed = f"{r.best_mbps:.2f}" if r.best_mbps > 0 else "-"
            table.add_row(
                str(i),
                r.ip,
                domains[:25],
                f"{r.tcp_ms:.0f}ms" if r.tcp_ms > 0 else "-",
                f"{r.tls_ms:.0f}ms" if r.tls_ms > 0 else "-",
                speed,
                f"[{score_color}]{r.score:.1f}[/]",
            )

    def action_stop_scan(self):
        if self.active_st:
            self.active_st.interrupted = True
            self.active_st.finished = True
        if self._scan_task and not self._scan_task.done():
            self._scan_task.cancel()

    def _export_results(self):
        st = self.active_st
        if not st or not st.res:
            self.app.notify("No scan data to export", title="Warning", severity="warning")
            return
        csv_p, cfg_p, full_p = do_export(st, st.input_file)
        self._log(f"Exported: [green]{os.path.basename(csv_p)}[/], [green]{os.path.basename(cfg_p)}[/]")
        self.app.notify(f"Results exported", severity="information")

    def _log(self, msg: str):
        try:
            log = self.query_one("#scan-log", RichLog)
            log.write(f"[dim][{time.strftime('%H:%M:%S')}][/] {msg}")
        except Exception:
            pass

    def watch_scan_running(self, running: bool):
        from src.screens.dashboard import DashboardScreen
        ds = self.app.get_dashboard()
        if ds:
            ds.log_activity(f"Scan {'started' if running else 'finished'}")

    async def _on_scan_progress(self, st: State):
        pb = self.query_one("#scan-progress", ProgressBar)
        while not st.finished:
            pb.update(total=max(st.total, 1), progress=st.done_count)
            self._update_table(st)
            await asyncio.sleep(0.3)

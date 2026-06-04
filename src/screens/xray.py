from __future__ import annotations

import asyncio
import os
import time
from typing import ClassVar, Optional

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical, Container
from textual.widget import Widget
from textual.widgets import Static, Label, Button, DataTable, ProgressBar, RichLog, Input, RadioSet, RadioButton
from textual.binding import Binding
from textual import work

from src.models import XrayTestState, PipelineConfig, XrayVariation
from src.config_parse import parse_vless_full, parse_vmess_full
from src.xray_utils import xray_find_binary, xray_install, xray_pipeline_test
from src.utils import _fmt_elapsed


class XrayScreen(Widget):
    BINDINGS: ClassVar = [
        Binding("escape", "stop", "Stop"),
    ]

    scan_running = False

    def __init__(self):
        super().__init__()
        self.xst: Optional[XrayTestState] = None
        self._update_task: Optional[asyncio.Task] = None

    def compose(self) -> ComposeResult:
        with Horizontal():
            with Vertical(classes="pane-left"):
                yield Label("CONFIGURATION", classes="section-title")
                yield Label("[dim]VLESS/VMess URI[/]")
                yield Input(placeholder="vless://...", id="xray-uri-input")
                yield Label("[dim]Fragment Preset[/]")
                with RadioSet(id="frag-preset"):
                    yield RadioButton("None", value=False)
                    yield RadioButton("Light", value=False)
                    yield RadioButton("Medium", value=False)
                    yield RadioButton("Heavy", value=False)
                    yield RadioButton("All", value=True, id="frag-all")
                yield Label("CONTROLS", classes="section-title")
                yield Button("▶ Start Test", id="btn-start-xray", variant="success")
                yield Button("⏹ Stop", id="btn-stop-xray", variant="error", classes="hidden")
                yield Button("💾 Export", id="btn-export-xray", variant="primary", classes="hidden")
                yield ProgressBar(id="xray-progress", show_percentage=True, show_eta=False)
            with Vertical(classes="pane-right"):
                yield Label("PIPELINE STAGES", classes="section-title")
                yield Static(id="stage-ip-scan", classes="stage-status")
                yield Static(id="stage-base-test", classes="stage-status")
                yield Static(id="stage-expansion", classes="stage-status")
                yield Label("RESULTS", classes="section-title")
                yield DataTable(id="xray-results-table", cursor_type="row")
                yield RichLog(id="xray-log", max_lines=30, highlight=True, markup=True)

    def on_mount(self):
        table = self.query_one("#xray-results-table", DataTable)
        table.add_columns("Rank", "SNI", "Fragment", "Conn", "TTFB", "Speed", "Score")

    def on_button_pressed(self, event: Button.Pressed):
        btn_id = event.button.id or ""
        if btn_id == "btn-start-xray":
            self._start_test()
        elif btn_id == "btn-stop-xray":
            self.action_stop()
        elif btn_id == "btn-export-xray":
            self._export_results()

    def _get_frag_preset(self) -> str:
        rset = self.query_one("#frag-preset", RadioSet)
        presets = ["none", "light", "medium", "heavy", "all"]
        idx = rset.pressed_index
        return presets[idx] if idx is not None else "all"

    @work(thread=False, exclusive=True)
    async def _start_test(self):
        if self.scan_running:
            return

        uri = self.query_one("#xray-uri-input", Input).value.strip()
        if not uri:
            self.app.notify("Please enter a VLESS/VMess URI", title="Warning", severity="warning")
            return

        parsed = parse_vless_full(uri) or parse_vmess_full(uri)
        if not parsed:
            self.app.notify("Invalid URI", title="Error", severity="error")
            return

        xray_bin = xray_find_binary() or xray_install()
        if not xray_bin:
            self.app.notify("Failed to find or install Xray", title="Error", severity="error")
            return

        self.scan_running = True
        self.query_one("#btn-start-xray", Button).add_class("hidden")
        self.query_one("#btn-stop-xray", Button).remove_class("hidden")
        self.query_one("#btn-export-xray", Button).add_class("hidden")
        self.query_one("#xray-log", RichLog).clear()

        xst = XrayTestState()
        self.xst = xst
        xst.source_uri = uri
        pcfg = PipelineConfig(uri=uri, parsed=parsed, frag_preset=self._get_frag_preset(), max_expansion=500)

        self._update_stages()
        self._log(f"Starting Xray pipeline test...")
        self._log(f"Fragment preset: [bold]{pcfg.frag_preset}[/]")

        self._update_task = asyncio.ensure_future(self._progress_updater(xst))

        try:
            await xray_pipeline_test(xst, pcfg)
        except asyncio.CancelledError:
            xst.interrupted = True
            xst.finished = True
        finally:
            if self._update_task:
                self._update_task.cancel()
            self._on_test_done(xst)

    async def _progress_updater(self, xst: XrayTestState):
        pb = self.query_one("#xray-progress", ProgressBar)
        while not xst.finished:
            if xst.total > 0:
                pb.update(total=xst.total, progress=xst.done_count)
            self._update_stages()
            self._update_table(xst)
            await asyncio.sleep(0.3)

    def _update_stages(self):
        xst = self.xst
        if not xst:
            return
        for i, stage in enumerate(xst.pipeline_stages):
            sid = ["stage-ip-scan", "stage-base-test", "stage-expansion"][i]
            widget = self.query_one(f"#{sid}", Static)
            st = stage["status"]
            label = stage["label"]
            if st == "done":
                widget.update(f"[green]✅ {label} — Complete[/]")
            elif st == "active":
                pct = f" {xst.done_count}/{xst.total}" if xst.total > 0 else ""
                widget.update(f"[yellow]🔄 {label}{pct}[/]")
            elif st == "interrupted":
                widget.update(f"[red]⛔ {label} — Interrupted[/]")
            else:
                widget.update(f"[dim]⏳ {label} — Waiting[/]")

    def _update_table(self, xst: XrayTestState):
        table = self.query_one("#xray-results-table", DataTable)
        table.clear()
        sorted_vars = sorted(xst.variations, key=lambda v: v.score, reverse=True)
        for i, v in enumerate(sorted_vars[:100], 1):
            frag = "none" if v.fragment is None else v.fragment.get("length", "?")
            conn = f"{v.connect_ms:.0f}ms" if v.connect_ms > 0 else "-"
            ttfb = f"{v.ttfb_ms:.0f}ms" if v.ttfb_ms > 0 else "-"
            speed = f"{v.speed_mbps:.2f}" if v.speed_mbps > 0 else "-"
            score_color = "green" if v.score >= 70 else "yellow" if v.score >= 40 else "red"
            table.add_row(str(i), v.sni[:25], str(frag), conn, ttfb, speed, f"[{score_color}]{v.score:.1f}[/]")

    def _on_test_done(self, xst: XrayTestState):
        self.scan_running = False
        self.query_one("#btn-start-xray", Button).remove_class("hidden")
        self.query_one("#btn-stop-xray", Button).add_class("hidden")
        self.query_one("#btn-export-xray", Button).remove_class("hidden")
        self._update_stages()

        alive = sum(1 for v in xst.variations if v.alive)
        if xst.interrupted:
            self._log("[yellow]Test interrupted[/]")
        else:
            self._log(f"[green]Test complete — {alive} alive variations[/]")
            self.app.notify(f"Xray test done — {alive} alive", severity="information")

    def action_stop(self):
        if self.xst:
            self.xst.interrupted = True

    def _export_results(self):
        from src.core import xray_save_results
        if not self.xst or not self.xst.variations:
            self.app.notify("No data to export", severity="warning")
            return
        csv_p, uri_p = xray_save_results(self.xst)
        self._log(f"[green]Exported to {os.path.basename(csv_p)}[/]")
        self.app.notify(f"Results exported", severity="information")

    def _log(self, msg: str):
        try:
            log = self.query_one("#xray-log", RichLog)
            log.write(f"[dim][{time.strftime('%H:%M:%S')}][/] {msg}")
        except Exception:
            pass

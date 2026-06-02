from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.widgets import Header, Footer, Static, Button, Label, ListView, ListItem, DataTable, ProgressBar, Input, ContentSwitcher
from textual.binding import Binding
from textual import work
import asyncio
import os
import glob
import time

from src.models import State, sorted_alive, CleanScanState, XrayTestState, PipelineConfig
from src.config_parse import load_input, parse_vless_full, parse_vmess_full
from src.clean_finder import generate_cf_ips, scan_clean_ips
from src.core import resolve_all, run_scan, do_export, xray_save_results
from src.constants import CF_SUBNETS
from src.xray_utils import xray_find_binary, xray_install, xray_pipeline_test
from src.utils import _results_path

def find_config_files():
    results = []
    for ext in ["*.txt", "*.json", "*.conf", "*.lst"]:
        for path in glob.glob(ext):
            results.append(path)
    return sorted(list(set(results)))

class Dashboard(Static):
    def compose(self) -> ComposeResult:
        with Horizontal():
            with Vertical(classes="pane-left"):
                yield Label("SYSTEM OVERVIEW", classes="section-title")
                with Vertical(classes="card"):
                    yield Label("Configs Loaded: [b]0[/]", id="dash-configs")
                    yield Label("Clean IPs: [b]0[/]", id="dash-clean")
                    yield Label("Avg Latency: [b]-[/]", id="dash-latency")
                yield Label("QUICK ACTIONS", classes="section-title")
                yield Button("Update CF Subnets", id="btn-subnet-update", variant="primary")
                yield Button("Clean Temp Files", id="btn-clean-temp")
            with Vertical(classes="pane-right"):
                yield Label("ACTIVITY LOG", classes="section-title")
                yield ListView(id="activity-log")

class ScannerView(Static):
    def compose(self) -> ComposeResult:
        with Horizontal():
            with Vertical(classes="pane-left"):
                yield Label("SOURCE", classes="section-title")
                yield ListView(*[ListItem(Label(f)) for f in find_config_files()], id="file-list")
                yield Button("Start Scan", id="start-scan", variant="success")
                yield Button("Stop Scan", id="stop-scan", variant="error", classes="hidden")
                yield Button("Export", id="export-scan", variant="primary", classes="hidden")
                yield Label("PROGRESS", classes="section-title")
                yield ProgressBar(id="scan-progress", show_percentage=True)
            with Vertical(classes="pane-right"):
                yield Label("LIVE RESULTS", classes="section-title")
                yield DataTable(id="results-table")

class CleanIPView(Static):
    def compose(self) -> ComposeResult:
        with Horizontal():
            with Vertical(classes="pane-left"):
                yield Label("PARAMETERS", classes="section-title")
                yield Button("Mode: Quick", id="clean-mode-quick")
                yield Button("Mode: Normal", id="clean-mode-normal", variant="primary")
                yield Button("Start Search", id="start-clean", variant="success")
                yield Button("Stop Search", id="stop-clean", variant="error", classes="hidden")
                yield Button("Export IPs", id="export-clean", variant="primary", classes="hidden")
                yield Label("PROGRESS", classes="section-title")
                yield ProgressBar(id="clean-progress", show_percentage=True)
            with Vertical(classes="pane-right"):
                yield Label("DISCOVERED IPS", classes="section-title")
                yield DataTable(id="clean-results-table")

class XrayView(Static):
    def compose(self) -> ComposeResult:
        with Horizontal():
            with Vertical(classes="pane-left"):
                yield Label("CONFIGURATION", classes="section-title")
                yield Label("VLESS/VMess URI")
                yield Input(placeholder="vless://...", id="xray-uri-input")
                yield Label("Fragment Preset")
                yield Button("Preset: All", id="frag-all", variant="primary")
                yield Button("Preset: Light", id="frag-light")
                yield Button("Start Test", id="start-xray", variant="success")
                yield Button("Stop Test", id="stop-xray", variant="error", classes="hidden")
                yield Button("Export Results", id="export-xray", variant="primary", classes="hidden")
                yield Label("PROGRESS", classes="section-title")
                yield ProgressBar(id="xray-progress")
            with Vertical(classes="pane-right"):
                yield Label("TEST TRACE", classes="section-title")
                yield Label("Current Stage: [b]Ready[/]", id="xray-stage-label")
                yield DataTable(id="xray-results-table")

class DeployView(Static):
    def compose(self) -> ComposeResult:
        with Horizontal():
            with Vertical(classes="pane-left"):
                yield Label("DEPLOYMENT", classes="section-title")
                yield Label("Status: [b]Linux Required[/]")
                if os.name != "posix":
                     yield Label("[error]Non-POSIX System Detected[/]", id="deploy-warning")
                yield Button("Prerequisite Check", id="btn-deploy-check", variant="primary")
                yield Button("Install Xray Core", id="btn-xray-install")
            with Vertical(classes="pane-right"):
                yield Label("OUTPUT CONSOLE", classes="section-title")
                yield ListView(id="deploy-console")

class CFEdgeApp(App):
    """A modern TUI for the Cloudflare Edge Scanner built with Textual."""
    
    CSS_PATH = "app.tcss"
    BINDINGS = [
        Binding("1", "switch_mode('dash')", "Home", show=True),
        Binding("2", "switch_mode('scanner')", "Scanner", show=True),
        Binding("3", "switch_mode('clean')", "Clean IP", show=True),
        Binding("4", "switch_mode('xray')", "Xray", show=True),
        Binding("5", "switch_mode('deploy')", "Deploy", show=True),
        Binding("q", "quit", "Quit", show=True),
    ]

    def __init__(self):
        super().__init__()
        self.active_st = None
        self.active_clean_state = None
        self.active_xray_state = None

    def compose(self) -> ComposeResult:
        yield Header()
        with ContentSwitcher(initial="dash", id="main-switcher"):
            yield Dashboard(id="dash")
            yield ScannerView(id="scanner")
            yield CleanIPView(id="clean")
            yield XrayView(id="xray")
            yield DeployView(id="deploy")
        yield Footer()

    def action_switch_mode(self, mode: str) -> None:
        self.query_one(ContentSwitcher).current = mode

    def on_mount(self) -> None:
        self.query_one("#results-table", DataTable).add_columns("Rank", "IP", "Ping", "Conn", "Speed", "Score")
        self.query_one("#clean-results-table", DataTable).add_columns("IP", "Latency")
        self.query_one("#xray-results-table", DataTable).add_columns("Rank", "SNI", "Frag", "Conn", "TTFB", "Score")
        self.log_activity("System Initialized")

    def toggle_buttons(self, start_id, stop_id, running=True, export_id=None):
        try:
            self.query_one(f"#{start_id}").set_class(running, "hidden")
            self.query_one(f"#{stop_id}").set_class(not running, "hidden")
            if export_id:
                 self.query_one(f"#{export_id}").set_class(running, "hidden")
        except Exception:
            pass

    def log_activity(self, message: str):
        try:
            log = self.query_one("#activity-log", ListView)
            log.append(ListItem(Label(f"[{time.strftime('%H:%M:%S')}] {message}")))
            log.scroll_end()
        except Exception:
            pass

    @work(exclusive=True, name="scan")
    async def action_start_scan(self) -> None:
        file_list = self.query_one("#file-list", ListView)
        files = find_config_files()
        
        if file_list.index is None or file_list.index < 0 or file_list.index >= len(files):
            self.notify("Please select a file first", title="Warning")
            return
            
        filename = files[file_list.index]
        self.log_activity(f"Scanner: Starting {filename}")
        self.toggle_buttons("start-scan", "stop-scan", True, "export-scan")
        
        st = State()
        self.active_st = st
        st.input_file = filename
        st.configs = load_input(filename)
        if not st.configs:
            self.notify(f"No configs found in {filename}", title="Error")
            self.toggle_buttons("start-scan", "stop-scan", False, "export-scan")
            return
            
        await resolve_all(st)
        if not st.ips and not st.interrupted:
            self.notify("No IPs resolved", title="Error")
            self.toggle_buttons("start-scan", "stop-scan", False, "export-scan")
            return
            
        update_task = asyncio.create_task(self.update_results_loop(st))
        
        try:
            await run_scan(st, 100, 10, 3.0, 10.0)
        finally:
            update_task.cancel()
            self.update_results(st)
            self.toggle_buttons("start-scan", "stop-scan", False, "export-scan")
            msg = "Scan interrupted" if st.interrupted else "Scan complete"
            self.log_activity(f"Scanner: {msg}")
            self.notify(msg)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "start-scan":
            self.action_start_scan()
        elif event.button.id == "stop-scan":
            self.action_stop_scan()
        elif event.button.id == "export-scan":
            self.action_export_scan()
        elif event.button.id == "start-clean":
            self.action_start_clean()
        elif event.button.id == "stop-clean":
            self.action_stop_clean()
        elif event.button.id == "export-clean":
            self.action_export_clean()
        elif event.button.id == "start-xray":
            self.action_start_xray()
        elif event.button.id == "stop-xray":
            self.action_stop_xray()
        elif event.button.id == "export-xray":
            self.action_export_xray()

    def action_stop_scan(self) -> None:
        if self.active_st:
            self.active_st.interrupted = True
        for worker in self.workers:
            if worker.name == "scan":
                worker.cancel()

    def action_export_scan(self) -> None:
        if not self.active_st or not self.active_st.res:
            self.notify("No scan data to export", title="Warning")
            return
        csv_p, cfg_p, full_p = do_export(self.active_st, self.active_st.input_file)
        self.notify(f"Exported to {os.path.basename(cfg_p)}", title="Success")

    async def update_results_loop(self, st: State) -> None:
        while not st.finished:
            self.update_results(st)
            await asyncio.sleep(0.5)

    def update_results(self, st: State) -> None:
        table = self.query_one("#results-table", DataTable)
        results = sorted_alive(st, "score")
        table.clear()
        for i, r in enumerate(results[:50], 1):
            table.add_row(str(i), r.ip, f"{r.tcp_ms:.0f}ms", f"{r.tls_ms:.0f}ms", f"{r.best_mbps:.2f} MB/s", f"{r.score:.1f}")
        
        # Update Dashboard stats
        self.query_one("#dash-configs", Label).update(f"Configs Loaded: [b]{len(st.configs)}[/]")
        if results:
             self.query_one("#dash-latency", Label).update(f"Avg Latency: [b]{sum(r.tcp_ms for r in results)/len(results):.1f}ms[/]")

    @work(exclusive=True, name="clean")
    async def action_start_clean(self) -> None:
        self.log_activity("Clean IP: Starting search...")
        self.toggle_buttons("start-clean", "stop-clean", True, "export-clean")
        
        ips = generate_cf_ips(CF_SUBNETS, 20)
        scan_state = CleanScanState(total=len(ips))
        self.active_clean_state = scan_state
        
        progress = self.query_one("#clean-progress", ProgressBar)
        progress.total = len(ips)
        update_task = asyncio.create_task(self.update_clean_loop(scan_state))
        try:
            await scan_clean_ips(ips, workers=100, timeout=3.0, validate=True, scan_state=scan_state)
        finally:
            update_task.cancel()
            self.update_clean_results(scan_state)
            self.toggle_buttons("start-clean", "stop-clean", False, "export-clean")
            msg = "IP Search interrupted" if scan_state.interrupted else "IP Search complete"
            self.log_activity(f"Clean IP: {msg}")
            self.notify(msg)

    def action_stop_clean(self) -> None:
        if self.active_clean_state:
            self.active_clean_state.interrupted = True
        for worker in self.workers:
            if worker.name == "clean":
                worker.cancel()

    def action_export_clean(self) -> None:
        if not self.active_clean_state or not self.active_clean_state.all_results:
            self.notify("No IP data to export", title="Warning")
            return
        path = _results_path("clean_ips.txt")
        with open(path, "w") as f:
            for ip, lat in sorted(self.active_clean_state.all_results, key=lambda x: x[1]):
                f.write(f"{ip}\n")
        self.notify(f"Exported to {os.path.basename(path)}", title="Success")

    async def update_clean_loop(self, scan_state: CleanScanState) -> None:
        progress = self.query_one("#clean-progress", ProgressBar)
        while scan_state.done < scan_state.total:
            progress.progress = scan_state.done
            self.update_clean_results(scan_state)
            await asyncio.sleep(0.5)

    def update_clean_results(self, scan_state: CleanScanState) -> None:
        table = self.query_one("#clean-results-table", DataTable)
        table.clear()
        for ip, lat in scan_state.results[:100]:
            table.add_row(ip, f"{lat:.0f}ms")
        self.query_one("#dash-clean", Label).update(f"Clean IPs Found: [b]{scan_state.found}[/]")

    @work(exclusive=True, name="xray")
    async def action_start_xray(self) -> None:
        uri = self.query_one("#xray-uri-input", Input).value.strip()
        if not uri:
            self.notify("Please enter a VLESS/VMess URI", title="Warning")
            return
        parsed = parse_vless_full(uri) or parse_vmess_full(uri)
        if not parsed:
            self.notify("Invalid URI", title="Error")
            return
            
        xray_bin = xray_find_binary() or xray_install()
        if not xray_bin:
            self.notify("Failed to find or install Xray", title="Error")
            return
            
        self.log_activity("Xray Test: Starting pipeline...")
        self.toggle_buttons("start-xray", "stop-xray", True, "export-xray")
        xst = XrayTestState()
        self.active_xray_state = xst
        xst.source_uri = uri
        pcfg = PipelineConfig(uri=uri, parsed=parsed, frag_preset="all", max_expansion=500)
        
        update_task = asyncio.create_task(self.update_xray_loop(xst))
        try:
            await xray_pipeline_test(xst, pcfg)
        finally:
            update_task.cancel()
            self.update_xray_results(xst)
            self.toggle_buttons("start-xray", "stop-xray", False, "export-xray")
            msg = "Xray test interrupted" if xst.interrupted else "Xray test complete"
            self.log_activity(f"Xray Test: {msg}")
            self.notify(msg)

    def action_stop_xray(self) -> None:
        if self.active_xray_state:
            self.active_xray_state.interrupted = True
        for worker in self.workers:
            if worker.name == "xray":
                worker.cancel()

    def action_export_xray(self) -> None:
        if not self.active_xray_state or not self.active_xray_state.variations:
            self.notify("No test data to export", title="Warning")
            return
        csv_p, uri_p = xray_save_results(self.active_xray_state)
        self.notify(f"Exported to {os.path.basename(uri_p)}", title="Success")

    async def update_xray_loop(self, xst: XrayTestState) -> None:
        progress = self.query_one("#xray-progress", ProgressBar)
        stage_label = self.query_one("#xray-stage-label", Label)
        while not xst.finished:
            progress.total = xst.total
            progress.progress = xst.done_count
            stage_label.update(f"Current Stage: [b]{xst.phase_label}[/]")
            self.update_xray_results(xst)
            await asyncio.sleep(0.5)

    def update_xray_results(self, xst: XrayTestState) -> None:
        table = self.query_one("#xray-results-table", DataTable)
        table.clear()
        sorted_vars = sorted(xst.variations, key=lambda v: v.score, reverse=True)
        for i, v in enumerate(sorted_vars[:50], 1):
            frag = "none" if v.fragment is None else v.fragment.get("length", "?")
            table.add_row(str(i), v.sni[:20], str(frag), f"{v.connect_ms:.0f}ms", f"{v.ttfb_ms:.0f}ms", f"{v.score:.1f}")

if __name__ == "__main__":
    app = CFEdgeApp()
    app.run()

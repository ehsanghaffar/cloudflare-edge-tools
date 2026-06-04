from __future__ import annotations

from typing import Optional

from textual.app import App, ComposeResult
from textual.widgets import Header, Footer, TabbedContent, TabPane
from textual.binding import Binding
from textual.widget import Widget

from src.screens.dashboard import DashboardScreen
from src.screens.scanner import ScannerScreen
from src.screens.clean_ip import CleanIPScreen
from src.screens.xray import XrayScreen
from src.screens.deploy import DeployScreen


class CFEdgeApp(App):
    CSS_PATH = "app.tcss"
    TITLE = "Cloudflare Edge Scanner"
    SUB_TITLE = "v1.1"

    BINDINGS = [
        Binding("q", "quit", "Quit", show=True),
        Binding("d", "switch_tab('dash')", "Dashboard", show=True),
        Binding("1", "switch_tab('scanner')", "Scanner", show=True),
        Binding("2", "switch_tab('clean')", "Clean IP", show=True),
        Binding("3", "switch_tab('xray')", "Xray", show=True),
        Binding("4", "switch_tab('deploy')", "Deploy", show=True),
    ]

    def __init__(self):
        super().__init__()
        self._dashboard: Optional[DashboardScreen] = None
        self._scanner: Optional[ScannerScreen] = None
        self._clean_ip: Optional[CleanIPScreen] = None
        self._xray: Optional[XrayScreen] = None
        self._deploy: Optional[DeployScreen] = None

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with TabbedContent(id="main-tabs", initial="dash"):
            with TabPane("📊 Dashboard", id="dash"):
                yield DashboardScreen()
            with TabPane("🔍 Scanner", id="scanner"):
                yield ScannerScreen()
            with TabPane("🌐 Clean IP", id="clean"):
                yield CleanIPScreen()
            with TabPane("⚡ Xray", id="xray"):
                yield XrayScreen()
            with TabPane("🚀 Deploy", id="deploy"):
                yield DeployScreen()
        yield Footer()

    def on_mount(self):
        self._dashboard = self.query_one(DashboardScreen)
        self._scanner = self.query_one(ScannerScreen)
        self._clean_ip = self.query_one(CleanIPScreen)
        self._xray = self.query_one(XrayScreen)
        self._deploy = self.query_one(DeployScreen)
        self._dashboard.log_activity("System initialized")

    def action_switch_tab(self, tab: str):
        tc = self.query_one(TabbedContent)
        tc.active = tab

    def switch_mode(self, mode: str):
        tc = self.query_one(TabbedContent)
        if mode in ("dash", "scanner", "clean", "xray", "deploy"):
            tc.active = mode

    def get_dashboard(self) -> Optional[DashboardScreen]:
        return self._dashboard

    def get_scanner(self) -> Optional[ScannerScreen]:
        return self._scanner

    def get_clean_ip(self) -> Optional[CleanIPScreen]:
        return self._clean_ip

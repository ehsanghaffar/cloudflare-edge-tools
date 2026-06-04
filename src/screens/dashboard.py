from __future__ import annotations

import os
import time
from typing import ClassVar

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical, Container
from textual.reactive import reactive
from textual.widgets import Static, Label, Button, ListView, ListItem, RichLog
from textual.screen import Screen
from textual.widget import Widget


from src.constants import VERSION


class StatCard(Static):
    def __init__(self, title: str, value: str = "-", icon: str = "", color: str = "$accent"):
        super().__init__()
        self._stat_title = title
        self._stat_value = value
        self._stat_icon = icon
        self._stat_color = color

    def compose(self) -> ComposeResult:
        with Vertical(classes="stat-card"):
            yield Label(f"{self._stat_icon} {self._stat_title}", classes="stat-title")
            yield Label(self._stat_value, id="stat-value", classes="stat-value")

    def update_value(self, value: str):
        self.query_one("#stat-value", Label).update(value)


class DashboardScreen(Widget):
    BINDINGS: ClassVar = []

    def compose(self) -> ComposeResult:
        with Container(id="dash-container"):
            yield Static(id="dash-header")
            with Horizontal(id="stats-row"):
                yield StatCard("Configs Loaded", "0", "📄", "$success")
                yield StatCard("Clean IPs Found", "0", "🌐", "$accent")
                yield StatCard("Last Scan", "-", "⏱️", "$warning")
                yield StatCard("Best Speed", "-", "🚀", "$secondary")
            with Horizontal(id="quick-actions"):
                yield Button("Open Scanner", id="btn-goto-scanner", variant="primary")
                yield Button("Clean IP Finder", id="btn-goto-clean", variant="default")
                yield Button("Xray Pipeline", id="btn-goto-xray", variant="default")
                yield Button("Deploy Server", id="btn-goto-deploy", variant="default")
            with Vertical(id="activity-section"):
                yield Label("ACTIVITY LOG", classes="section-title")
                yield RichLog(id="activity-log", max_lines=100, highlight=True, markup=True)

    def on_mount(self):
        header = self.query_one("#dash-header", Static)
        header.update(
            f"[bold $accent]Cloudflare Edge Scanner[/] [dim]v{VERSION}[/]\n"
            f"[dim]Network performance testing & proxy optimization tool[/]"
        )
        self._ensure_subscribed()

    def on_button_pressed(self, event: Button.Pressed):
        btn_id = event.button.id or ""
        if btn_id == "btn-goto-scanner":
            self.app.switch_mode("scanner")
        elif btn_id == "btn-goto-clean":
            self.app.switch_mode("clean")
        elif btn_id == "btn-goto-xray":
            self.app.switch_mode("xray")
        elif btn_id == "btn-goto-deploy":
            self.app.switch_mode("deploy")

    def log_activity(self, message: str):
        try:
            log = self.query_one("#activity-log", RichLog)
            log.write(f"[dim][{time.strftime('%H:%M:%S')}][/] {message}")
        except Exception:
            pass

    def update_stats(self, configs: int = 0, clean_ips: int = 0, last_scan: str = "-", best_speed: str = "-"):
        cards = list(self.query("#stats-row StatCard"))
        if len(cards) >= 4:
            cards[0].update_value(str(configs))
            cards[1].update_value(str(clean_ips))
            cards[2].update_value(last_scan)
            cards[3].update_value(best_speed)

    def _ensure_subscribed(self):
        pass

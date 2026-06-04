from __future__ import annotations

import os
import sys
import time
from typing import ClassVar, Optional

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical, Container
from textual.widget import Widget
from textual.widgets import Static, Label, Button, RichLog, Input, RadioSet, RadioButton
from textual.binding import Binding
from textual import work

from src.deploy_utils import _tui_run_deploy


class DeployScreen(Widget):
    BINDINGS: ClassVar = []

    def compose(self) -> ComposeResult:
        with Horizontal():
            with Vertical(classes="pane-left"):
                yield Label("DEPLOYMENT OPTIONS", classes="section-title")
                yield Label("[dim]Protocol[/]")
                with RadioSet(id="deploy-protocol"):
                    yield RadioButton("VLESS", value=True, id="proto-vless")
                    yield RadioButton("VMess", value=False, id="proto-vmess")
                yield Label("[dim]Transport[/]")
                with RadioSet(id="deploy-transport"):
                    yield RadioButton("TCP", value=True, id="trans-tcp")
                    yield RadioButton("WebSocket", value=False, id="trans-ws")
                    yield RadioButton("gRPC", value=False, id="trans-grpc")
                    yield RadioButton("HTTP/2", value=False, id="trans-h2")
                yield Label("[dim]Security[/]")
                with RadioSet(id="deploy-security"):
                    yield RadioButton("REALITY", value=True, id="sec-reality")
                    yield RadioButton("TLS", value=False, id="sec-tls")
                    yield RadioButton("None", value=False, id="sec-none")
                yield Label("CONTROLS", classes="section-title")
                yield Button("▶ Deploy Xray", id="btn-deploy", variant="primary")
                if sys.platform != "linux":
                    yield Static("[yellow]⚠ Deploy requires Linux[/]", classes="warning-text")
            with Vertical(classes="pane-right"):
                yield Label("OUTPUT CONSOLE", classes="section-title")
                yield RichLog(id="deploy-console", max_lines=200, highlight=True, markup=True)

    def on_mount(self):
        self._log("[dim]Deploy Xray on a Linux VPS[/]")
        self._log("[dim]Configure protocol, transport, and security above, then press Deploy[/]")
        if sys.platform != "linux":
            self._log("[yellow]⚠ Deploy is only available on Linux[/]")

    def on_button_pressed(self, event: Button.Pressed):
        if event.button.id == "btn-deploy":
            if sys.platform != "linux":
                self.app.notify("Deploy requires Linux", severity="error")
                return
            self._run_deploy()

    @work(thread=False)
    async def _run_deploy(self):
        self._log("[green]Starting deployment...[/]")
        try:
            await _tui_run_deploy()
            self._log("[green]Deployment complete[/]")
            self.app.notify("Deployment complete", severity="information")
        except Exception as e:
            self._log(f"[red]Deployment error: {e}[/]")
            self.app.notify(f"Deployment error: {e}", severity="error")

    def _log(self, msg: str):
        try:
            log = self.query_one("#deploy-console", RichLog)
            log.write(f"[dim][{time.strftime('%H:%M:%S')}][/] {msg}")
        except Exception:
            pass

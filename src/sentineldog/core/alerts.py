from __future__ import annotations

import json
import logging
import os
import sys
import time
import urllib.request
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    HAS_RICH = True
except ImportError:
    HAS_RICH = False


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class IncidentCategory(str, Enum):
    ROOTKIT_CROSS_VIEW = "ROOTKIT_CROSS_VIEW"
    ROOTKIT_LD_PRELOAD = "ROOTKIT_LD_PRELOAD"
    ROOTKIT_KERNEL = "ROOTKIT_KERNEL"
    ROOTKIT_NETWORK = "ROOTKIT_NETWORK"
    FIM_INTEGRITY = "FIM_INTEGRITY"
    LOG_BRUTE_FORCE = "LOG_BRUTE_FORCE"
    LOG_PRIV_ESC = "LOG_PRIV_ESC"
    LOG_ACCOUNT = "LOG_ACCOUNT"
    SYSTEM_ANOMALY = "SYSTEM_ANOMALY"


@dataclass
class SecurityIncident:
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    category: IncidentCategory = IncidentCategory.SYSTEM_ANOMALY
    severity: Severity = Severity.MEDIUM
    title: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    recommendation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "category": self.category.value if isinstance(self.category, IncidentCategory) else str(self.category),
            "severity": self.severity.value if isinstance(self.severity, Severity) else str(self.severity),
            "title": self.title,
            "details": self.details,
            "recommendation": self.recommendation,
        }


class AlertManager:
    """Dispatches alerts to Console, JSON file, and optional Webhooks."""

    def __init__(
        self,
        console_output: bool = True,
        json_log_path: Optional[str] = "logs/incidents.json",
        webhook_url: Optional[str] = None
    ) -> None:
        self.console_output = console_output
        self.json_log_path = Path(json_log_path) if json_log_path else None
        self.webhook_url = webhook_url
        self.recent_incidents: List[SecurityIncident] = []
        self._max_history = 100

        if HAS_RICH:
            self.console = Console()
        else:
            self.console = None

        if self.json_log_path:
            self.json_log_path.parent.mkdir(parents=True, exist_ok=True)

    def trigger(self, incident: SecurityIncident) -> None:
        """Process and dispatch a new security incident."""
        self.recent_incidents.append(incident)
        if len(self.recent_incidents) > self._max_history:
            self.recent_incidents.pop(0)

        # 1. Console Output
        if self.console_output:
            self._render_console(incident)

        # 2. JSON File Logging
        if self.json_log_path:
            self._write_json_log(incident)

        # 3. Webhook Dispatch
        if self.webhook_url:
            self._dispatch_webhook(incident)

    def _render_console(self, incident: SecurityIncident) -> None:
        color_map = {
            Severity.INFO: "blue",
            Severity.LOW: "cyan",
            Severity.MEDIUM: "yellow",
            Severity.HIGH: "red",
            Severity.CRITICAL: "bold red on black",
        }
        color = color_map.get(incident.severity, "white")

        if HAS_RICH and self.console:
            table = Table(show_header=False, box=None, padding=(0, 1))
            table.add_row("[bold]Category:[/bold]", f"[cyan]{incident.category.value}[/cyan]")
            table.add_row("[bold]Time:[/bold]", f"[dim]{incident.timestamp}[/dim]")
            for k, v in incident.details.items():
                table.add_row(f"[bold]{k}:[/bold]", str(v))
            if incident.recommendation:
                table.add_row("[bold yellow]Remedy:[/bold yellow]", f"[italic]{incident.recommendation}[/italic]")

            panel = Panel(
                table,
                title=f"[{color}][ALERT] {incident.severity.value}: {incident.title}[/{color}]",
                border_style=color.split()[0],
                expand=False,
            )
            self.console.print(panel)
        else:
            print(f"\n[!] ALERT [{incident.severity.value}] {incident.title}")
            print(f"    Category: {incident.category.value} | Time: {incident.timestamp}")
            for k, v in incident.details.items():
                print(f"    {k}: {v}")
            if incident.recommendation:
                print(f"    Remedy: {incident.recommendation}\n")

    def _write_json_log(self, incident: SecurityIncident) -> None:
        try:
            with open(self.json_log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(incident.to_dict()) + "\n")
        except Exception as e:
            sys.stderr.write(f"[-] Failed to write alert to {self.json_log_path}: {e}\n")

    def _dispatch_webhook(self, incident: SecurityIncident) -> None:
        if not self.webhook_url:
            return
        payload = {
            "content": f"🚨 **[SentinelDog Alert: {incident.severity.value}]** {incident.title}",
            "embeds": [{
                "title": incident.title,
                "description": f"**Category:** `{incident.category.value}`\n**Remedy:** {incident.recommendation}",
                "color": 15158332 if incident.severity in [Severity.HIGH, Severity.CRITICAL] else 15105570,
                "fields": [{"name": k, "value": str(v), "inline": True} for k, v in list(incident.details.items())[:5]],
                "timestamp": incident.timestamp
            }]
        }
        try:
            req = urllib.request.Request(
                self.webhook_url,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json", "User-Agent": "SentinelDog/1.0"}
            )
            urllib.request.urlopen(req, timeout=5)
        except Exception as e:
            sys.stderr.write(f"[-] Webhook dispatch error: {e}\n")

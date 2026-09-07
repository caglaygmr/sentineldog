from __future__ import annotations

import argparse
import asyncio
import os
import sys
from pathlib import Path
from typing import List, Optional

try:
    from rich import print as rprint
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

from . import __version__
from .core.alerts import Severity
from .core.baseline import BaselineManager
from .core.config import AppConfig
from .core.engine import WatchdogEngine


BANNER = r"""
  ____             _   _            _ ____              
 / ___|  ___ _ __ | |_(_)_ __   ___| |  _ \  ___   __ _ 
 \___ \ / _ \ '_ \| __| | '_ \ / _ \ | | | |/ _ \ / _` |
  ___) |  __/ | | | |_| | | | |  __/ | |_| | (_) | (_| |
 |____/ \___|_| |_|\__|_|_| |_|\___|_|____/ \___/ \__, |
 Linux Security Watchdog & Rootkit Sentinel       |___/ 
"""


def render_banner() -> None:
    if HAS_RICH:
        console = Console()
        console.print(f"[bold cyan]{BANNER}[/bold cyan]")
        console.print(f"[dim]Version {__version__} | Autonomous Defense & Cross-View Rootkit Detection[/dim]\n")
    else:
        print(BANNER)
        print(f"Version {__version__} | Autonomous Defense & Cross-View Rootkit Detection\n")


def cmd_scan(args: argparse.Namespace) -> int:
    """Executes a diagnostic security scan across all subsystems."""
    render_banner()
    cfg = AppConfig.load(config_path=args.config)
    engine = WatchdogEngine(cfg)

    if HAS_RICH:
        console = Console()
        with console.status("[bold green]Conducting deep cross-view & rootkit diagnostic scan...[/bold green]"):
            incidents = engine.scan_all(full_pid_sweep=args.full)
    else:
        print("[*] Conducting deep cross-view & rootkit diagnostic scan...")
        incidents = engine.scan_all(full_pid_sweep=args.full)

    # Print summary table
    if HAS_RICH:
        console = Console()
        table = Table(title="Diagnostic Scan Summary", show_lines=True)
        table.add_column("Subsystem / Detector", style="cyan", no_wrap=True)
        table.add_column("Status", style="bold")
        table.add_column("Incidents", justify="right")

        # Categorize
        cross_view_cnt = sum(1 for i in incidents if i.category.value.startswith("ROOTKIT_CROSS"))
        preload_cnt = sum(1 for i in incidents if i.category.value.startswith("ROOTKIT_LD"))
        kernel_cnt = sum(1 for i in incidents if i.category.value.startswith("ROOTKIT_KERNEL"))
        net_cnt = sum(1 for i in incidents if i.category.value.startswith("ROOTKIT_NETWORK"))
        fim_cnt = sum(1 for i in incidents if i.category.value.startswith("FIM"))

        def status_str(cnt: int) -> str:
            return "[green]PASSED (CLEAN)[/green]" if cnt == 0 else "[red]ANOMALY DETECTED[/red]"

        table.add_row("Process Cross-View (Syscall vs /proc)", status_str(cross_view_cnt), str(cross_view_cnt))
        table.add_row("Dynamic Linker Hooks (/etc/ld.so.preload)", status_str(preload_cnt), str(preload_cnt))
        table.add_row("Kernel Modules & Taint Flags", status_str(kernel_cnt), str(kernel_cnt))
        table.add_row("Hidden Sockets & Backdoors", status_str(net_cnt), str(net_cnt))
        table.add_row("File Integrity Monitoring (FIM)", status_str(fim_cnt), str(fim_cnt))

        console.print(table)
        if incidents:
            console.print(f"\n[bold red]⚠️ Total {len(incidents)} security incident(s) detected![/bold red]")
            return 1
        else:
            console.print("\n[bold green]✓ System integrity verified: No rootkit hooks or discrepancies found.[/bold green]")
            return 0
    else:
        print(f"\nScan completed. Total incidents: {len(incidents)}")
        return 1 if incidents else 0


def cmd_watch(args: argparse.Namespace) -> int:
    """Runs SentinelDog in real-time daemon mode."""
    render_banner()
    cfg = AppConfig.load(config_path=args.config)
    engine = WatchdogEngine(cfg)

    if HAS_RICH:
        console = Console()
        console.print(f"[bold green]▶ SentinelDog daemon started[/bold green]")
        console.print(f"  • Deep Scan Interval : [cyan]{cfg.general.deep_scan_interval_seconds}s[/cyan]")
        console.print(f"  • Log Sentinel       : [cyan]{', '.join(cfg.log_sentinel.target_logs)}[/cyan]")
        console.print(f"  • Incident Log       : [cyan]{cfg.alerts.json_log_path}[/cyan]")
        console.print("[dim]Press Ctrl+C to stop.\n[/dim]")
    else:
        print("[*] SentinelDog daemon started.")
        print("Press Ctrl+C to stop.\n")

    try:
        asyncio.run(engine.start())
    except KeyboardInterrupt:
        if HAS_RICH:
            Console().print("\n[yellow][*] Watchdog stopped gracefully.[/yellow]")
        else:
            print("\n[*] Watchdog stopped gracefully.")
    return 0


def cmd_baseline(args: argparse.Namespace) -> int:
    """Generates or updates the cryptographic FIM baseline."""
    render_banner()
    cfg = AppConfig.load(config_path=args.config)

    paths_to_monitor = args.paths if args.paths else cfg.fim.monitored_paths
    baseline_mgr = BaselineManager(cfg.fim.baseline_path)

    if HAS_RICH:
        console = Console()
        with console.status(f"[bold green]Hashing {len(paths_to_monitor)} monitored paths...[/bold green]"):
            snapshot = baseline_mgr.create_snapshot(paths_to_monitor)
            baseline_mgr.save(snapshot)
        console.print(f"[bold green]✓ Baseline created successfully:[/bold green] [cyan]{len(snapshot)}[/cyan] files indexed.")
        console.print(f"  Saved to: [dim]{cfg.fim.baseline_path}[/dim]")
    else:
        snapshot = baseline_mgr.create_snapshot(paths_to_monitor)
        baseline_mgr.save(snapshot)
        print(f"Baseline created: {len(snapshot)} files indexed in {cfg.fim.baseline_path}")

    return 0


def cmd_status(args: argparse.Namespace) -> int:
    """Displays current configuration and baseline health."""
    render_banner()
    cfg = AppConfig.load(config_path=args.config)
    baseline_mgr = BaselineManager(cfg.fim.baseline_path)
    existing = baseline_mgr.load()

    if HAS_RICH:
        console = Console()
        table = Table(title="SentinelDog Status", show_header=False)
        table.add_row("Service Name", cfg.general.service_name)
        table.add_row("Baseline DB", f"{cfg.fim.baseline_path} ({len(existing)} files indexed)")
        table.add_row("Monitored Paths", str(len(cfg.fim.monitored_paths)))
        table.add_row("Incident Log File", cfg.alerts.json_log_path)
        table.add_row("Webhook Configured", "Yes" if cfg.alerts.webhook_url else "No")
        console.print(table)
    else:
        print(f"Service: {cfg.general.service_name}")
        print(f"Baseline DB: {cfg.fim.baseline_path} ({len(existing)} entries)")
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="sentineldog",
        description="SentinelDog: Linux Security Watchdog, Rootkit Cross-View Detector & Log Sentinel",
    )
    parser.add_argument("-v", "--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("-c", "--config", help="Custom configuration file path (YAML)")

    subparsers = parser.add_subparsers(dest="command", required=True)

    # scan command
    scan_p = subparsers.add_parser("scan", help="Run a one-time comprehensive diagnostic scan")
    scan_p.add_argument("--full", action="store_true", help="Perform full 65535 PID sweep (thorough)")
    scan_p.set_defaults(func=cmd_scan)

    # watch command
    watch_p = subparsers.add_parser("watch", help="Run in continuous watchdog daemon mode")
    watch_p.set_defaults(func=cmd_watch)

    # baseline command
    base_p = subparsers.add_parser("baseline", help="Manage cryptographic FIM baseline")
    base_sub = base_p.add_subparsers(dest="base_action", required=True)
    b_create = base_sub.add_parser("create", help="Create or refresh file baseline")
    b_create.add_argument("--paths", nargs="*", help="Specific paths to hash into baseline")
    b_create.set_defaults(func=cmd_baseline)

    # status command
    stat_p = subparsers.add_parser("status", help="Show configuration and baseline status")
    stat_p.set_defaults(func=cmd_status)

    args = parser.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()

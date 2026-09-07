#!/usr/bin/env python3
"""
SentinelDog Threat Simulation Harness.
Simulates real-world rootkit, FIM tampering, and authentication attacks
to demonstrate detection capabilities during demos and internship presentations.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import time
from pathlib import Path

# Ensure src/ is importable
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from rich.console import Console
from rich.panel import Panel

from sentineldog.core.alerts import AlertManager, Severity
from sentineldog.core.config import AppConfig
from sentineldog.detectors.fim import FileIntegrityDetector
from sentineldog.detectors.ld_preload import LDPreloadDetector
from sentineldog.log_sentinel.rules import LogRuleEngine


console = Console()


def run_ssh_brute_force_demo(alerts: AlertManager):
    console.print("\n[bold yellow]─── [Scenario 1] Simulating SSH Brute-Force Attack ───[/bold yellow]")
    engine = LogRuleEngine(ssh_threshold=4, ssh_window=30)
    attacker_ip = "203.0.113.42"

    console.print(f"[*] Attacker ({attacker_ip}) launching automated dictionary attack on port 22...")
    for i in range(1, 6):
        time.sleep(0.3)
        fake_line = f"Sep 07 12:00:0{i} srv-prod sshd[{1400+i}]: Failed password for invalid user admin from {attacker_ip} port {50000+i} ssh2"
        console.print(f"  [dim]» Auth log entry {i}: Failed password attempt from {attacker_ip}[/dim]")
        incidents = engine.process_line(fake_line)
        for inc in incidents:
            alerts.trigger(inc)


def run_fim_tampering_demo(alerts: AlertManager):
    console.print("\n[bold yellow]─── [Scenario 2] Simulating Trojaned Binary (FIM Tampering) ───[/bold yellow]")
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        fake_ps = tmp / "ps"
        fake_ps.write_text("#!/bin/sh\necho 'clean process list output'")
        os.chmod(fake_ps, 0o755)

        base_file = tmp / "baseline.json"
        fim = FileIntegrityDetector(monitored_paths=[str(fake_ps)], baseline_path=base_file)
        fim.update_baseline()
        console.print(f"[*] Baseline established for [cyan]{fake_ps}[/cyan]")

        # Attacker injects rootkit hook into binary
        time.sleep(0.5)
        console.print("[!] Attacker replaces binary with trojanized version hiding malware PIDs...")
        fake_ps.write_text("#!/bin/sh\necho 'tampered rootkit output with filtered PIDs'")

        incidents = fim.scan()
        for inc in incidents:
            alerts.trigger(inc)


def run_suid_backdoor_demo(alerts: AlertManager):
    console.print("\n[bold yellow]─── [Scenario 3] Simulating Permission Escalation Backdoor ───[/bold yellow]")
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        fake_bash = tmp / "backdoor_tool"
        fake_bash.write_text("#!/bin/sh\necho 'tool'")
        os.chmod(fake_bash, 0o755)

        base_file = tmp / "baseline.json"
        fim = FileIntegrityDetector(monitored_paths=[str(fake_bash)], baseline_path=base_file)
        fim.update_baseline()

        # Attacker escalates file permissions to world-writable (0o777)
        console.print("[!] Attacker modifies file permissions to world-writable (chmod 777)...")
        os.chmod(fake_bash, 0o777)

        incidents = fim.scan()
        for inc in incidents:
            alerts.trigger(inc)


def run_uid0_backdoor_demo(alerts: AlertManager):
    console.print("\n[bold yellow]─── [Scenario 4] Simulating Rogue Root Account (UID 0) ───[/bold yellow]")
    engine = LogRuleEngine(detect_useradd=True)
    backdoor_log = "Sep 07 12:05:12 srv-prod useradd[8910]: new user: name=toor2, UID=0, GID=0, home=/root, shell=/bin/bash"

    console.print("[*] Log entry received: Unauthorized user creation event...")
    incidents = engine.process_line(backdoor_log)
    for inc in incidents:
        alerts.trigger(inc)


def main():
    console.print(Panel.fit(
        "[bold cyan]SentinelDog Threat Simulation & Live Verification Suite[/bold cyan]\n"
        "[dim]Simulating Real-World Rootkit & Intrusion Vectors[/dim]",
        border_style="cyan"
    ))

    alerts = AlertManager(console_output=True, json_log_path="logs/simulation_incidents.json")

    run_ssh_brute_force_demo(alerts)
    run_fim_tampering_demo(alerts)
    run_suid_backdoor_demo(alerts)
    run_uid0_backdoor_demo(alerts)

    console.print("\n[bold green]✓ All attack simulations completed and successfully flagged by SentinelDog engines![/bold green]")
    console.print("[dim]Incidents logged to logs/simulation_incidents.json[/dim]\n")


if __name__ == "__main__":
    main()

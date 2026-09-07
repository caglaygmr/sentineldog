from __future__ import annotations

import asyncio
import logging
import signal
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from .alerts import AlertManager, IncidentCategory, SecurityIncident, Severity
from .baseline import BaselineManager
from .config import AppConfig
from ..detectors.cross_view import CrossViewDetector
from ..detectors.fim import FileIntegrityDetector
from ..detectors.kernel import KernelRootkitDetector
from ..detectors.ld_preload import LDPreloadDetector
from ..detectors.network import NetworkStealthDetector
from ..log_sentinel.rules import LogRuleEngine
from ..log_sentinel.watcher import LogFileWatcher


class WatchdogEngine:
    """
    Central orchestration engine for SentinelDog.
    Coordinates periodic scans, real-time log tailing, and incident reporting.
    """

    def __init__(self, config: Optional[AppConfig] = None) -> None:
        self.config = config or AppConfig.load()
        self.alerts = AlertManager(
            console_output=self.config.alerts.console_output,
            json_log_path=self.config.alerts.json_log_path,
            webhook_url=self.config.alerts.webhook_url,
        )

        # Initialize detectors
        self.cross_view = CrossViewDetector(max_pid=self.config.rootkit.max_pid_sweep)
        self.ld_preload = LDPreloadDetector()
        self.network = NetworkStealthDetector()
        
        # Load known signatures if present
        known_mods = self.config.signatures.get("rootkit_signatures", {}).get("known_modules", [])
        self.kernel = KernelRootkitDetector(known_signatures=known_mods)

        self.fim = FileIntegrityDetector(
            monitored_paths=self.config.fim.monitored_paths,
            baseline_path=self.config.fim.baseline_path,
        )

        self.log_rules = LogRuleEngine(
            ssh_threshold=self.config.log_sentinel.ssh_brute_force_threshold,
            ssh_window=self.config.log_sentinel.ssh_brute_force_window,
            sudo_threshold=self.config.log_sentinel.sudo_fail_threshold,
            detect_useradd=self.config.log_sentinel.detect_useradd,
            detect_uid0=self.config.log_sentinel.detect_uid0,
        )
        self.log_watcher = LogFileWatcher(
            target_paths=self.config.log_sentinel.target_logs,
            poll_interval=1.0,
        )

        self.is_running = False
        self.total_scans_performed = 0

    def scan_all(self, full_pid_sweep: bool = False) -> List[SecurityIncident]:
        """Runs a complete one-shot security diagnostic scan."""
        all_incidents: List[SecurityIncident] = []

        # 1. Rootkit: Cross-View Process Check
        if self.config.rootkit.enabled and self.config.rootkit.enable_cross_view:
            incidents = self.cross_view.scan(full_sweep=full_pid_sweep)
            for inc in incidents:
                self.alerts.trigger(inc)
            all_incidents.extend(incidents)

        # 2. Rootkit: LD_PRELOAD Hooks
        if self.config.rootkit.enabled and self.config.rootkit.enable_ld_preload:
            incidents = self.ld_preload.scan()
            for inc in incidents:
                self.alerts.trigger(inc)
            all_incidents.extend(incidents)

        # 3. Rootkit: Kernel Taints & Hidden LKMs
        if self.config.rootkit.enabled and self.config.rootkit.enable_kernel_modules:
            incidents = self.kernel.scan()
            for inc in incidents:
                self.alerts.trigger(inc)
            all_incidents.extend(incidents)

        # 4. Rootkit: Hidden Network Ports
        if self.config.rootkit.enabled and self.config.rootkit.enable_hidden_network:
            incidents = self.network.scan()
            for inc in incidents:
                self.alerts.trigger(inc)
            all_incidents.extend(incidents)

        # 5. File Integrity Monitoring (FIM)
        if self.config.fim.enabled:
            incidents = self.fim.scan()
            for inc in incidents:
                self.alerts.trigger(inc)
            all_incidents.extend(incidents)

        self.total_scans_performed += 1
        return all_incidents

    async def _periodic_deep_scan(self) -> None:
        """Background task running deep rootkit and FIM checks at configured intervals."""
        while self.is_running:
            try:
                self.scan_all(full_pid_sweep=False)
            except Exception as e:
                sys.stderr.write(f"[-] Error during periodic scan: {e}\n")
            await asyncio.sleep(self.config.general.deep_scan_interval_seconds)

    async def _tail_logs_task(self) -> None:
        """Background task tailing security logs and evaluating rules in real time."""
        if not self.config.log_sentinel.enabled:
            return

        try:
            async for path, line in self.log_watcher.follow():
                if not self.is_running:
                    break
                incidents = self.log_rules.process_line(line)
                for inc in incidents:
                    self.alerts.trigger(inc)
        except asyncio.CancelledError:
            pass
        except Exception as e:
            sys.stderr.write(f"[-] Error in log tailer task: {e}\n")

    async def start(self) -> None:
        """Starts the asynchronous watchdog daemon."""
        self.is_running = True

        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, self.stop)
            except (NotImplementedError, RuntimeError):
                pass

        # Perform initial startup diagnostic
        self.scan_all(full_pid_sweep=False)

        # Launch concurrent background workers
        tasks = [
            asyncio.create_task(self._periodic_deep_scan(), name="DeepScanTask"),
            asyncio.create_task(self._tail_logs_task(), name="LogTailTask"),
        ]

        try:
            await asyncio.gather(*tasks)
        except asyncio.CancelledError:
            pass

    def stop(self) -> None:
        """Stops the watchdog engine."""
        self.is_running = False

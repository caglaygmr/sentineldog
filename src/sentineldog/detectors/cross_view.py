from __future__ import annotations

import errno
import os
import sys
import time
from pathlib import Path
from typing import Dict, List, Set, Tuple

try:
    import psutil
except ImportError:
    psutil = None

from ..core.alerts import IncidentCategory, SecurityIncident, Severity


class CrossViewDetector:
    """
    Detects stealth processes hidden by rootkits using Cross-View Discrepancy Analysis.
    
    Detection Vectors:
    1. Userland Enumeration (psutil / ps)
    2. Low-level /proc filesystem directory listing
    3. Kernel Syscall Probing: os.kill(pid, 0) brute-force across the PID space
    
    If os.kill(pid, 0) confirms a PID is alive but the PID is missing from
    readdir(/proc) or userland APIs, a getdents64 / sys_call hook is hiding it.
    """

    def __init__(self, max_pid: int = 32768) -> None:
        self.max_pid = self._determine_max_pid(max_pid)

    def _determine_max_pid(self, default_limit: int) -> int:
        pid_max_path = Path("/proc/sys/kernel/pid_max")
        if pid_max_path.is_file():
            try:
                with open(pid_max_path, "r") as f:
                    val = int(f.read().strip())
                    # Cap at 65536 for quick scanning unless configured higher
                    return min(val, default_limit)
            except Exception:
                pass
        return min(default_limit, 32768)

    def get_psutil_pids(self) -> Set[int]:
        """Gets visible PIDs reported by userland process APIs."""
        if psutil:
            try:
                return set(psutil.pids())
            except Exception:
                pass
        return set()

    def get_proc_dir_pids(self) -> Set[int]:
        """Directly scans /proc directory entries for numeric folder names."""
        proc = Path("/proc")
        pids = set()
        if not proc.is_dir():
            return pids
        try:
            for entry in os.scandir("/proc"):
                if entry.is_dir() and entry.name.isdigit():
                    pids.add(int(entry.name))
        except (PermissionError, OSError):
            pass
        return pids

    def sweep_syscall_pids(self, upper_bound: int) -> Set[int]:
        """
        Probes PIDs using os.kill(pid, 0).
        If returncode is 0 or errno is EPERM, the process exists in the kernel task table.
        """
        alive_pids = set()
        for pid in range(1, upper_bound + 1):
            try:
                os.kill(pid, 0)
                alive_pids.add(pid)
            except OSError as err:
                if err.errno == errno.EPERM:
                    # Operation not permitted: process exists under another UID
                    alive_pids.add(pid)
                elif err.errno == errno.ESRCH:
                    # No such process
                    pass
                else:
                    pass
        return alive_pids

    def scan(self, full_sweep: bool = False) -> List[SecurityIncident]:
        """
        Executes cross-view verification and returns detected discrepancies.
        """
        incidents: List[SecurityIncident] = []

        # 1. Gather views
        proc_pids = self.get_proc_dir_pids()
        userland_pids = self.get_psutil_pids() or proc_pids

        # Discrepancy Check 1: In /proc dir but hidden from psutil
        hidden_from_userland = proc_pids - userland_pids
        # Filter out PID 0 / kernel transient threads
        hidden_from_userland = {p for p in hidden_from_userland if p > 0}

        if hidden_from_userland:
            # Verify persistence (prevent transient PID false positives)
            time.sleep(0.05)
            verified_hidden = set()
            for pid in hidden_from_userland:
                if Path(f"/proc/{pid}").is_dir():
                    verified_hidden.add(pid)

            if verified_hidden:
                incidents.append(
                    SecurityIncident(
                        category=IncidentCategory.ROOTKIT_CROSS_VIEW,
                        severity=Severity.HIGH,
                        title="Process Hidden from Userland APIs",
                        details={
                            "hidden_pids": sorted(list(verified_hidden)),
                            "method": "/proc directory exists but invisible to psutil/ps",
                            "count": len(verified_hidden),
                        },
                        recommendation=(
                            "Investigate potential userland rootkit (LD_PRELOAD) "
                            "or hooked libc functions filtering ps/top output."
                        ),
                    )
                )

        # Discrepancy Check 2: Kernel Syscall vs Visible Process Tables (/proc & userland)
        sweep_limit = self.max_pid if full_sweep else min(self.max_pid, 10000)
        syscall_pids = self.sweep_syscall_pids(sweep_limit)

        # A truly stealth rootkit process responds to kill(0) but is completely
        # missing from /proc directory entries AND standard userland process listings.
        visible_pids = proc_pids.union(userland_pids)
        if not visible_pids:
            return incidents

        hidden_from_visible = syscall_pids - visible_pids
        if hidden_from_visible:
            # Re-check after brief delay to eliminate process termination race conditions
            time.sleep(0.05)
            confirmed_stealth = set()
            for pid in hidden_from_visible:
                try:
                    os.kill(pid, 0)
                    # Re-verify it still exists in kernel but is still omitted from visible tables
                    rechecked_visible = self.get_proc_dir_pids().union(self.get_psutil_pids())
                    if pid not in rechecked_visible:
                        confirmed_stealth.add(pid)
                except OSError:
                    pass

            if confirmed_stealth:
                incidents.append(
                    SecurityIncident(
                        category=IncidentCategory.ROOTKIT_CROSS_VIEW,
                        severity=Severity.CRITICAL,
                        title="Critical Stealth Process Detected (Kernel Rootkit getdents Hook)",
                        details={
                            "stealth_pids": sorted(list(confirmed_stealth)),
                            "detection_technique": "kill(pid, 0) succeeded but PID missing from process tables",
                            "suspected_mechanism": "sys_getdents64 interception hiding kernel task structures",
                            "count": len(confirmed_stealth),
                        },
                        recommendation=(
                            "Immediate incident response required. A kernel module rootkit (LKM) "
                            "is manipulating directory entries to conceal malware processes. "
                            "Inspect dmesg, /proc/modules, and boot into clean media for forensic imaging."
                        ),
                    )
                )

        return incidents

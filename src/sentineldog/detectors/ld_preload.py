from __future__ import annotations

import os
from pathlib import Path
from typing import Dict, List

from ..core.alerts import IncidentCategory, SecurityIncident, Severity


class LDPreloadDetector:
    """
    Detects userland rootkits leveraging dynamic linker hijacking:
    - /etc/ld.so.preload manipulation
    - Suspicious /etc/ld.so.conf.d paths
    - Injected LD_PRELOAD / LD_LIBRARY_PATH environment variables in running processes
    """

    PRELOAD_FILE = Path("/etc/ld.so.preload")
    LD_CONF_DIR = Path("/etc/ld.so.conf.d")

    def scan(self) -> List[SecurityIncident]:
        incidents: List[SecurityIncident] = []

        # Check 1: /etc/ld.so.preload presence and content
        preload_incident = self._check_ld_preload_file()
        if preload_incident:
            incidents.append(preload_incident)

        # Check 2: Process environment inspection (/proc/<pid>/environ)
        env_incidents = self._check_process_environments()
        incidents.extend(env_incidents)

        # Check 3: Suspicious dynamic linker search paths
        conf_incident = self._check_ld_conf_paths()
        if conf_incident:
            incidents.append(conf_incident)

        return incidents

    def _check_ld_preload_file(self) -> SecurityIncident | None:
        if not self.PRELOAD_FILE.exists():
            return None

        try:
            content = self.PRELOAD_FILE.read_text(encoding="utf-8", errors="ignore").strip()
            if content:
                libraries = [line.strip() for line in content.splitlines() if line.strip() and not line.startswith("#")]
                if libraries:
                    return SecurityIncident(
                        category=IncidentCategory.ROOTKIT_LD_PRELOAD,
                        severity=Severity.CRITICAL,
                        title="Malicious /etc/ld.so.preload Detected",
                        details={
                            "preload_file": str(self.PRELOAD_FILE),
                            "injected_libraries": libraries,
                            "raw_content": content,
                        },
                        recommendation=(
                            "High-risk userland rootkit active! Libraries listed in /etc/ld.so.preload "
                            "intercept libc functions across all executed binaries. Inspect and remove rogue "
                            "shared libraries (.so) and restore /etc/ld.so.preload immediately."
                        ),
                    )
        except Exception as e:
            return SecurityIncident(
                category=IncidentCategory.ROOTKIT_LD_PRELOAD,
                severity=Severity.MEDIUM,
                title="Unable to Read /etc/ld.so.preload",
                details={"error": str(e)},
            )
        return None

    def _check_process_environments(self) -> List[SecurityIncident]:
        incidents: List[SecurityIncident] = []
        proc_dir = Path("/proc")
        if not proc_dir.is_dir():
            return incidents

        suspicious_pids: Dict[int, Dict[str, str]] = {}

        try:
            for entry in os.scandir("/proc"):
                if not (entry.is_dir() and entry.name.isdigit()):
                    continue

                pid = int(entry.name)
                environ_file = Path(entry.path) / "environ"
                if not environ_file.is_file():
                    continue

                try:
                    with open(environ_file, "rb") as f:
                        raw = f.read(8192)  # Read initial env block
                    
                    env_entries = raw.split(b"\x00")
                    for env_var in env_entries:
                        if env_var.startswith(b"LD_PRELOAD="):
                            val = env_var.decode("utf-8", errors="ignore").split("=", 1)[1]
                            if val:
                                suspicious_pids[pid] = {"LD_PRELOAD": val}
                except (PermissionError, FileNotFoundError, OSError):
                    continue
        except (PermissionError, OSError):
            pass

        if suspicious_pids:
            incidents.append(
                SecurityIncident(
                    category=IncidentCategory.ROOTKIT_LD_PRELOAD,
                    severity=Severity.HIGH,
                    title="Active Process with Injected LD_PRELOAD Environment",
                    details={
                        "affected_processes": suspicious_pids,
                        "count": len(suspicious_pids),
                    },
                    recommendation=(
                        "Process has LD_PRELOAD explicitly set in memory. "
                        "Identify the parent process, verify process binaries, and kill compromised tasks."
                    ),
                )
            )

        return incidents

    def _check_ld_conf_paths(self) -> SecurityIncident | None:
        if not self.LD_CONF_DIR.is_dir():
            return None

        suspicious_paths = []
        suspicious_keywords = ["/tmp", "/dev/shm", "/var/tmp", "/.", "hidden"]

        try:
            for conf_file in self.LD_CONF_DIR.glob("*.conf"):
                try:
                    lines = conf_file.read_text(encoding="utf-8", errors="ignore").splitlines()
                    for line in lines:
                        cleaned = line.strip()
                        if cleaned and not cleaned.startswith("#"):
                            for kw in suspicious_keywords:
                                if kw in cleaned:
                                    suspicious_paths.append({"file": str(conf_file), "path": cleaned})
                except (PermissionError, OSError):
                    continue
        except (PermissionError, OSError):
            pass

        if suspicious_paths:
            return SecurityIncident(
                category=IncidentCategory.ROOTKIT_LD_PRELOAD,
                severity=Severity.HIGH,
                title="Suspicious Dynamic Linker Configuration Search Path",
                details={"suspicious_paths": suspicious_paths},
                recommendation="Inspect /etc/ld.so.conf.d/ for rogue paths loading libraries from volatile or writable directories.",
            )
        return None

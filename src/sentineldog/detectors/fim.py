from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List

from ..core.alerts import IncidentCategory, SecurityIncident, Severity
from ..core.baseline import BaselineManager, compute_sha256


class FileIntegrityDetector:
    """
    Cryptographic File Integrity Monitor (FIM).
    Detects unauthorized alterations, trojaned core utilities (/bin/ps, /bin/ls, etc.),
    and suspicious SUID permission changes.
    """

    def __init__(
        self,
        monitored_paths: List[str],
        baseline_path: str | Path = "data/fim_baseline.json"
    ) -> None:
        self.monitored_paths = monitored_paths
        self.baseline_mgr = BaselineManager(baseline_path)
        self._baseline_cache: Dict[str, Dict[str, Any]] = self.baseline_mgr.load()

    def update_baseline(self) -> int:
        """Takes a fresh snapshot of all monitored files and saves to baseline DB."""
        snapshot = self.baseline_mgr.create_snapshot(self.monitored_paths)
        self.baseline_mgr.save(snapshot)
        self._baseline_cache = snapshot
        return len(snapshot)

    def scan(self) -> List[SecurityIncident]:
        incidents: List[SecurityIncident] = []

        if not self._baseline_cache:
            # Baseline hasn't been created yet
            return incidents

        # 1. Check existing baseline records against current system state
        for filepath_str, baseline_info in self._baseline_cache.items():
            p = Path(filepath_str)

            if not p.exists():
                incidents.append(
                    SecurityIncident(
                        category=IncidentCategory.FIM_INTEGRITY,
                        severity=Severity.HIGH,
                        title=f"Monitored Critical File Removed: {p.name}",
                        details={
                            "path": filepath_str,
                            "expected_sha256": baseline_info.get("sha256"),
                            "status": "DELETED",
                        },
                        recommendation=f"File {filepath_str} is missing. Verify if intentionally removed or compromised.",
                    )
                )
                continue

            current_hash = compute_sha256(p)
            if not current_hash:
                continue

            # Hash divergence check (Trojaned binary)
            if current_hash != baseline_info.get("sha256"):
                incidents.append(
                    SecurityIncident(
                        category=IncidentCategory.FIM_INTEGRITY,
                        severity=Severity.CRITICAL,
                        title=f"Binary Integrity Breach Detected: {p.name}",
                        details={
                            "path": filepath_str,
                            "expected_sha256": baseline_info.get("sha256"),
                            "actual_sha256": current_hash,
                            "file_size": p.stat().st_size,
                        },
                        recommendation=(
                            f"CRITICAL: {filepath_str} checksum differs from cryptographic baseline. "
                            "Binary may have been patched with a rootkit or trojan. "
                            "Restore original package binary (e.g. 'apt-get --reinstall install coreutils')."
                        ),
                    )
                )

            # Permission alteration check
            try:
                st = p.stat()
                current_mode = oct(st.st_mode)
                expected_mode = baseline_info.get("mode")
                if expected_mode and current_mode != expected_mode:
                    exp_val = int(expected_mode, 0) if isinstance(expected_mode, str) else expected_mode
                    is_suid_added = bool(st.st_mode & 0o4000) and not bool(exp_val & 0o4000)
                    is_world_writable = bool(st.st_mode & 0o0002) and not bool(exp_val & 0o0002)

                    if is_suid_added:
                        incidents.append(
                            SecurityIncident(
                                category=IncidentCategory.FIM_INTEGRITY,
                                severity=Severity.CRITICAL,
                                title=f"Unauthorized SUID Flag Added: {p.name}",
                                details={
                                    "path": filepath_str,
                                    "expected_mode": expected_mode,
                                    "actual_mode": current_mode,
                                },
                                recommendation=(
                                    f"Potential Privilege Escalation Backdoor! SUID bit was added to {filepath_str}. "
                                    f"Remove SUID flag immediately: 'chmod u-s {filepath_str}'."
                                ),
                            )
                        )
                    elif is_world_writable:
                        incidents.append(
                            SecurityIncident(
                                category=IncidentCategory.FIM_INTEGRITY,
                                severity=Severity.HIGH,
                                title=f"Insecure World-Writable Permission Added: {p.name}",
                                details={
                                    "path": filepath_str,
                                    "expected_mode": expected_mode,
                                    "actual_mode": current_mode,
                                },
                                recommendation=f"File {filepath_str} is now world-writable. Restore strict permissions.",
                            )
                        )
                    else:
                        incidents.append(
                            SecurityIncident(
                                category=IncidentCategory.FIM_INTEGRITY,
                                severity=Severity.MEDIUM,
                                title=f"File Permissions Modified: {p.name}",
                                details={
                                    "path": filepath_str,
                                    "expected_mode": expected_mode,
                                    "actual_mode": current_mode,
                                },
                                recommendation=f"Verify if permission change on {filepath_str} was authorized.",
                            )
                        )
            except OSError:
                pass

        return incidents

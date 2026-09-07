from __future__ import annotations

import os
from pathlib import Path
from typing import Dict, List, Set

from ..core.alerts import IncidentCategory, SecurityIncident, Severity


class KernelRootkitDetector:
    """
    Detects kernel-level anomalies and rootkits:
    1. Cross-View Kernel Modules: Discrepancy between /proc/modules and /sys/module/
    2. Known malicious rootkit module signatures (Diamorphine, Reptile, Suterusu, etc.)
    3. Kernel taint flag analysis (/proc/sys/kernel/tainted)
    """

    TAINT_FLAGS = {
        1: "PROPRIETARY_MODULE",
        2: "FORCED_MODULE",
        4: "UNSAFE_SMP",
        8: "FORCED_UNLOAD",
        16: "MACHINE_CHECK_EXCEPTION",
        32: "BAD_PAGE",
        64: "USER_REQUESTED",
        128: "DIE_CALLED",
        256: "ACPI_OVERRIDDEN",
        512: "KERNEL_WARNING",
        1024: "STAGING_DRIVER",
        2048: "FIRMWARE_WORKAROUND",
        4096: "OUT_OF_TREE_MODULE",
        8192: "UNSIGNED_MODULE",
        16384: "SOFTLOCKUP",
        32768: "LIVEPATCH",
    }

    def __init__(self, known_signatures: List[str] | None = None) -> None:
        self.known_signatures = set(known_signatures or [
            "diamorphine", "reptile", "suterusu", "kbeast",
            "adore", "knark", "vlany", "mood-nt", "rk", "mafix"
        ])

    def scan(self) -> List[SecurityIncident]:
        incidents: List[SecurityIncident] = []

        # 1. Cross-View Kernel Module Check
        cross_incident = self._check_module_discrepancy()
        if cross_incident:
            incidents.append(cross_incident)

        # 2. Known Rootkit Signatures
        sig_incidents = self._check_known_signatures()
        incidents.extend(sig_incidents)

        # 3. Kernel Taint Verification
        taint_incident = self._check_kernel_taint()
        if taint_incident:
            incidents.append(taint_incident)

        return incidents

    def get_proc_modules(self) -> Set[str]:
        """Modules listed in /proc/modules (what lsmod sees)."""
        p = Path("/proc/modules")
        modules = set()
        if not p.is_file():
            return modules
        try:
            with open(p, "r", encoding="utf-8") as f:
                for line in f:
                    parts = line.split()
                    if parts:
                        modules.add(parts[0].replace("-", "_"))
        except (PermissionError, FileNotFoundError, OSError):
            pass
        return modules

    def get_sys_modules(self) -> Set[str]:
        """Modules registered in sysfs /sys/module/."""
        p = Path("/sys/module")
        modules = set()
        if not p.is_dir():
            return modules
        try:
            for entry in os.scandir("/sys/module"):
                if entry.is_dir():
                    modules.add(entry.name.replace("-", "_"))
        except (PermissionError, OSError):
            pass
        return modules

    def _check_module_discrepancy(self) -> SecurityIncident | None:
        proc_mods = self.get_proc_modules()
        sys_mods = self.get_sys_modules()

        if not proc_mods or not sys_mods:
            return None

        # Classic rootkit: unlinks itself from kernel module linked list (/proc/modules)
        # but kobject still resides under sysfs /sys/module/
        # Note: built-in kernel features can exist in /sys/module without being in /proc/modules,
        # so we check if the /sys/module entry has an 'initstate' or 'sections' attribute (LKM-specific).
        hidden_lkms = set()
        for mod in (sys_mods - proc_mods):
            mod_sys_path = Path(f"/sys/module/{mod}")
            # Dynamic LKMs have 'initstate' or 'sections' or 'refcnt'
            if (mod_sys_path / "initstate").exists() or (mod_sys_path / "sections").exists():
                hidden_lkms.add(mod)

        if hidden_lkms:
            return SecurityIncident(
                category=IncidentCategory.ROOTKIT_KERNEL,
                severity=Severity.CRITICAL,
                title="Hidden Kernel Module (LKM) Detected",
                details={
                    "hidden_modules": sorted(list(hidden_lkms)),
                    "detection_vector": "Registered in /sys/module with active initstate but unlinked from /proc/modules",
                },
                recommendation=(
                    "CRITICAL: A kernel rootkit is hiding its presence by unhooking from the kernel module list. "
                    "Analyze dmesg, check memory dumps, and reboot system into a clean rescue kernel."
                ),
            )
        return None

    def _check_known_signatures(self) -> List[SecurityIncident]:
        incidents: List[SecurityIncident] = []
        loaded = self.get_proc_modules().union(self.get_sys_modules())
        for mod in loaded:
            if mod.lower() in self.known_signatures:
                incidents.append(
                    SecurityIncident(
                        category=IncidentCategory.ROOTKIT_KERNEL,
                        severity=Severity.CRITICAL,
                        title=f"Known Malicious Rootkit Module Detected: {mod}",
                        details={"module": mod, "status": "active_in_kernel"},
                        recommendation=f"Immediately unload module ('rmmod -f {mod}') and initiate malware containment.",
                    )
                )
        return incidents

    def _check_kernel_taint(self) -> SecurityIncident | None:
        p = Path("/proc/sys/kernel/tainted")
        if not p.is_file():
            return None
        try:
            val = int(p.read_text().strip())
            if val == 0:
                return None

            active_flags = []
            for bit, name in self.TAINT_FLAGS.items():
                if val & bit:
                    active_flags.append(f"{name} (bit {bit})")

            # High suspicion if out-of-tree or unsigned modules are forced into kernel
            is_high_risk = bool(val & 4096 or val & 8192 or val & 2)
            severity = Severity.HIGH if is_high_risk else Severity.LOW

            return SecurityIncident(
                category=IncidentCategory.ROOTKIT_KERNEL,
                severity=severity,
                title="Kernel Taint Detected",
                details={
                    "taint_value": val,
                    "active_flags": active_flags,
                },
                recommendation=(
                    "Inspect recent insmod/modprobe actions. Unsigned or out-of-tree kernel code has been executed."
                ),
            )
        except Exception:
            return None

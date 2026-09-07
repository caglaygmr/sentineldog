from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import yaml
except ImportError:
    yaml = None


@dataclass
class GeneralConfig:
    service_name: str = "sentineldog"
    check_interval_seconds: int = 5
    deep_scan_interval_seconds: int = 30
    log_level: str = "INFO"


@dataclass
class AlertsConfig:
    console_output: bool = True
    json_log_path: str = "logs/incidents.json"
    webhook_url: Optional[str] = None
    syslog_facility: str = "LOG_SECURITY"


@dataclass
class RootkitConfig:
    enabled: bool = True
    enable_cross_view: bool = True
    enable_ld_preload: bool = True
    enable_kernel_modules: bool = True
    enable_hidden_network: bool = True
    max_pid_sweep: int = 65535


@dataclass
class FIMConfig:
    enabled: bool = True
    baseline_path: str = "data/fim_baseline.json"
    monitored_paths: List[str] = field(default_factory=lambda: [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/sudoers",
        "/etc/ld.so.preload",
        "/etc/ld.so.conf",
        "/etc/crontab",
        "/bin/ps",
        "/bin/ls",
        "/bin/netstat",
        "/bin/ss",
        "/bin/login",
        "/usr/bin/sudo",
        "/usr/bin/ssh"
    ])
    exclude_patterns: List[str] = field(default_factory=lambda: ["*.swp", "*~"])


@dataclass
class LogSentinelConfig:
    enabled: bool = True
    target_logs: List[str] = field(default_factory=lambda: [
        "/var/log/auth.log",
        "/var/log/secure",
        "/var/log/syslog"
    ])
    ssh_brute_force_threshold: int = 5
    ssh_brute_force_window: int = 60
    alert_on_sudo_failure: bool = True
    sudo_fail_threshold: int = 3
    detect_useradd: bool = True
    detect_uid0: bool = True


@dataclass
class AppConfig:
    general: GeneralConfig = field(default_factory=GeneralConfig)
    alerts: AlertsConfig = field(default_factory=AlertsConfig)
    rootkit: RootkitConfig = field(default_factory=RootkitConfig)
    fim: FIMConfig = field(default_factory=FIMConfig)
    log_sentinel: LogSentinelConfig = field(default_factory=LogSentinelConfig)
    signatures: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def load(cls, config_path: Optional[str | Path] = None, signatures_path: Optional[str | Path] = None) -> AppConfig:
        cfg = cls()

        # Locate config file
        candidates = []
        if config_path:
            candidates.append(Path(config_path))
        candidates.extend([
            Path("config/watchdog.yaml"),
            Path("/etc/sentineldog/watchdog.yaml"),
            Path(__file__).parent.parent.parent.parent / "config" / "watchdog.yaml"
        ])

        found_path = None
        for p in candidates:
            if p.is_file():
                found_path = p
                break

        if found_path and yaml:
            try:
                with open(found_path, "r", encoding="utf-8") as f:
                    raw = yaml.safe_load(f) or {}
                cfg._apply_raw_config(raw)
            except Exception as e:
                print(f"[!] Warning: Failed to parse config from {found_path}: {e}")

        # Locate signatures file
        sig_candidates = []
        if signatures_path:
            sig_candidates.append(Path(signatures_path))
        sig_candidates.extend([
            Path("config/signatures.yaml"),
            Path("/etc/sentineldog/signatures.yaml"),
            Path(__file__).parent.parent.parent.parent / "config" / "signatures.yaml"
        ])

        for sp in sig_candidates:
            if sp.is_file() and yaml:
                try:
                    with open(sp, "r", encoding="utf-8") as f:
                        cfg.signatures = yaml.safe_load(f) or {}
                    break
                except Exception as e:
                    print(f"[!] Warning: Failed to load signatures: {e}")

        return cfg

    def _apply_raw_config(self, raw: Dict[str, Any]) -> None:
        if "general" in raw:
            g = raw["general"]
            self.general.service_name = g.get("service_name", self.general.service_name)
            self.general.check_interval_seconds = g.get("check_interval_seconds", self.general.check_interval_seconds)
            self.general.deep_scan_interval_seconds = g.get("deep_scan_interval_seconds", self.general.deep_scan_interval_seconds)
            self.general.log_level = g.get("log_level", self.general.log_level)

        if "alerts" in raw:
            a = raw["alerts"]
            self.alerts.console_output = a.get("console_output", self.alerts.console_output)
            self.alerts.json_log_path = a.get("json_log_path", self.alerts.json_log_path)
            self.alerts.webhook_url = a.get("webhook_url", self.alerts.webhook_url)
            self.alerts.syslog_facility = a.get("syslog_facility", self.alerts.syslog_facility)

        if "rootkit_detection" in raw:
            rk = raw["rootkit_detection"]
            self.rootkit.enabled = rk.get("enabled", self.rootkit.enabled)
            self.rootkit.enable_cross_view = rk.get("enable_cross_view", self.rootkit.enable_cross_view)
            self.rootkit.enable_ld_preload = rk.get("enable_ld_preload", self.rootkit.enable_ld_preload)
            self.rootkit.enable_kernel_modules = rk.get("enable_kernel_modules", self.rootkit.enable_kernel_modules)
            self.rootkit.enable_hidden_network = rk.get("enable_hidden_network", self.rootkit.enable_hidden_network)
            self.rootkit.max_pid_sweep = rk.get("max_pid_sweep", self.rootkit.max_pid_sweep)

        if "file_integrity" in raw:
            fim = raw["file_integrity"]
            self.fim.enabled = fim.get("enabled", self.fim.enabled)
            self.fim.baseline_path = fim.get("baseline_path", self.fim.baseline_path)
            if "monitored_paths" in fim:
                self.fim.monitored_paths = fim["monitored_paths"]
            if "exclude_patterns" in fim:
                self.fim.exclude_patterns = fim["exclude_patterns"]

        if "log_sentinel" in raw:
            ls = raw["log_sentinel"]
            self.log_sentinel.enabled = ls.get("enabled", self.log_sentinel.enabled)
            if "target_logs" in ls:
                self.log_sentinel.target_logs = ls["target_logs"]
            rules = ls.get("rules", {})
            if "ssh_brute_force" in rules:
                sbf = rules["ssh_brute_force"]
                self.log_sentinel.ssh_brute_force_threshold = sbf.get("threshold", self.log_sentinel.ssh_brute_force_threshold)
                self.log_sentinel.ssh_brute_force_window = sbf.get("window_seconds", self.log_sentinel.ssh_brute_force_window)
            if "privilege_escalation" in rules:
                pe = rules["privilege_escalation"]
                self.log_sentinel.alert_on_sudo_failure = pe.get("alert_on_sudo_failure", self.log_sentinel.alert_on_sudo_failure)
                self.log_sentinel.sudo_fail_threshold = pe.get("sudo_fail_threshold", self.log_sentinel.sudo_fail_threshold)
            if "account_tampering" in rules:
                at = rules["account_tampering"]
                self.log_sentinel.detect_useradd = at.get("detect_useradd", self.log_sentinel.detect_useradd)
                self.log_sentinel.detect_uid0 = at.get("detect_uid0", self.log_sentinel.detect_uid0)

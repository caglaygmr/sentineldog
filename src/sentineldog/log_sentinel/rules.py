from __future__ import annotations

import re
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from ..core.alerts import IncidentCategory, SecurityIncident, Severity


class LogRuleEngine:
    """
    Evaluates log events against threat signatures and stateful behavioral rules.
    """

    # SSH Failure patterns (Debian/Ubuntu auth.log, RHEL/CentOS secure, sshd)
    SSH_FAILED_PATTERNS = [
        re.compile(r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+) port (?P<port>\d+)"),
        re.compile(r"authentication failure;.*rhost=(?P<ip>[0-9a-fA-F:.]+)(?:.*user=(?P<user>\S*))?"),
        re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)"),
    ]

    # Sudo Abuse patterns
    SUDO_FAIL_PATTERNS = [
        re.compile(r"sudo:\s+(?P<user>\S+)\s+: (?P<count>\d+) incorrect password attempt"),
        re.compile(r"sudo:\s+pam_unix\(sudo:auth\):\s+authentication failure;.*user=(?P<user>\S+)"),
    ]

    # Account Tampering patterns
    USERADD_PATTERNS = [
        re.compile(r"new user: name=(?P<user>\S+), UID=(?P<uid>\d+), GID=(?P<gid>\d+)"),
        re.compile(r"useradd.*name=(?P<user>\S+)"),
    ]

    # Shell spawned from web server user
    SUSPICIOUS_SHELL_PATTERNS = [
        re.compile(r"(?:www-data|apache|nginx|nobody).*COMMAND=(?:/bin/sh|/bin/bash|/bin/dash)"),
    ]

    def __init__(
        self,
        ssh_threshold: int = 5,
        ssh_window: int = 60,
        sudo_threshold: int = 3,
        detect_useradd: bool = True,
        detect_uid0: bool = True,
    ) -> None:
        self.ssh_threshold = ssh_threshold
        self.ssh_window = ssh_window
        self.sudo_threshold = sudo_threshold
        self.detect_useradd = detect_useradd
        self.detect_uid0 = detect_uid0

        # State tracking: IP -> list of timestamps
        self.ssh_failures: Dict[str, List[float]] = defaultdict(list)
        self.ssh_alerted_ips: Set[str] = set()

        # State tracking: User -> list of timestamps
        self.sudo_failures: Dict[str, List[float]] = defaultdict(list)

    def process_line(self, line: str) -> List[SecurityIncident]:
        """Analyzes a single log line and returns any triggered security incidents."""
        incidents: List[SecurityIncident] = []

        now = time.time()

        # 1. SSH Brute Force Check
        ssh_incident = self._check_ssh_failure(line, now)
        if ssh_incident:
            incidents.append(ssh_incident)

        # 2. Sudo Abuse / Local Privilege Escalation
        sudo_incident = self._check_sudo_failure(line, now)
        if sudo_incident:
            incidents.append(sudo_incident)

        # 3. Account Tampering
        if self.detect_useradd:
            acc_incident = self._check_account_creation(line)
            if acc_incident:
                incidents.append(acc_incident)

        # 4. Web Service Shell Spawning (Web Shell / RCE)
        shell_incident = self._check_suspicious_shell(line)
        if shell_incident:
            incidents.append(shell_incident)

        return incidents

    def _check_ssh_failure(self, line: str, now: float) -> SecurityIncident | None:
        for pattern in self.SSH_FAILED_PATTERNS:
            match = pattern.search(line)
            if match:
                ip = match.groupdict().get("ip")
                user = match.groupdict().get("user", "unknown")
                if not ip:
                    continue

                # Add event timestamp
                self.ssh_failures[ip].append(now)

                # Purge timestamps outside sliding window
                cutoff = now - self.ssh_window
                self.ssh_failures[ip] = [t for t in self.ssh_failures[ip] if t >= cutoff]

                failure_count = len(self.ssh_failures[ip])
                if failure_count >= self.ssh_threshold and ip not in self.ssh_alerted_ips:
                    self.ssh_alerted_ips.add(ip)
                    return SecurityIncident(
                        category=IncidentCategory.LOG_BRUTE_FORCE,
                        severity=Severity.HIGH,
                        title=f"SSH Brute-Force Attack Detected from {ip}",
                        details={
                            "source_ip": ip,
                            "target_user": user,
                            "failed_attempts": failure_count,
                            "window_seconds": self.ssh_window,
                            "trigger_line": line.strip(),
                        },
                        recommendation=(
                            f"Block IP {ip} using iptables or fail2ban: "
                            f"'iptables -A INPUT -s {ip} -j DROP'. Verify SSH key-only authentication."
                        ),
                    )
        return None

    def _check_sudo_failure(self, line: str, now: float) -> SecurityIncident | None:
        for pattern in self.SUDO_FAIL_PATTERNS:
            match = pattern.search(line)
            if match:
                user = match.groupdict().get("user", "unknown")
                self.sudo_failures[user].append(now)

                # Window check (2 minutes)
                cutoff = now - 120
                self.sudo_failures[user] = [t for t in self.sudo_failures[user] if t >= cutoff]

                if len(self.sudo_failures[user]) >= self.sudo_threshold:
                    # Reset counter to avoid continuous triggers
                    self.sudo_failures[user].clear()
                    return SecurityIncident(
                        category=IncidentCategory.LOG_PRIV_ESC,
                        severity=Severity.HIGH,
                        title=f"Repeated Sudo Authentication Failure for user '{user}'",
                        details={
                            "user": user,
                            "failed_attempts": self.sudo_threshold,
                            "trigger_line": line.strip(),
                        },
                        recommendation="Investigate compromised account credentials or unauthorized internal operator.",
                    )
        return None

    def _check_account_creation(self, line: str) -> SecurityIncident | None:
        for pattern in self.USERADD_PATTERNS:
            match = pattern.search(line)
            if match:
                user = match.groupdict().get("user", "unknown")
                uid = match.groupdict().get("uid", "")

                # High risk: Non-root user given UID 0 (root equivalent backdoor)
                if uid == "0" and user != "root":
                    return SecurityIncident(
                        category=IncidentCategory.LOG_ACCOUNT,
                        severity=Severity.CRITICAL,
                        title=f"Rogue Root-Equivalent Account Created (UID 0): '{user}'",
                        details={
                            "account_name": user,
                            "uid": uid,
                            "raw_log": line.strip(),
                        },
                        recommendation=(
                            f"CRITICAL: User '{user}' was created with UID 0 (Root privileges). "
                            "This is a classic backdoor persistence technique. Lock account immediately."
                        ),
                    )
                else:
                    return SecurityIncident(
                        category=IncidentCategory.LOG_ACCOUNT,
                        severity=Severity.MEDIUM,
                        title=f"New System Account Created: '{user}'",
                        details={
                            "account_name": user,
                            "uid": uid,
                            "raw_log": line.strip(),
                        },
                        recommendation="Verify if account addition was authorized by system administrators.",
                    )
        return None

    def _check_suspicious_shell(self, line: str) -> SecurityIncident | None:
        for pattern in self.SUSPICIOUS_SHELL_PATTERNS:
            if pattern.search(line):
                return SecurityIncident(
                    category=IncidentCategory.LOG_PRIV_ESC,
                    severity=Severity.CRITICAL,
                    title="Suspicious Interactive Shell Spawned by Web Service User",
                    details={"raw_log": line.strip()},
                    recommendation=(
                        "Potential Web Shell or Remote Code Execution (RCE) payload executing as web user. "
                        "Isolate web server and check access logs."
                    ),
                )
        return None

from __future__ import annotations

import time
import pytest

from sentineldog.core.alerts import IncidentCategory, Severity
from sentineldog.log_sentinel.rules import LogRuleEngine


def test_ssh_brute_force_detection():
    engine = LogRuleEngine(ssh_threshold=3, ssh_window=30)
    attacker_ip = "192.168.1.150"

    log_line = f"Jan 15 10:00:01 server sshd[1234]: Failed password for invalid user admin from {attacker_ip} port 44122 ssh2"

    # 1st attempt -> No alert yet
    assert len(engine.process_line(log_line)) == 0

    # 2nd attempt -> No alert yet
    assert len(engine.process_line(log_line)) == 0

    # 3rd attempt -> Triggers SSH Brute-Force incident!
    incidents = engine.process_line(log_line)
    assert len(incidents) == 1
    assert incidents[0].category == IncidentCategory.LOG_BRUTE_FORCE
    assert incidents[0].severity == Severity.HIGH
    assert incidents[0].details["source_ip"] == attacker_ip
    assert incidents[0].details["failed_attempts"] == 3


def test_sudo_abuse_detection():
    engine = LogRuleEngine(sudo_threshold=2)
    user = "intruder"

    line = f"Jan 15 10:05:00 server sudo: pam_unix(sudo:auth): authentication failure; logname= uid=1001 euid=0 tty=/dev/pts/1 ruser= rhost=  user={user}"

    # 1st fail
    assert len(engine.process_line(line)) == 0

    # 2nd fail
    incidents = engine.process_line(line)
    assert len(incidents) == 1
    assert incidents[0].category == IncidentCategory.LOG_PRIV_ESC
    assert incidents[0].details["user"] == user


def test_rogue_uid0_account_detection():
    engine = LogRuleEngine(detect_useradd=True)
    backdoor_line = "Jan 15 10:10:00 server useradd[555]: new user: name=ghostroot, UID=0, GID=0, home=/root, shell=/bin/bash"

    incidents = engine.process_line(backdoor_line)
    assert len(incidents) == 1
    assert incidents[0].category == IncidentCategory.LOG_ACCOUNT
    assert incidents[0].severity == Severity.CRITICAL
    assert "UID 0" in incidents[0].title
    assert incidents[0].details["account_name"] == "ghostroot"


def test_webshell_spawn_detection():
    engine = LogRuleEngine()
    webshell_line = "Jan 15 10:15:00 server sudo: www-data : TTY=unknown ; PWD=/var/www/html ; USER=root ; COMMAND=/bin/bash -c id"

    incidents = engine.process_line(webshell_line)
    assert len(incidents) == 1
    assert incidents[0].category == IncidentCategory.LOG_PRIV_ESC
    assert incidents[0].severity == Severity.CRITICAL

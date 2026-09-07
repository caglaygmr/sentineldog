from __future__ import annotations

import os
from pathlib import Path
import pytest

from sentineldog.core.alerts import IncidentCategory, Severity
from sentineldog.detectors.fim import FileIntegrityDetector


def test_fim_detects_file_tampering(tmp_path: Path):
    target_file = tmp_path / "fake_ps"
    target_file.write_text("original binary code 1.0")

    baseline_file = tmp_path / "baseline.json"

    # Initialize and take baseline
    fim = FileIntegrityDetector(
        monitored_paths=[str(target_file)],
        baseline_path=str(baseline_file),
    )
    count = fim.update_baseline()
    assert count == 1

    # Scan with no changes
    incidents = fim.scan()
    assert len(incidents) == 0

    # Attacker injects trojan into binary
    target_file.write_text("malicious rootkit trojan code injected!")

    # Scan should now detect integrity breach
    incidents = fim.scan()
    assert len(incidents) == 1
    assert incidents[0].category == IncidentCategory.FIM_INTEGRITY
    assert incidents[0].severity == Severity.CRITICAL
    assert "fake_ps" in incidents[0].title


def test_fim_detects_file_deletion(tmp_path: Path):
    target_file = tmp_path / "critical_tool"
    target_file.write_text("system tool content")

    baseline_file = tmp_path / "baseline.json"

    fim = FileIntegrityDetector(
        monitored_paths=[str(target_file)],
        baseline_path=str(baseline_file),
    )
    fim.update_baseline()

    # Attacker or malware removes the binary
    target_file.unlink()

    incidents = fim.scan()
    assert len(incidents) == 1
    assert incidents[0].details["status"] == "DELETED"

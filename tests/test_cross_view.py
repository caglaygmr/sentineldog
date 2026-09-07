from __future__ import annotations

from unittest.mock import MagicMock, patch
import pytest

from sentineldog.core.alerts import IncidentCategory, Severity
from sentineldog.detectors.cross_view import CrossViewDetector


def test_cross_view_clean_state():
    detector = CrossViewDetector(max_pid=100)
    with patch.object(detector, "get_proc_dir_pids", return_value={1, 2, 3}), \
         patch.object(detector, "get_psutil_pids", return_value={1, 2, 3}), \
         patch.object(detector, "sweep_syscall_pids", return_value={1, 2, 3}):
        incidents = detector.scan(full_sweep=False)
        assert len(incidents) == 0


def test_cross_view_detects_hidden_from_userland():
    detector = CrossViewDetector(max_pid=100)
    # PID 99 is visible in /proc, but hidden from psutil (userland rootkit)
    with patch.object(detector, "get_proc_dir_pids", return_value={1, 2, 99}), \
         patch.object(detector, "get_psutil_pids", return_value={1, 2}), \
         patch.object(detector, "sweep_syscall_pids", return_value={1, 2, 99}), \
         patch("pathlib.Path.is_dir", return_value=True):
        incidents = detector.scan(full_sweep=False)
        assert len(incidents) >= 1
        inc = incidents[0]
        assert inc.category == IncidentCategory.ROOTKIT_CROSS_VIEW
        assert inc.severity == Severity.HIGH
        assert 99 in inc.details["hidden_pids"]


def test_cross_view_detects_stealth_kernel_rootkit():
    detector = CrossViewDetector(max_pid=100)
    # PID 666 responds to kill(0) (in kernel task table),
    # but is completely missing from /proc directory (getdents64 hooked by LKM rootkit)
    with patch.object(detector, "get_proc_dir_pids", return_value={1, 2}), \
         patch.object(detector, "get_psutil_pids", return_value={1, 2}), \
         patch.object(detector, "sweep_syscall_pids", return_value={1, 2, 666}), \
         patch("os.kill", return_value=None), \
         patch("pathlib.Path.is_dir", return_value=False):
        incidents = detector.scan(full_sweep=False)
        stealth_incs = [i for i in incidents if i.severity == Severity.CRITICAL]
        assert len(stealth_incs) == 1
        assert 666 in stealth_incs[0].details["stealth_pids"]

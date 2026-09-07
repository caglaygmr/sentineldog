from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional


def compute_sha256(filepath: str | Path) -> Optional[str]:
    """Computes SHA-256 digest of a file in streaming chunks."""
    p = Path(filepath)
    if not p.is_file():
        return None
    h = hashlib.sha256()
    try:
        with open(p, "rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)
        return h.hexdigest()
    except (PermissionError, FileNotFoundError, OSError):
        return None


class BaselineManager:
    """Manages baseline snapshots for File Integrity Monitoring."""

    def __init__(self, baseline_path: str | Path = "data/fim_baseline.json") -> None:
        self.baseline_path = Path(baseline_path)

    def load(self) -> Dict[str, Dict[str, Any]]:
        if not self.baseline_path.exists():
            return {}
        try:
            with open(self.baseline_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            return {}

    def save(self, data: Dict[str, Dict[str, Any]]) -> None:
        self.baseline_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.baseline_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def create_snapshot(self, paths: List[str]) -> Dict[str, Dict[str, Any]]:
        """Takes a snapshot of all specified paths (files and directories recursively)."""
        snapshot: Dict[str, Dict[str, Any]] = {}
        for path_str in paths:
            p = Path(path_str)
            if p.is_file():
                self._record_file(p, snapshot)
            elif p.is_dir():
                try:
                    for sub in p.rglob("*"):
                        if sub.is_file() and not sub.is_symlink():
                            self._record_file(sub, snapshot)
                except (PermissionError, OSError):
                    continue
        return snapshot

    def _record_file(self, p: Path, snapshot: Dict[str, Dict[str, Any]]) -> None:
        try:
            st = p.stat()
            file_hash = compute_sha256(p)
            if file_hash:
                snapshot[str(p.resolve())] = {
                    "sha256": file_hash,
                    "size": st.st_size,
                    "mode": oct(st.st_mode),
                    "mtime": st.st_mtime,
                    "uid": st.st_uid,
                    "gid": st.st_gid,
                }
        except (PermissionError, FileNotFoundError, OSError):
            pass

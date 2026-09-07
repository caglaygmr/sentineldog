from __future__ import annotations

import asyncio
import os
import time
from pathlib import Path
from typing import AsyncGenerator, Callable, Dict, List, Optional, Tuple


class LogFileWatcher:
    """
    Asynchronously monitors and tails log files in real time.
    Handles log rotation (logrotate truncation or inode switch).
    """

    def __init__(self, target_paths: List[str | Path], poll_interval: float = 0.5) -> None:
        self.target_paths = [Path(p) for p in target_paths]
        self.poll_interval = poll_interval
        # Map: filepath -> (file_descriptor, last_inode, last_offset)
        self._file_states: Dict[Path, Tuple[Optional[int], int]] = {}

    def _open_file(self, path: Path) -> Tuple[Optional[int], int]:
        try:
            st = path.stat()
            # Start at end of file so we only tail newly generated events
            return st.st_ino, st.st_size
        except (PermissionError, FileNotFoundError, OSError):
            return None, 0

    async def follow(self) -> AsyncGenerator[Tuple[Path, str], None]:
        """
        Continuously yields (path, new_line) as logs are written.
        """
        # Initialize file pointers
        for path in self.target_paths:
            if path.exists():
                self._file_states[path] = self._open_file(path)

        while True:
            had_activity = False
            for path in self.target_paths:
                if not path.is_file():
                    continue

                try:
                    st = path.stat()
                    curr_ino, curr_size = st.st_ino, st.st_size
                    saved_ino, saved_offset = self._file_states.get(path, (None, 0))

                    # Check for file rotation (inode change or file shrunk)
                    if saved_ino is not None and (curr_ino != saved_ino or curr_size < saved_offset):
                        saved_offset = 0

                    if curr_size > saved_offset:
                        had_activity = True
                        with open(path, "r", encoding="utf-8", errors="replace") as f:
                            f.seek(saved_offset)
                            while line := f.readline():
                                if line.endswith("\n"):
                                    yield path, line.rstrip("\r\n")
                            new_offset = f.tell()

                        self._file_states[path] = (curr_ino, new_offset)
                    else:
                        self._file_states[path] = (curr_ino, saved_offset)

                except (PermissionError, FileNotFoundError, OSError):
                    continue

            # Sleep briefly if no new logs were read
            if not had_activity:
                await asyncio.sleep(self.poll_interval)
            else:
                await asyncio.sleep(0.05)

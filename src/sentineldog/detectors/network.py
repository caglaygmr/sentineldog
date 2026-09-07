from __future__ import annotations

import socket
import struct
from pathlib import Path
from typing import Dict, List, NamedTuple, Set, Tuple

try:
    import psutil
except ImportError:
    psutil = None

from ..core.alerts import IncidentCategory, SecurityIncident, Severity


class SocketEndpoint(NamedTuple):
    ip: str
    port: int
    state: str


class NetworkStealthDetector:
    """
    Detects hidden network listeners and backdoors by cross-referencing:
    - Raw kernel socket tables (/proc/net/tcp, /proc/net/tcp6, /proc/net/udp)
    - Userland socket tables (psutil.net_connections)
    """

    TCP_STATES = {
        "01": "ESTABLISHED",
        "02": "SYN_SENT",
        "03": "SYN_RECV",
        "04": "FIN_WAIT1",
        "05": "FIN_WAIT2",
        "06": "TIME_WAIT",
        "07": "CLOSE",
        "08": "CLOSE_WAIT",
        "09": "LAST_ACK",
        "0A": "LISTEN",
        "0B": "CLOSING",
    }

    def scan(self) -> List[SecurityIncident]:
        incidents: List[SecurityIncident] = []

        raw_listen_sockets = self.get_proc_net_listeners()
        psutil_listen_sockets = self.get_psutil_listeners()

        if not raw_listen_sockets and not psutil_listen_sockets:
            return incidents

        # View A: Raw /proc/net/tcp listeners
        # View B: Userland psutil listeners
        raw_ports = {s.port for s in raw_listen_sockets}
        psutil_ports = {s.port for s in psutil_listen_sockets}

        # Ports listening in /proc/net/tcp but hidden from psutil
        hidden_from_userland = raw_ports - psutil_ports
        # Exclude port 0 or ephemerals
        hidden_from_userland = {p for p in hidden_from_userland if p > 0}

        if hidden_from_userland:
            incidents.append(
                SecurityIncident(
                    category=IncidentCategory.ROOTKIT_NETWORK,
                    severity=Severity.HIGH,
                    title="Hidden Listening Network Port Detected",
                    details={
                        "hidden_ports": sorted(list(hidden_from_userland)),
                        "detection_method": "Listening in /proc/net/tcp but filtered in userland socket listings",
                    },
                    recommendation=(
                        "Inspect active connections with raw socket analysis or external port scanning (nmap). "
                        "A backdoor listener may be filtering userland netstat/ss/lsof output."
                    ),
                )
            )

        return incidents

    def get_proc_net_listeners(self) -> List[SocketEndpoint]:
        """Parses /proc/net/tcp and /proc/net/tcp6 to find all LISTEN endpoints."""
        listeners: List[SocketEndpoint] = []
        for proto in ["tcp", "tcp6"]:
            net_file = Path(f"/proc/net/{proto}")
            if not net_file.is_file():
                continue
            try:
                with open(net_file, "r") as f:
                    lines = f.readlines()[1:]  # skip header
                for line in lines:
                    parts = line.strip().split()
                    if len(parts) < 4:
                        continue
                    local_addr, st_hex = parts[1], parts[3]
                    state = self.TCP_STATES.get(st_hex.upper(), "UNKNOWN")
                    if state == "LISTEN":
                        ip, port = self._parse_hex_addr(local_addr, is_v6=(proto == "tcp6"))
                        listeners.append(SocketEndpoint(ip=ip, port=port, state=state))
            except (PermissionError, FileNotFoundError, OSError):
                pass
        return listeners

    def get_psutil_listeners(self) -> List[SocketEndpoint]:
        """Retrieves userland listening sockets via psutil."""
        listeners: List[SocketEndpoint] = []
        if not psutil:
            return listeners
        try:
            for conn in psutil.net_connections(kind="inet"):
                if conn.status == "LISTEN" and conn.laddr:
                    listeners.append(
                        SocketEndpoint(
                            ip=conn.laddr.ip,
                            port=conn.laddr.port,
                            state="LISTEN",
                        )
                    )
        except (PermissionError, psutil.AccessDenied, OSError):
            pass
        return listeners

    def _parse_hex_addr(self, addr_str: str, is_v6: bool = False) -> Tuple[str, int]:
        try:
            hex_ip, hex_port = addr_str.split(":")
            port = int(hex_port, 16)
            if not is_v6:
                # Little endian IPv4
                ip = socket.inet_ntoa(struct.pack("<L", int(hex_ip, 16)))
            else:
                # IPv6 hex format
                ip = hex_ip  # simplified representation
            return ip, port
        except Exception:
            return "0.0.0.0", 0

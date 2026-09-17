"""
nmap.py - Nmap adapter.

Besides the low-level run() (ToolResult), it exposes a DOMAIN method
`scan_web_ports(ip)` that returns an already-parsed list of `PortInfo`. All the
knowledge of "how nmap's output is read" (python-nmap object or XML) lives here,
not in the module: WebScanner only receives clean ports.
"""

from __future__ import annotations

import shutil
import xml.etree.ElementTree as ET
from dataclasses import dataclass

from core.scope import assert_in_scope
from tools.ExternalTool import ExternalTool, ToolResult

WEB_PORTS = [80, 443, 8080, 8443]


@dataclass(frozen=True)
class PortInfo:
    """Information about a port after the scan."""

    port: int
    state: str
    service: str | None = None
    version: str | None = None

    @property
    def is_open(self) -> bool:
        return self.state == "open"


class NmapTool(ExternalTool):
    binary = "nmap"

    def is_available(self) -> bool:
        return shutil.which(self.binary) is not None

    # --- low-level run() (ExternalTool contract) ---
    def run(self, ip: str, ports: str = "80,443,8080,8443",
            arguments: str = "-sV", max_time: int = 300) -> ToolResult:
        cmd = [self.binary, *arguments.split(), "-p", ports, "-oX", "-", ip]
        return self._run_command(cmd, max_time)

    # --- domain method: already-parsed ports ---
    def scan_web_ports(self, ip: str, ports: list[int] | None = None) -> list[PortInfo]:
        """
        Scans the web ports and returns a list of PortInfo (one per queried
        port). Uses python-nmap if available; otherwise, parses the XML.
        """
        assert_in_scope(ip)
        ports = ports or WEB_PORTS
        try:
            return self._scan_pynmap(ip, ports)
        except ImportError:
            return self._scan_xml(ip, ports)

    def _scan_pynmap(self, ip: str, ports: list[int]) -> list[PortInfo]:
        import nmap  # ImportError -> falls back to XML parsing
        nm = nmap.PortScanner()
        nm.scan(ip, ",".join(map(str, ports)), arguments="-sV")
        # Dump nmap's raw XML output (not just the already-parsed ports) to
        # stdout: ModuleBase captures it and persists it as the row's `log`,
        # visible later in the detail modal.
        print(f"📡 {nm.command_line()}")
        raw_output = nm.get_nmap_last_output()
        if isinstance(raw_output, bytes):
            raw_output = raw_output.decode("utf-8", errors="replace")
        print(raw_output)
        results: list[PortInfo] = []
        host_ok = ip in nm.all_hosts()
        for port in ports:
            if host_ok and "tcp" in nm[ip] and port in nm[ip]["tcp"]:
                info = nm[ip]["tcp"][port]
                service = info.get("name", "unknown")
                results.append(PortInfo(
                    port=port, state=info["state"],
                    service=service if service != "unknown" else None,
                    version=info.get("product") or None,
                ))
            else:
                results.append(PortInfo(port=port, state="closed"))
        return results

    def _scan_xml(self, ip: str, ports: list[int]) -> list[PortInfo]:
        tool_result = self.run(ip, ports=",".join(map(str, ports)))
        print(f"📡 nmap -sV -p {','.join(map(str, ports))} -oX - {ip}")
        print(tool_result.stdout or "(no output)")
        found: dict[int, tuple] = {}
        try:
            root = ET.fromstring(tool_result.stdout)
            for port_el in root.findall(".//port"):
                portid = int(port_el.get("portid", 0))
                state_el = port_el.find("state")
                svc_el = port_el.find("service")
                found[portid] = (
                    state_el.get("state") if state_el is not None else "closed",
                    svc_el.get("name") if svc_el is not None else None,
                    svc_el.get("product") if svc_el is not None else None,
                )
        except ET.ParseError:
            pass
        results = []
        for port in ports:
            state, service, version = found.get(port, ("closed", None, None))
            results.append(PortInfo(
                port=port, state=state,
                service=service if service and service != "unknown" else None,
                version=version or None,
            ))
        return results

"""
nikto.py - Nikto adapter.

Besides the low-level run() (ToolResult), it exposes `discover(url)`, which runs
Nikto and returns the candidate URLs already extracted from its output. All the
knowledge of "how Nikto's output is read" (lines starting with '+ ', paths,
absolute URLs, terms to ignore) lives here, not in WebCrawler.

Scope filtering is NOT done here: it is the crawler's policy (it depends on its
base_netloc/base_path). The tool returns absolute candidates; the module
normalizes and filters them.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

from core.scope import assert_in_scope
from tools.ExternalTool import ExternalTool, ToolResult

_SKIP_TERMS = ("Target IP:", "Target Hostname:", "Target Port:", "Start Time:",
               "End Time:", "Server:", "host(s) tested", "requests:")
_PATH_RE = re.compile(r"\+\s+(/[^\s:]+)")
_URL_RE = re.compile(r"https?://[^\s,.:]+(?:[^\s,]*)?")


class NiktoTool(ExternalTool):
    binary = "nikto"

    # --- low-level run() (ExternalTool contract) ---
    def run(self, url: str, max_time: int = 600) -> ToolResult:
        return self._run_command(
            [self.binary, "-h", url, "-Tuning", "1", "-nossl"], max_time)

    # --- domain method: candidate URLs already extracted ---
    def discover(self, url: str) -> list[str]:
        """
        Runs Nikto against `url` and returns the list of absolute URLs
        discovered (unfiltered by scope, which is the module's job). Preserves
        order and deduplicates at extraction level.
        """
        assert_in_scope(url)
        stdout = self.run(url).stdout or ""
        base = urlparse(url)
        found: list[str] = []

        for line in stdout.split("\n"):
            line = line.strip()
            if not line.startswith("+ ") or any(term in line for term in _SKIP_TERMS):
                continue

            # Paths like "+ /admin/..." -> absolute URL against the base host
            if m := _PATH_RE.match(line):
                candidate = f"{base.scheme}://{base.netloc}{m.group(1)}"
                if candidate not in found:
                    found.append(candidate)

            # Absolute URLs embedded in the line
            for raw in _URL_RE.findall(line):
                candidate = raw.rstrip(":,.")
                if candidate and candidate not in found:
                    found.append(candidate)

        return found

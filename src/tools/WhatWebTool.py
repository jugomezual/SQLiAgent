"""
whatweb.py - WhatWeb adapter.

Besides the low-level run() (ToolResult), it exposes `fingerprint(url)`, which
runs WhatWeb and returns a list of already-parsed `WebFingerprint`
(technologies, cookies, headers, normalized HTTP status...). All the handling of
WhatWeb's JSON output with plugins lives here, not in WebScanner.
"""

from __future__ import annotations

import json
import re
import shutil
from dataclasses import dataclass, field

from core.scope import assert_in_scope
from tools.ExternalTool import ExternalTool, ToolResult

_COOKIE_NAME = re.compile(r"^([^=]+)")
_HTTP_STATUS = re.compile(r"(\d+)")
_TECHS = ["PHP", "Apache", "nginx", "WordPress", "Drupal", "jQuery", "MySQL", "JQuery",
          "Bootstrap", "AngularJS", "React", "Vue", "Python", "Ruby", "ASP.NET", "IIS",
          "Tomcat", "Node.js"]
_HEADER_PLUGINS = ("HTTPServer", "X-Powered-By", "X-Frame-Options", "X-XSS-Protection",
                   "Content-Security-Policy", "Strict-Transport-Security", "Server")


@dataclass
class WebFingerprint:
    """Fingerprinting result of a URL (already normalized)."""

    url: str
    http_status: int | None = None
    redirect: str | None = None
    server: str | None = None
    technologies: list[str] = field(default_factory=list)
    cookies: list[str] = field(default_factory=list)
    headers: dict = field(default_factory=dict)
    uncommon_headers: list[str] = field(default_factory=list)


class WhatWebTool(ExternalTool):
    binary = "whatweb"

    def is_available(self) -> bool:
        # `whatweb --version` loads its whole plugin DB and can be slow enough
        # to trip ExternalTool's default 5s probe, silently disabling
        # fingerprinting for the entire scan (see NmapTool for the same fix).
        return shutil.which(self.binary) is not None

    # --- low-level run() (ExternalTool contract) ---
    def run(self, url: str, max_time: int = 15) -> ToolResult:
        return self._run_command([self.binary, "--log-json=-", url], max_time)

    # --- domain method: already-parsed fingerprints ---
    def fingerprint(self, url: str) -> list[WebFingerprint]:
        """Runs WhatWeb against `url` and returns the list of WebFingerprint."""
        assert_in_scope(url)
        stdout = self.run(url).stdout or ""
        # Dump WhatWeb's raw JSON to stdout: ModuleBase captures it and
        # persists it as the row's `log`, visible later in the detail modal.
        print(f"🔎 whatweb --log-json=- {url}")
        print(stdout or "(no output)")
        results = []
        for line in stdout.strip().split("\n"):
            line = line.strip()
            if not (line and line.startswith("{")):
                continue
            try:
                raw = json.loads(line)
            except json.JSONDecodeError:
                continue
            results.append(self._parse(raw, url))
        return results

    # --- internal parsing ---
    def _parse(self, raw: dict, fallback_url: str) -> WebFingerprint:
        plugins = raw.get("plugins", {})
        fp = WebFingerprint(url=raw.get("target", fallback_url))
        fp.http_status = self._normalize_status(raw.get("http_status"), plugins)
        fp.server = plugins.get("HTTPServer", {}).get("string", [""])[0]

        if "RedirectLocation" in plugins:
            redir = plugins["RedirectLocation"].get("string", [])
            fp.redirect = ", ".join(redir if isinstance(redir, list) else [redir])

        techs = []
        for tech in _TECHS:
            if tech in plugins and isinstance(plugins[tech], dict):
                version = plugins[tech].get("version", [""])[0] if "version" in plugins[tech] else ""
                techs.append(f"{tech} {version}".strip() if version else tech)
        for key in ("HTTPServer", "X-Powered-By"):
            if key in plugins and "string" in plugins[key]:
                val = plugins[key]["string"]
                techs.extend(val if isinstance(val, list) else [val])
        fp.technologies = list(dict.fromkeys(filter(None, techs)))[:50]

        if "Cookies" in plugins:
            fp.cookies = [m.group(1) for c in plugins["Cookies"].get("string", [])
                          if c and (m := _COOKIE_NAME.match(c))]

        for name, data in plugins.items():
            if isinstance(data, dict) and "string" in data and any(h in name for h in _HEADER_PLUGINS):
                val = data["string"]
                fp.headers[name] = val if isinstance(val, list) else ([val] if val else [])

        if "UncommonHeaders" in plugins:
            unc = plugins["UncommonHeaders"].get("string", [])
            fp.uncommon_headers = unc if isinstance(unc, list) else ([unc] if unc else [])
        return fp

    @staticmethod
    def _normalize_status(http_status, plugins) -> int | None:
        if http_status and http_status != "N/A":
            try:
                return int(http_status)
            except (TypeError, ValueError):
                pass
        code = next((p.strip("[]") for p in plugins
                     if isinstance(p, str) and p.startswith("[") and p.endswith("]")), None)
        if code and (m := _HTTP_STATUS.match(code)):
            return int(m.group(1))
        return None

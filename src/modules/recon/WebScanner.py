#!/usr/bin/env python3
"""
web_scanner.py - Web port scanning (nmap) and fingerprinting (whatweb).

Pattern: BaseModule (Template Method) + NmapTool/WhatWebTool (Adapter).
All parsing lives in the tools: NmapTool.scan_web_ports returns PortInfo and
WhatWebTool.fingerprint returns WebFingerprint. This module only ORCHESTRATES
(job/host, choosing URLs) and PERSISTS (saving 200 web apps, logs).
"""

from __future__ import annotations

if __name__ == "__main__":
    import os
    import sys
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

from urllib.parse import urlparse

from core import ModuleBase, ModuleResult
from tools import NmapTool, WhatWebTool


class WebScanner(ModuleBase):
    slug = "web_scanner"

    def __init__(self, target, *, mode="Normal", depth=4, comment=None, job_id=None, model=None):
        super().__init__(target_id=None, job_id=job_id)
        self.raw_target = target
        self.mode = mode
        self.depth = depth
        self.comment = comment
        self.model = model
        self.nmap = NmapTool()
        self.whatweb = WhatWebTool()
        self.ip = None
        self.url = None
        self.host_id = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def validate(self) -> bool:
        self.ip, self.url, error = self._validate_target(self.raw_target)
        if error:
            self.console.error(error)
            return False
        # Scope is not checked here: it is done later, inside run()
        # (via NmapTool.scan_web_ports), once load() has already created the
        # job/host — this way, if the target is out of scope, on_failure()
        # can mark those rows as error instead of failing silently
        # before any row to mark even exists.
        self.require_tool(self.nmap)  # nmap is mandatory
        if not self.whatweb.is_available():
            self.console.warn("whatweb not available: fingerprinting will be skipped")
        return True

    def load(self) -> bool:
        """Creates job + host in the database."""
        self.job_id = self.db.create_job(
            job_type=self.mode, model=self.model if self.mode == "IA" else None,
            depth=self.depth, comment=self.comment, target_url=self.url or self.raw_target)
        if self.job_id:
            self.console.ok(f"Job created: ID={self.job_id}")
            self.host_id = self.db.insert_host(self.job_id, self.ip, "running")
            if self.host_id:
                self.console.ok(f"Host created: ID={self.host_id}")
        else:
            self.console.warn("Could not create the job; continuing without DB")
        return True

    def run(self) -> ModuleResult:
        self.console.banner(f"FULL SCAN: {self.ip}")

        # --- Ports (parsing lives in NmapTool) ---
        ports = self.nmap.scan_web_ports(self.ip)
        for p in ports:
            self.console.plain(f"  {'✓' if p.is_open else '✗'} Port {p.port}: "
                               f"{p.state.upper()}{f' ({p.service})' if p.service else ''}")
        open_ports = [p.port for p in ports if p.is_open]
        if self.host_id:
            self.db.insert_nmap_results(self.host_id, [
                {"port": p.port, "state": p.state, "service": p.service, "version": p.version}
                for p in ports
            ])

        if not open_ports:
            if self.host_id:
                self.db.update_host_state(self.host_id, "done")
            if self.job_id:
                self.db.finish_job(self.job_id, "done")
            return ModuleResult.empty(self.slug, "No open web ports (80/443/8080/8443)")

        if self.job_id and self.host_id:
            self.db.insert_activity_log(
                jobs_id=self.job_id, event_type="host_identified", reference_id=self.host_id,
                reference_table="host", details={"host": self.ip, "ports": open_ports})

        # --- Fingerprint + persistence (parsing lives in WhatWebTool) ---
        saved = 0
        if self.whatweb.is_available():
            for url in self._urls_to_analyze(open_ports):
                saved += self._analyze_and_save(url)

        if self.host_id:
            self.db.update_host_state(self.host_id, "done")

        return ModuleResult.ok(self.slug, "Scan completed", findings=len(open_ports),
                               open_ports=open_ports, web_apps_saved=saved)

    def report(self, result: ModuleResult) -> None:
        self.console.banner("✅ ANALYSIS COMPLETED" if result.succeeded else "⚠️  NO RESULTS")
        if result.data.get("open_ports"):
            self.console.plain(f"🔓 Open ports: {result.data['open_ports']}")
            self.console.plain(f"💾 Web apps saved (200): {result.data.get('web_apps_saved', 0)}")
        else:
            self.console.plain(result.message)

    def on_failure(self, result: ModuleResult) -> None:
        if self.host_id:
            self.db.update_host_state(self.host_id, "error", error_message=result.message)
        if self.job_id:
            self.db.finish_job(self.job_id, "error", error_message=result.message)

    def on_log(self, result: ModuleResult, log_text: str) -> None:
        if self.host_id:
            self.db.update_host_log(self.host_id, log_text)

    # ------------------------------------------------------------------
    # Orchestration / persistence
    # ------------------------------------------------------------------

    def _urls_to_analyze(self, open_ports) -> list[str]:
        if self.url:
            return [self.url]
        urls = []
        for port in open_ports:
            proto = "https" if port in (443, 8443) else "http"
            urls.append(f"{proto}://{self.ip}" if port in (80, 443)
                        else f"{proto}://{self.ip}:{port}")
        return urls

    def _analyze_and_save(self, url) -> int:
        self.console.banner(f"Analyzing {url}", char="-")
        saved = 0
        try:
            fingerprints = self.whatweb.fingerprint(url)
        except Exception as exc:
            # One port/URL failing (out of scope, whatweb hiccup) must not
            # abort fingerprinting of this host's other open ports.
            self.console.error(f"{url}: analysis failed, continuing: {exc}")
            return 0
        for fp in fingerprints:
            if fp.http_status != 200:
                continue
            webapp_id = self.db.insert_web_app(
                host_id=self.host_id, target_url=fp.url, http_status=fp.http_status,
                redirect_location=fp.redirect, technologies=fp.technologies,
                cookies=fp.cookies, headers=fp.headers, uncommon_headers=fp.uncommon_headers)
            saved += 1
            if self.job_id and webapp_id:
                self.db.insert_activity_log(
                    jobs_id=self.job_id, event_type="webapp_identified",
                    reference_id=webapp_id, reference_table="host_web_app",
                    details={"web": fp.url})
        if saved:
            self.console.ok(f"Saved {saved} page(s) with status 200")
        return saved

    # ------------------------------------------------------------------
    # Target validation
    # ------------------------------------------------------------------

    @staticmethod
    def _validate_target(target):
        target = target.strip()
        if target.startswith(("http://", "https://")):
            try:
                parsed = urlparse(target)
                if not parsed.netloc:
                    return None, None, "Invalid URL format"
                hostname = parsed.hostname or parsed.netloc.split(":")[0]
                return hostname, target, None
            except Exception as exc:
                return None, None, f"Error parsing the URL: {exc}"
        if not target or len(target) > 255:
            return None, None, "Invalid IP/hostname"
        return target, None, None


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Scans ports (nmap) and fingerprints (whatweb) a target")
    parser.add_argument("target", help="IP, hostname or URL to scan")
    parser.add_argument("--mode", default="Normal", choices=["Normal", "IA"], help="Job type (default: Normal)")
    parser.add_argument("--depth", type=int, default=4, help="Crawling depth to associate with the job (default: 4)")
    parser.add_argument("--comment", default=None, help="Free comment for the job")
    parser.add_argument("--job-id", type=int, default=None, help="Reuse an existing job instead of creating a new one")
    parser.add_argument("--model", default=None, help="AI model to use when --mode=IA")
    args = parser.parse_args()

    result = WebScanner(
        args.target, mode=args.mode, depth=args.depth, comment=args.comment,
        job_id=args.job_id, model=args.model,
    ).execute()
    sys.exit(result.exit_code())

#!/usr/bin/env python3
"""
web_detector.py - SQLi detection on crawled pages (SQLMap).

Pattern: BaseModule (Template Method) + SqlmapTool (Adapter, run()->ToolResult).
It supports two modes depending on how it is built:
  - WebDetector(web_app_id=N)      -> analyzes all pages of the web_app.
  - WebDetector(crawl_page_id=N)   -> analyzes a single page.
Parsing of SQLMap's output is done by SqlmapTool itself (run_parsed).
"""

from __future__ import annotations

if __name__ == "__main__":
    import os
    import sys
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

import json
import time

from core import ModuleBase, ModuleResult
from tools import SqlmapTool


class WebDetector(ModuleBase):
    slug = "web_detector"

    def __init__(self, web_app_id=None, *, crawl_page_id=None, job_id=None):
        super().__init__(target_id=web_app_id, job_id=job_id)
        self.web_app_id = web_app_id
        self.crawl_page_id = crawl_page_id
        self.sqlmap = SqlmapTool()
        self.pages: list = []
        self.results: list = []

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def validate(self) -> bool:
        self.require_tool(self.sqlmap)
        return True

    def load(self) -> bool:
        return self._load_single_page() if self.crawl_page_id else self._load_web_app_pages()

    def run(self) -> ModuleResult:
        mode = "single page" if self.crawl_page_id else f"web_app {self.web_app_id}"
        self.console.banner(f"🔍 WEBDETECTOR - SQLi analysis ({mode})")

        targets = self._get_testable_targets()
        if not targets:
            if self.crawl_page_id:
                self.db.update_crawl_page_state(self.crawl_page_id, "done")
            return ModuleResult.empty(self.slug, "No forms/URLs with parameters to analyze")

        self.console.step(f"Targets found: {len(targets)}")
        try:
            for idx, target in enumerate(targets, 1):
                self.console.plain(f"\n--- Target {idx}/{len(targets)} ---")
                # _analyze_target() catches its own failures (including an
                # out-of-scope target) and always records them to the DB, so
                # one bad form/param never costs the other targets on this page.
                self.results.append(self._analyze_target(target))
                if idx < len(targets):
                    time.sleep(2)
        finally:
            if self.crawl_page_id:
                self.db.update_crawl_page_state(self.crawl_page_id, "done")

        vulnerable = [r for r in self.results if r.get("vulnerable")]
        return ModuleResult.ok(self.slug, "Analysis completed", findings=len(vulnerable),
                               analyzed=len(self.results), vulnerable=len(vulnerable))

    def on_log(self, result: ModuleResult, log_text: str) -> None:
        if self.crawl_page_id:
            self.db.update_crawl_page_log(self.crawl_page_id, log_text)

    def report(self, result: ModuleResult) -> None:
        self.console.banner("📊 ANALYSIS SUMMARY")
        vulnerable = [r for r in self.results if r.get("vulnerable")]
        safe = [r for r in self.results if not r.get("vulnerable") and not r.get("error")]
        errors = [r for r in self.results if r.get("error")]
        self.console.plain(f"📋 Analyzed: {len(self.results)}")
        self.console.plain(f"⚠️  Vulnerable: {len(vulnerable)}")
        self.console.plain(f"✅ Safe: {len(safe)}")
        self.console.plain(f"❌ With error: {len(errors)}")
        for i, r in enumerate(vulnerable, 1):
            self.console.plain(f"\n[{i}] {r.get('url')}")
            if r.get("injection_points"):
                self.console.plain(f"    🎯 {', '.join(r['injection_points'])}")
            if r.get("dbms"):
                self.console.plain(f"    💾 DBMS: {r['dbms']}")

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    def _load_web_app_pages(self) -> bool:
        pages = self.db.get_crawl_pages(self.web_app_id)
        if not pages:
            self.console.error("There are no crawled pages for this web_app_id")
            return False
        for page in pages:
            self._attach_details(page)
            self.pages.append(page)
        self.console.ok(f"{len(self.pages)} page(s) loaded")
        return True

    def _load_single_page(self) -> bool:
        page = self.db.get_crawl_page(self.crawl_page_id)
        if not page:
            self.console.error(f"There is no crawl_page with ID {self.crawl_page_id}")
            self.db.update_crawl_page_state(self.crawl_page_id, "done")
            return False
        if not self.job_id and page.get("web_app_id"):
            web_app = self.db.get_web_app(page["web_app_id"])
            if web_app and web_app.get("host_id"):
                host = self.db.get_host(web_app["host_id"])
                if host and host.get("jobs_id"):
                    self.job_id = host["jobs_id"]
        self._attach_details(page)
        self.pages = [page]
        return True

    def _attach_details(self, page) -> None:
        details = self.db.get_crawl_page_details(page["id"])
        page["forms"] = json.loads(details["forms_json"]) if details and details.get("forms_json") else []
        page["url_params"] = json.loads(details["url_params_json"]) if details and details.get("url_params_json") else []
        page["standalone_inputs"] = json.loads(details["standalone_inputs_json"]) if details and details.get("standalone_inputs_json") else []

    # ------------------------------------------------------------------
    # Target selection (transplanted)
    # ------------------------------------------------------------------

    def _get_testable_targets(self) -> list:
        targets, seen = [], set()
        for page in self.pages:
            for form in page.get("forms", []):
                fields = [f for f in form.get("fields", [])
                          if f.get("name") and f.get("type") not in ("button", "reset", "image")]
                if not fields:
                    continue
                sig = (form["action"], form["method"].upper(),
                       frozenset(f["name"] for f in fields))
                if sig in seen:
                    continue
                seen.add(sig)
                targets.append({
                    "type": "FORM", "crawl_page_id": page["id"], "page_url": page["url"],
                    "target_url": form["action"], "method": form["method"].upper(),
                    "form_type": form.get("type", "GENERIC"), "fields": fields,
                })
            if page.get("url_params"):
                # Test every URL param, not just ID-shaped names (id/user/key/...):
                # a genuinely injectable param can be called anything ('name',
                # 'query', 'bID', ...) — SqlmapTool.skip_flags() still excludes
                # the handful of known-problematic routing param names.
                targets.append({
                    "type": "URL_PARAMS", "crawl_page_id": page["id"], "page_url": page["url"],
                    "target_url": page["url"], "method": "GET",
                    "params": page["url_params"],
                })
        return targets

    # ------------------------------------------------------------------
    # Analysis of a target
    # ------------------------------------------------------------------

    def _analyze_target(self, target) -> dict:
        crawl_page_id = target["crawl_page_id"]
        is_form = "fields" in target
        method = target["method"] if is_form else "GET"
        sqli_id = None

        # Everything below (including an out-of-scope target via
        # assert_in_scope, or any other unexpected failure) is caught here so
        # this target always leaves a queryable sqli_detector row instead of
        # silently vanishing from the results with no DB trace.
        try:
            if is_form:
                cmd, final_url = self.sqlmap.build_probe(
                    target["target_url"], method=target["method"], fields=target["fields"])
            else:
                cmd, final_url = self.sqlmap.build_probe(
                    target["target_url"], method="GET",
                    param_names=[p.get("name", "") for p in target["params"]])
            if cmd is None:
                return self._record_target_error(
                    None, crawl_page_id, target["target_url"], method, "Could not build form data")

            sqli_id = self.db.insert_sqli_detector(
                crawl_page_id=crawl_page_id, target_url=final_url, method=method,
                is_vulnerable=0, state="running")
            if not sqli_id:
                return {"vulnerable": False, "error": "Database error"}

            # Higher level/risk (see SqlmapTool.base_args/build_probe) means a
            # much bigger payload battery per parameter — 240s was tuned for
            # the old level=1/risk=1 defaults and now cuts thorough runs short.
            report = self.sqlmap.run_parsed(cmd, max_time=600)

            if report.connection_timeouts >= 3:
                return self._handle_error(sqli_id, "Too many connection timeouts (possible WAF/IPS)")

            new_state = "pending" if report.vulnerable else "done"
            self.db.update_sqli_detector_results(
                sqli_id=sqli_id, is_vulnerable=1 if report.vulnerable else 0,
                injection_points=report.injection_points or None,
                injection_types=report.injection_types or None,
                dbms=report.dbms, error_message=None, state=new_state)

            if report.vulnerable:
                self.console.warn(f"VULNERABLE: {final_url}")
                if self.job_id:
                    self.db.insert_activity_log(
                        jobs_id=self.job_id, event_type="vulnerable_page_found",
                        reference_id=sqli_id, reference_table="sqli_detector",
                        details={"url": final_url})
            else:
                self.console.ok(f"Not vulnerable: {final_url}")
            return {"url": final_url, **report.__dict__}
        except Exception as exc:
            return self._record_target_error(sqli_id, crawl_page_id, target.get("target_url", ""), method, str(exc))

    def _record_target_error(self, sqli_id, crawl_page_id, target_url, method, message) -> dict:
        if sqli_id:
            self.db.update_sqli_detector_results(
                sqli_id=sqli_id, is_vulnerable=0, error_message=message, state="error")
        else:
            self.db.insert_sqli_detector(
                crawl_page_id=crawl_page_id, target_url=target_url, method=method,
                is_vulnerable=0, error_message=message, state="error")
        self.console.error(message)
        return {"vulnerable": False, "error": message}

    def _handle_error(self, sqli_id, msg) -> dict:
        self.db.update_sqli_detector_results(
            sqli_id=sqli_id, is_vulnerable=0, error_message=msg, state="error")
        self.console.error(msg)
        return {"vulnerable": False, "error": msg}


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Detects SQLi with SQLMap on already-crawled pages")
    parser.add_argument("--web-app-id", type=int, default=None, help="Analyzes all pages of this host_web_app")
    parser.add_argument("--crawl-page-id", type=int, default=None, help="Analyzes a single crawl_page")
    parser.add_argument("--job-id", type=int, default=None, help="Job ID (for activity logs)")
    args = parser.parse_args()

    if args.web_app_id is None and args.crawl_page_id is None:
        parser.error("specify --web-app-id or --crawl-page-id")

    result = WebDetector(
        web_app_id=args.web_app_id, crawl_page_id=args.crawl_page_id, job_id=args.job_id,
    ).execute()
    sys.exit(result.exit_code())

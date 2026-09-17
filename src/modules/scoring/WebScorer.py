#!/usr/bin/env python3


"""
web_scorer.py - SQLi priority scoring of crawl_pages.

Pattern: BaseModule (Template Method). It does not use external tools. Two
scoring strategies, chosen based on each page's job type:
  - Normal: deterministic local scoring (SCORING_TABLE).
  - IA:     batch evaluation via the AI module (if available).
"""

from __future__ import annotations

if __name__ == "__main__":
    import os
    import sys
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

from core import ModuleBase, ModuleResult
from modules.scoring.WebScorerAIPromt import ia_priorizar_paginas_sqli_batch

IA_AVAILABLE = True
CONTEXT_FIELDS = [
    "url", "base_url", "is_admin_path", "has_login_form", "has_register_form",
    "has_search_form", "has_upload_form", "has_form_without_csrf", "has_errors",
    "has_parametres_url", "is_referred_robots", "has_get_params", "has_post_params",
]

SCORING_TABLE = {
    "has_errors": 80, "has_post_params": 20, "has_get_params": 20,
    "has_parametres_url": 15, "has_search_form": 15, "has_form_without_csrf": 10,
    "has_login_form": 10, "has_register_form": 10, "has_upload_form": 5,
    "is_admin_path": 5, "is_referred_robots": 5,
}


class WebScorer(ModuleBase):
    slug = "web_scorer"

    def __init__(self, crawl_page_ids, *, job_id=None):
        super().__init__(target_id=None, job_id=job_id)
        self.page_ids = list(crawl_page_ids)
        self.success_count = 0

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def validate(self) -> bool:
        if not self.page_ids:
            self.console.error("No crawl_page_ids were specified")
            return False
        return True

    def load(self) -> bool:
        """Classifies the pages by strategy (Normal / IA)."""
        self.normal_pages, self.ai_pages = [], []
        for page_id in self.page_ids:
            row = self.db.get_crawl_page(page_id)
            if isinstance(row, list):
                row = row[0] if row else None
            if not row:
                self.console.warn(f"crawl_page id={page_id} not found, skipping")
                continue
            ctx = self._build_context(row)
            ctx["id"] = page_id
            ctx["jobs_id"] = row.get("jobs_id")
            if self._job_type(row) == "IA":
                self.ai_pages.append((page_id, ctx))
            else:
                self.normal_pages.append((page_id, ctx))

        if not self.normal_pages and not self.ai_pages:
            self.console.error("There are no valid pages")
            return False
        return True

    def run(self) -> ModuleResult:
        self.console.banner(f"🔍 WEBSCORER - {len(self.page_ids)} pages")
        if self.normal_pages:
            self._score_normal(self.normal_pages)
        if self.ai_pages:
            self._score_ai(self.ai_pages)
        msg = f"{self.success_count}/{len(self.page_ids)} pages scored"
        if self.success_count:
            return ModuleResult.ok(self.slug, msg, findings=self.success_count)
        return ModuleResult.empty(self.slug, msg)

    def on_log(self, result: ModuleResult, log_text: str) -> None:
        for page_id in self.page_ids:
            self.db.update_crawl_page_log(page_id, log_text)

    # ------------------------------------------------------------------
    # Normal strategy (local)
    # ------------------------------------------------------------------

    def _score_normal(self, pages) -> None:
        self.console.step(f"Normal mode: {len(pages)} pages (local)")
        for page_id, ctx in pages:
            # One page's data crashing _compute_local/_save must not cost the
            # other ~50 pages in this batch their score (and thus their shot
            # at ever reaching the detector) — isolate per page.
            try:
                score, level, reasons = self._compute_local(ctx)
                self._save(page_id, score, level)
                self.console.ok(f"id={page_id} score={score} level='{level}' {reasons}")
                self.success_count += 1
            except Exception as exc:
                self.console.error(f"id={page_id} failed to score, continuing: {exc}")
                self.db.update_crawl_page_state(page_id, "error", error_message=str(exc))

    # ------------------------------------------------------------------
    # AI strategy (in batches grouped by job)
    # ------------------------------------------------------------------

    def _score_ai(self, pages) -> None:
        if not IA_AVAILABLE:
            self.console.error("AI module not available — reverting to pending_score")
            for page_id, _ in pages:
                self.db.update_crawl_page_state(page_id, "pending_score")
            return

        groups: dict = {}
        for page_id, ctx in pages:
            groups.setdefault(ctx.get("jobs_id") or 0, []).append((page_id, ctx))

        for jobs_id, group in groups.items():
            job_context = self.db.get_sqli_context_for_job(jobs_id) if jobs_id else None
            self.console.step(f"AI mode: job={jobs_id}, {len(group)} pages")
            results = ia_priorizar_paginas_sqli_batch(
                [ctx for _, ctx in group], job_context=job_context)
            if not results:
                self.console.error("AI call failed — reverting to pending_score")
                for page_id, _ in group:
                    self.db.update_crawl_page_state(page_id, "pending_score")
                continue
            by_id = {r["id"]: r for r in results if isinstance(r, dict) and "id" in r}
            for page_id, _ in group:
                r = by_id.get(page_id)
                if not r or r.get("priority_score") is None or r.get("priority_level") is None:
                    self.console.warn(f"No AI result for id={page_id} — pending_score")
                    self.db.update_crawl_page_state(page_id, "pending_score")
                    continue
                try:
                    self._save(page_id, r["priority_score"], r["priority_level"])
                    self.console.ok(f"id={page_id} score={r['priority_score']} level='{r['priority_level']}'")
                    self.success_count += 1
                except Exception as exc:
                    self.console.error(f"id={page_id} failed to save AI score, continuing: {exc}")
                    self.db.update_crawl_page_state(page_id, "error", error_message=str(exc))

    # ------------------------------------------------------------------
    # Utilities
    # ------------------------------------------------------------------

    @staticmethod
    def _build_context(row: dict) -> dict:
        ctx = {}
        for field in CONTEXT_FIELDS:
            value = row.get(field)
            if field not in ("url", "base_url") and isinstance(value, int):
                value = bool(value)
            ctx[field] = value
        return ctx

    def _job_type(self, row: dict) -> str:
        jobs_id = row.get("jobs_id")
        if not jobs_id:
            return "Normal"
        return (self.db.get_job(jobs_id) or {}).get("type", "Normal")

    @staticmethod
    def _compute_local(ctx: dict):
        raw = sum(pts for field, pts in SCORING_TABLE.items() if ctx.get(field) is True)
        score = min(raw, 100)
        if ctx.get("has_errors") is True and score >= 80:
            level = "high"
        elif score >= 30:
            level = "medium"
        else:
            level = "low"
        reasons = [f for f in SCORING_TABLE if ctx.get(f) is True]
        return score, level, reasons

    def _save(self, page_id: int, score: int, level: str) -> None:
        self.db.update_crawl_page_priority(page_id, score, level)
        self.db.update_crawl_page_state(page_id, "pending")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Scores the SQLi priority of a batch of crawl_pages")
    parser.add_argument("--crawl-page-ids", required=True, help="Comma-separated crawl_page IDs, e.g. 1,2,3")
    parser.add_argument("--job-id", type=int, default=None, help="Job ID (for activity logs)")
    args = parser.parse_args()

    page_ids = [int(x) for x in args.crawl_page_ids.split(",") if x.strip()]
    result = WebScorer(page_ids, job_id=args.job_id).execute()
    sys.exit(result.exit_code())

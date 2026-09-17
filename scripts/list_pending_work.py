#!/usr/bin/env python3
"""Lists all pending/in-flight pipeline work in the DB.

Read-only counterpart to mark_pending_done.py - shows exactly what that
script would touch, without changing anything. Mirrors the definition of
"pending work" from db/domains/status.py::StatusMixin.get_pending_work_count():
  - host_web_app:  state in ('pending', 'running')
  - crawl_page:    state in ('pending', 'running', 'pending_score', 'running_score')
  - sqli_detector: state == 'pending'
"""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from sqlalchemy import select

from core.console import Console
from db.base import DatabaseConnection
from db.models import CrawlPage, HostWebApp, SqliDetector

console = Console()

# model, states-to-report, label column (what to print as the identifying value)
PENDING_QUERIES = [
    (HostWebApp, ["pending", "running"], "target_url"),
    (CrawlPage, ["pending", "running", "pending_score", "running_score"], "url"),
    (SqliDetector, ["pending"], "target_url"),
]


def list_pending(job_id: int = None) -> dict:
    session = DatabaseConnection.get_instance().session
    report = {}
    for model, states, label_col in PENDING_QUERIES:
        stmt = select(model).where(model.state.in_(states))
        if job_id is not None:
            stmt = stmt.where(model.jobs_id == job_id)
        rows = session.scalars(stmt.order_by(model.jobs_id, model.id)).all()
        report[model.__tablename__] = [
            {
                "id": row.id,
                "jobs_id": row.jobs_id,
                "state": row.state,
                "label": getattr(row, label_col, None),
            }
            for row in rows
        ]
    return report


def print_report(report: dict) -> None:
    total = sum(len(rows) for rows in report.values())
    if total == 0:
        console.ok("No pending work found.")
        return

    for table, rows in report.items():
        if not rows:
            continue
        console.step(f"{table} ({len(rows)}):")
        for row in rows:
            console.plain(f"  • id={row['id']} jobs_id={row['jobs_id']} state={row['state']} {row['label']}")

    console.ok(f"Total: {total} pending item(s)")


def main():
    parser = argparse.ArgumentParser(
        description="Lists all pending/in-flight pipeline work (host_web_app, "
                     "crawl_page, sqli_detector)."
    )
    parser.add_argument("--job-id", type=int, default=None,
                        help="Limit to a single job (default: all jobs)")
    parser.add_argument("--json", action="store_true",
                        help="Print machine-readable JSON instead of a text report")
    args = parser.parse_args()

    report = list_pending(args.job_id)

    if args.json:
        console.plain(json.dumps(report, indent=2))
    else:
        print_report(report)


if __name__ == "__main__":
    main()

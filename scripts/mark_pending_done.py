#!/usr/bin/env python3
"""Marks all pending/in-flight pipeline work as 'done'.

Drains the backlog that SQLiAgentOrchestrator.py would otherwise keep dispatching -
useful to stop a stuck or runaway monitoring session, or to reset a job's
outstanding work once its pipeline processes are no longer running.

Mirrors the definition of "pending work" from
db/domains/status.py::StatusMixin.get_pending_work_count():
  - host_web_app:  state in ('pending', 'running')
  - crawl_page:    state in ('pending', 'running', 'pending_score', 'running_score')
  - sqli_detector: state == 'pending'
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from sqlalchemy import update

from core.console import Console
from db.base import DatabaseConnection
from db.models import CrawlPage, HostWebApp, SqliDetector

console = Console()

PENDING_STATES = {
    HostWebApp: ["pending", "running"],
    CrawlPage: ["pending", "running", "pending_score", "running_score"],
    SqliDetector: ["pending"],
}


def mark_all_done(job_id: int = None) -> dict:
    session = DatabaseConnection.get_instance().session
    counts = {}
    for model, states in PENDING_STATES.items():
        stmt = update(model).where(model.state.in_(states))
        if job_id is not None:
            stmt = stmt.where(model.jobs_id == job_id)
        stmt = stmt.values(state="done")
        result = session.execute(stmt)
        counts[model.__tablename__] = result.rowcount
    session.commit()
    return counts


def main():
    parser = argparse.ArgumentParser(
        description="Marks all pending/in-flight pipeline work (host_web_app, "
                     "crawl_page, sqli_detector) as 'done'."
    )
    parser.add_argument("--job-id", type=int, default=None,
                        help="Limit to a single job (default: all jobs)")
    parser.add_argument("--yes", action="store_true",
                        help="Skip the confirmation prompt")
    args = parser.parse_args()

    scope = f"job_id={args.job_id}" if args.job_id is not None else "ALL jobs"
    if not args.yes:
        answer = input(f"This will mark all pending/running pipeline work as 'done' for {scope}. Continue? [y/N] ")
        if answer.strip().lower() not in ("y", "yes"):
            console.warn("Aborted.")
            sys.exit(1)

    counts = mark_all_done(args.job_id)
    total = sum(counts.values())
    console.ok(f"Marked {total} row(s) as done:")
    for table, count in counts.items():
        console.plain(f"  • {table}: {count}")


if __name__ == "__main__":
    main()

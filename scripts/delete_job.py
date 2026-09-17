"""Deletes a job and every row that belongs to it.

All FK chains under `jobs` (hosts -> host_web_app -> crawl_page -> ...
-> sqli_exploit -> sqli_exploit_tables -> sqli_exploit_columns ->
sqli_exploit_data, plus activity_logs directly) are declared ON DELETE
CASCADE in the schema (see db/sqli_tfg.sql), so a single
`DELETE FROM jobs WHERE id = :job_id` is enough - MySQL cascades the rest
in one statement. That's deliberately raw SQL instead of the ORM's
session.delete(Job) (see DatabaseManager.delete_job in db/domains/jobs.py):
the ORM cascade would load every related row - including sqli_exploit's
LONGTEXT log/databases_json columns, ~26KB/row - into Python before
deleting them one by one, which is exactly the kind of full-table-scan
cost fixed by the jobs_id indexes baked into db/sqli_tfg.sql.

Usage (run from the project root, so .env is picked up):
    python scripts/delete_job.py <job_id> [--yes]

--yes / -y skips the confirmation prompt (for non-interactive use).
"""

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sqlalchemy import text

from db.base import DatabaseConnection

# Tables carrying jobs_id, in cascade order, for the pre-delete summary.
# (host_web_app_nikto hangs off host_web_app, not jobs, but still carries
# jobs_id and is cascaded via host_web_app -> CASCADE.)
RELATED_TABLES = [
    "hosts",
    "host_web_app",
    "host_nmap",
    "host_web_app_nikto",
    "crawl_page",
    "crawl_page_details",
    "sqli_detector",
    "sqli_exploit",
    "sqli_exploit_tables",
    "sqli_exploit_columns",
    "sqli_exploit_data",
    "activity_logs",
]


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("job_id", type=int, help="ID of the job to delete")
    parser.add_argument("-y", "--yes", action="store_true", help="Skip the confirmation prompt")
    args = parser.parse_args()

    engine = DatabaseConnection.get_instance().engine
    with engine.connect() as conn:
        job = conn.execute(
            text("SELECT id, type, target_url, state, timestamp FROM jobs WHERE id = :job_id"),
            {"job_id": args.job_id},
        ).mappings().first()

        if job is None:
            print(f"Job {args.job_id} not found.")
            sys.exit(1)

        print(f"Job {job['id']}: type={job['type']} state={job['state']} "
              f"target_url={job['target_url']} timestamp={job['timestamp']}")
        print("\nRows that will be deleted:")

        total = 0
        for table in RELATED_TABLES:
            count = conn.execute(
                text(f"SELECT COUNT(*) FROM {table} WHERE jobs_id = :job_id"),
                {"job_id": args.job_id},
            ).scalar()
            if count:
                print(f"  {table:<20} {count}")
                total += count
        print(f"  {'jobs':<20} 1")
        print(f"  {'total':<20} {total + 1}")

    if not args.yes:
        answer = input(f"\nDelete job {args.job_id} and all {total} related rows? [y/N] ").strip().lower()
        if answer != "y":
            print("Aborted.")
            sys.exit(1)

    start = time.monotonic()
    with engine.begin() as conn:
        result = conn.execute(text("DELETE FROM jobs WHERE id = :job_id"), {"job_id": args.job_id})
    elapsed = time.monotonic() - start

    if result.rowcount:
        print(f"Deleted job {args.job_id} and its cascaded rows in {elapsed:.2f}s.")
    else:
        print(f"Job {args.job_id} was not deleted (already gone?).")
        sys.exit(1)


if __name__ == "__main__":
    main()

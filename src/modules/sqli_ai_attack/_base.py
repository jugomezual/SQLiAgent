#!/usr/bin/env python3
"""
_base.py - Common base of the AI-assisted post-exploitation modules.

The three modules in this package (schema analysis, credential hunting and
admin-user injection) shared LITERALLY the same lifecycle, written three times
as a standalone script with `argparse` + module-level code:

    1. Query the results DB (sqli_exploit_tables + sqli_exploit_columns).
    2. Filter the tables of interest against a list of patterns.
    3. Build the `bd_structure` consumed by the AI function.
    4. Call the corresponding AI function.

`SqliAiAttackModule` extracts steps 1-3 (identical in all three) to the core's
`BaseModule` pattern: they live in `validate()` and `load()`. Each subclass only
provides what makes it different:

    - slug             : stable identifier for the record.
    - TABLA_PATTERNS   : patterns of relevant tables.
    - REQUIRE_DB       : True if --db is mandatory (schema analyzer).
    - run()            : calls ITS AI function and returns a ModuleResult.
"""

from __future__ import annotations

import json as _json
from typing import Any, Optional, Pattern

from core import BaseModule, ModuleResult

# ---------------------------------------------------------------------------
# Offensive-capability removal notice
# ---------------------------------------------------------------------------
# The AI prompts that used to drive this package have been removed for safety.
# The former AI entry points now call this helper instead of contacting the
# model, so the modules stay importable and the CLI / report flows keep working
# while the offensive behaviour is disabled. The message is deliberately plain
# ASCII so it can never fail to print on a non-UTF-8 console.
def offensive_prompt_removed_notice(capability: str) -> None:
    """Print a clear notice that an offensive AI prompt has been removed.

    Args:
        capability: short description of the disabled feature, e.g.
            "database credential discovery".
    """
    line = "=" * 70
    print("")
    print(line)
    print("[!] OFFENSIVE AI PROMPT REMOVED - CAPABILITY DISABLED")
    print(line)
    print(f'The AI prompt that powered "{capability}" has been intentionally')
    print("removed from this build.")
    print("")
    print("These prompts instructed a language model to actively assist with")
    print("offensive database post-exploitation - locating credential stores,")
    print("inferring privilege-escalation paths and generating admin-account")
    print("injection SQL. They were stripped to prevent this tool from being")
    print("misused to attack systems without proper authorization.")
    print("")
    print("No AI request was sent and no offensive output was produced.")
    print(line)


class SqliAiAttackModule(BaseModule):
    """Common lifecycle of the AI-assisted post-exploitation phase."""

    #: Patterns of relevant tables. Each subclass sets its own.
    TABLA_PATTERNS: list[Pattern[str]] = []

    #: If True, the subclass requires a specific `db_name` (does not accept "all").
    REQUIRE_DB: bool = False

    def __init__(self, db_name: Optional[str] = None, *, job_id: Optional[int] = None,
                 quiet: bool = False):
        super().__init__(target_id=None, job_id=job_id, quiet=quiet)
        self.db_name = db_name
        # Populated by load(); consumed by run() in the subclass.
        self.bd_structure: dict[str, list] = {"bases_de_datos": []}

    # ------------------------------------------------------------------
    # Lifecycle (BaseModule pattern)
    # ------------------------------------------------------------------

    def validate(self) -> bool:
        if self.REQUIRE_DB and not self.db_name:
            self.console.error("A specific database must be provided (--db)")
            return False
        return True

    def load(self) -> bool:
        """Queries the DB, filters the relevant tables and assembles `bd_structure`."""
        rows_tables, rows_columns = self._fetch_exploit_data()

        if not rows_tables:
            self.console.warn(f"There is no exploitation data for {self._target_label()}")
            return False

        columns_index = self._index_columns(rows_columns)
        self.bd_structure = self._build_structure(rows_tables, columns_index)

        if not self.bd_structure["bases_de_datos"]:
            self.console.warn(f"No relevant tables were found in {self._target_label()}")
            return False
        return True

    # `run()` is each subclass's responsibility (it calls its AI function).

    # ------------------------------------------------------------------
    # Shared utilities
    # ------------------------------------------------------------------

    def is_relevant_table(self, table_name: str) -> bool:
        """True if the table name matches any of the TABLA_PATTERNS."""
        return any(p.match(table_name) for p in self.TABLA_PATTERNS)

    def _target_label(self) -> str:
        """Human-readable label of the current target, for console messages."""
        label = f"'{self.db_name}'" if self.db_name else "no specific database"
        if self.job_id:
            label += f" (job {self.job_id})"
        return label

    def _fetch_exploit_data(self) -> tuple[list, list]:
        """
        Returns (table_rows, column_rows) from the exploitation results
        layer, applying the --db / --job filters.
        """
        return self.db.get_exploit_schema_rows(self.db_name, self.job_id)

    @staticmethod
    def _parse_json_list(value: Any) -> list:
        """Parses a JSON field that must be a list; [] on any error."""
        try:
            parsed = _json.loads(value) if isinstance(value, str) else value
            return parsed if isinstance(parsed, list) else []
        except Exception:
            return []

    def _index_columns(self, rows_columns: list) -> dict[int, dict[str, list]]:
        """Index exploit_tables_id -> {table_name -> [columns]}."""
        index: dict[int, dict[str, list]] = {}
        for row in rows_columns:
            etid = row["sqli_exploit_tables_id"]
            tname = row["table_name"] or ""
            index.setdefault(etid, {})[tname] = self._parse_json_list(row["columns_json"])
        return index

    def _build_structure(self, rows_tables: list,
                         columns_index: dict[int, dict[str, list]]) -> dict[str, list]:
        """
        Builds the structure the AI expects:

            {"bases_de_datos": [
                {"nombre": <db>, "tablas": [{"nombre": <t>, "columnas": [...]}, ...]},
                ...
            ]}

        The query already filters by --db/--job, so here we only aggregate and
        discard the tables that do not match TABLA_PATTERNS.
        """
        dbs_dict: dict[str, dict[str, list]] = {}
        for row in rows_tables:
            db_name = row["db_name"] or "unknown"
            etid = row["exploit_tables_id"]
            tables = self._parse_json_list(row["tables_json"])
            tables_cols = columns_index.get(etid, {})
            bucket = dbs_dict.setdefault(db_name, {})
            for table_name in tables:
                if self.is_relevant_table(table_name):
                    bucket[table_name] = tables_cols.get(table_name, [])

        databases = [
            {
                "nombre": db_name,
                "tablas": [{"nombre": t, "columnas": cols} for t, cols in tables.items()],
            }
            for db_name, tables in dbs_dict.items()
            if tables
        ]
        return {"bases_de_datos": databases}

    # ------------------------------------------------------------------
    # Helper to keep each module's CLI execution working
    # ------------------------------------------------------------------

    @classmethod
    def _cli(cls, description: str) -> "SqliAiAttackModule":
        """
        Builds an instance from --db/--job arguments.
        Used by each module's `if __name__ == '__main__':` blocks to
        preserve script usage:  `python -m ... --db X --job 3`.
        """
        import argparse

        parser = argparse.ArgumentParser(description=description)
        parser.add_argument("--db", required=cls.REQUIRE_DB, default=None,
                            help="Database name"
                                 + ("" if cls.REQUIRE_DB else " (omit = all)"))
        parser.add_argument("--job", required=False, default=None, type=int,
                            help="Job ID to filter by (omit = all)")
        args = parser.parse_args()
        return cls(args.db, job_id=args.job)

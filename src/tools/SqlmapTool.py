"""
sqlmap_tool.py - SQLMap adapter.

Centralizes the common SQLMap logic:

    - Check availability.
    - Build form-data.
    - Provide base flags.
    - Run SQLMap with streaming + timeout.
    - Detect markers in the output.
    - Locate dump CSVs.
    - Read dump CSVs.

The modules remain responsible for building the concrete command.
"""

from __future__ import annotations

import csv
import glob
import os
import queue
import re
import shlex
import subprocess
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable
import json
from urllib.parse import quote_plus, urlparse, parse_qs

from core.scope import assert_in_scope
from tools.ExternalTool import ExternalTool, ToolResult


DEFAULT_OUTPUT_DIR = "/var/lib/sqlmap_output"


@dataclass(frozen=True)
class SqlmapResult(ToolResult):
    """SQLMap-specific result, compatible with ToolResult."""

    success: bool = False
    output_lines: list[str] = field(default_factory=list)
    marker_matches: dict[str, bool] = field(default_factory=dict)
    error: str | None = None


@dataclass
class SqlmapReport:
    """
    Already-PARSED SQLMap output (domain). Produced by `parse_output`, it captures
    everything the modules need: databases, tables, columns, dump status,
    vulnerability, injection points/types, DBMS and number of connection timeouts.
    Each module reads only the fields it cares about.
    """

    success: bool = False
    databases: list[str] = field(default_factory=list)
    tables: list[str] = field(default_factory=list)
    columns: list[dict] = field(default_factory=list)
    dumped: bool = False
    entries: int = 0
    vulnerable: bool = False
    injection_points: list[str] = field(default_factory=list)
    injection_types: list[str] = field(default_factory=list)
    dbms: str | None = None
    connection_timeouts: int = 0


class SqlmapTool(ExternalTool):
    """Adapter for the `sqlmap` binary."""

    binary = "sqlmap"
    version_args = ["--version"]

    #: GET parameters/fields that are worth excluding from testing (--skip). "page"
    #: is deliberately not here: it is exactly the vulnerable parameter of
    #: Mutillidae (one of the most common targets), so excluding it by name
    #: left us blind to that real case.
    PROBLEMATIC_PARAMS = ("file", "include", "template", "view", "module", "action")

    def __init__(self, output_dir: str = DEFAULT_OUTPUT_DIR):
        self.output_dir = output_dir

    @staticmethod
    def build_form_data(fields: list[dict[str, Any]]) -> str | None:
        """Turns a form's fields into a test POST body."""
        params: list[str] = []
        for field in fields:
            name = field.get("name")
            if not name:
                continue
            field_type = field.get("type", "text").lower()
            if field_type in ("checkbox", "radio"):
                value = field.get("value", "1")
            elif field_type == "select":
                options = field.get("options", [])
                value = options[0] if options else "1"
            else:
                value = field.get("value") or "1"
            params.append(f"{quote_plus(name)}={quote_plus(str(value))}")
        return "&".join(params) if params else None

    def base_args(self, *, threads: int = 5, fresh_queries: bool = False,
                  output_dir: bool = True) -> list[str]:
        """Base flags common to every SQLMap invocation in the project."""
        args = ["--batch", f"--threads={threads}", "--timeout=30",
                "--retries=1", "--union-cols=1-15"]
        if fresh_queries:
            args.append("--fresh-queries")
        if output_dir:
            args.append(f"--output-dir={self.output_dir}")
        return args

    def skip_flags(self, names) -> list[str]:
        """Returns ['--skip', 'a,b'] with the problematic parameters, or []."""
        problematic = [n for n in names
                       if any(p in (n or "").lower() for p in self.PROBLEMATIC_PARAMS)]
        return ["--skip", ",".join(problematic)] if problematic else []

    def command_for_vuln(self, url: str, method: str, extra_args=(), *,
                         forms_json=None, threads: int = 5,
                         fresh_queries: bool = False) -> list[str]:
        """
        Builds the command to EXPLOIT an already-known vulnerability
        (DBDumper/SQLExploiter). The module only provides url, method, the
        forms from the crawl and the operation flags (--dbs, -D, --dump...).
        """
        assert_in_scope(url)
        cmd = (["sqlmap", "-u", url]
               + self.base_args(threads=threads, fresh_queries=fresh_queries)
               + list(extra_args))
        if method == "POST" and forms_json:
            forms = json.loads(forms_json) if isinstance(forms_json, str) else forms_json
            matching = next((f for f in forms if f.get("action") == url), None)
            if matching and (data := self.build_form_data(matching.get("fields", []))):
                cmd += ["--data", data, "--crawl=0"]
        elif method == "GET" and "?" in url:
            cmd += self.skip_flags(parse_qs(urlparse(url).query).keys())
        return cmd

    def build_probe(self, url: str, *, method: str = "GET", fields=None,
                    param_names=None) -> tuple[list[str] | None, str | None]:
        """
        Builds the command to DETECT injection (WebDetector) against a
        form (fields) or a URL with parameters (param_names).
        Returns (cmd, final_url); (None, None) if there is no usable form-data.
        """
        assert_in_scope(url)
        common = ["--batch", "--timeout=30", "--retries=1", "--union-cols=1-15"]
        if fields is not None:  # form-type target
            data = self.build_form_data(fields)
            if not data:
                return None, None
            skip = self.skip_flags(f.get("name", "") for f in fields)
            if method == "GET":
                sep = "&" if "?" in url else "?"
                final_url = f"{url}{sep}{data}"
                cmd = (["sqlmap", "-u", final_url, "--batch", "--threads=1"]
                       + common[1:] + ["--fresh-queries", "--crawl=0"] + skip)
                return cmd, final_url
            cmd = (["sqlmap", "-u", url, "--batch", "--threads=1"]
                   + common[1:] + ["--fresh-queries", "--data", data])
            return cmd, url
        # URL-with-parameters target
        cmd = ["sqlmap", "-u", url] + common + self.skip_flags(param_names or [])
        return cmd, url

    def run(
            self,
            cmd: list[str],
            *,
            max_time: int = 360,
            markers: dict[str, str] | None = None,
            on_line: Callable[[str, dict[str, Any]], None] | None = None,
            stream_to_console: bool = True,
    ) -> SqlmapResult:
        """Runs an already-built SQLMap command. Returns a SqlmapResult."""
        markers = markers or {}
        marker_matches = {key: False for key in markers}
        output_lines: list[str] = []
        state: dict[str, Any] = {
            "success": False,
            "output": output_lines,
            "error": None,
            **marker_matches,
        }
        command_preview = shlex.join(cmd)

        if stream_to_console:
            print("\n📝 SQLMap command:")
            print(f"   {command_preview}\n")

        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                errors="replace",
                bufsize=1,
            )

            line_queue: queue.Queue[str | None] = queue.Queue()

            def _reader() -> None:
                if process.stdout is None:
                    line_queue.put(None)
                    return
                for raw_line in process.stdout:
                    line_queue.put(raw_line)
                line_queue.put(None)

            reader_thread = threading.Thread(target=_reader, daemon=True)
            reader_thread.start()

            started_at = time.monotonic()
            timed_out = False

            while True:
                elapsed = time.monotonic() - started_at
                if elapsed > max_time:
                    timed_out = True
                    self._terminate(process)
                    state["error"] = f"Timeout: SQLMap exceeded the {max_time}s limit"
                    break
                try:
                    raw = line_queue.get(timeout=0.1)
                except queue.Empty:
                    if process.poll() is not None:
                        break
                    continue
                if raw is None:
                    break
                line = raw.strip()
                if not line:
                    continue
                output_lines.append(line)
                if stream_to_console:
                    print(f"  {line}")
                low = line.lower()
                for key, pattern in markers.items():
                    if re.search(pattern, low):
                        marker_matches[key] = True
                        state[key] = True
                        state["success"] = True
                if on_line:
                    on_line(line, state)

            try:
                returncode = process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._terminate(process)
                returncode = process.returncode

            for key in marker_matches:
                marker_matches[key] = bool(state.get(key, marker_matches[key]))
            success = bool(state.get("success")) or any(marker_matches.values())

            return SqlmapResult(
                command=cmd, command_preview=command_preview, returncode=returncode,
                stdout="\n".join(output_lines), stderr="", timed_out=timed_out,
                success=success, output_lines=output_lines,
                marker_matches=marker_matches, error=state.get("error"),
            )
        except Exception as exc:
            return SqlmapResult(
                command=cmd, command_preview=command_preview, returncode=None,
                stdout="\n".join(output_lines), stderr=str(exc), timed_out=False,
                success=False, output_lines=output_lines,
                marker_matches=marker_matches, error=f"Error running SQLMap: {exc}",
            )

    @staticmethod
    def _terminate(process: subprocess.Popen) -> None:
        if process.poll() is not None:
            return
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()

    # ------------------------------------------------------------------
    # Output parsing (domain)
    # ------------------------------------------------------------------

    def run_parsed(self, cmd: list[str], *, max_time: int = 360, **kwargs) -> SqlmapReport:
        """
        Runs SQLMap and returns a parsed SqlmapReport directly.
        Convenience method analogous to NmapTool.scan_web_ports /
        WhatWebTool.fingerprint: one call -> domain data.
        """
        result = self.run(cmd, max_time=max_time, **kwargs)
        return self.parse_output(result.stdout)

    @staticmethod
    def parse_output(stdout: str) -> SqlmapReport:
        """
        Parses the COMPLETE SQLMap output in a single pass and returns a
        SqlmapReport. It is the adapter's own responsibility (it used to be
        scattered across the modules).
        """
        report = SqlmapReport()
        capture_mode: str | None = None

        for raw in (stdout or "").splitlines():
            line = raw.strip()
            if not line:
                continue
            low = line.lower()

            if "connection timed out" in low:
                report.connection_timeouts += 1

            # --- Vulnerability (WebDetector) ---
            if "all tested parameters do not appear to be injectable" in low:
                report.vulnerable = False
            elif any(x in low for x in ("is vulnerable", "injection point", "resumed the following")):
                report.vulnerable = True
            if m := re.search(r"Parameter:\s*([^\s(]+)", line):
                if m.group(1) not in report.injection_points:
                    report.injection_points.append(m.group(1))
            if (m := re.search(r"Type:\s*(.+)", line)) and "testing" not in low:
                t = m.group(1).strip()
                if t not in report.injection_types:
                    report.injection_types.append(t)
            if "back-end dbms:" in low:
                if m := re.search(r"back-end DBMS:\s*(.+)", line, re.IGNORECASE):
                    report.dbms = m.group(1).strip()

            # --- Databases ---
            if "available databases" in low:
                capture_mode = "dbs"
                report.success = True
            elif capture_mode == "dbs" and line.startswith("[*]"):
                db = line.replace("[*]", "").strip()
                if (db and db not in report.databases
                        and not any(k in db.lower() for k in
                                    ("ending", "starting", "shutting", "fetched"))
                        and "@" not in db and "/" not in db):
                    report.databases.append(db)

            # --- Tables ---
            if "[" in line and "table" in low:
                capture_mode = "tables"
                report.success = True
            elif capture_mode == "tables" and line.startswith("|") and line.endswith("|"):
                t = line.strip("|").strip()
                if (len(t) > 2 and not t.startswith(("+", "-", "_"))
                        and not set('[]()"\'.,|').intersection(set(t))
                        and t.replace("_", "").replace(" ", "").isalnum()
                        and t not in report.tables):
                    report.tables.append(t)

            # --- Columns ---
            if "[" in line and "column" in low:
                capture_mode = "columns"
                report.success = True
            elif capture_mode == "columns" and line.startswith("|") and line.endswith("|"):
                parts = [p.strip() for p in line.split("|") if p.strip()]
                if parts and not parts[0].startswith(("+", "-")) and parts[0].lower() != "column":
                    col = {"name": parts[0], "type": parts[1] if len(parts) > 1 else "unknown"}
                    if col not in report.columns:
                        report.columns.append(col)

            # --- Dump ---
            if "dumped to csv file" in low or ("table" in low and "dumped" in low):
                report.dumped = True
                report.success = True
            if "entries" in low:
                nums = re.findall(r"\d+", line)
                if nums:
                    report.entries = int(nums[0])

        return report

    @staticmethod
    def rows_as_dicts(headers: list[str], rows: list[list[str]]) -> list[dict]:
        """Converts the (headers, rows) from read_csv_dump into a list of dicts."""
        return [dict(zip(headers, r)) for r in rows]

    def find_dump_csv(self, target_url: str, db_name: str, table_name: str) -> str | None:
        """Finds the CSV that SQLMap generates for a specific dump."""
        domain = urlparse(target_url).netloc.replace(":", "_")
        patterns = [
            os.path.join(self.output_dir, domain, "dump", db_name, f"{table_name}.csv"),
            os.path.join(self.output_dir, domain, "dump", f"{table_name}.csv"),
            os.path.join(self.output_dir, domain, "dump", db_name, "*.csv"),
        ]
        for pattern in patterns:
            matches = glob.glob(pattern)
            if matches:
                return matches[0]
        return None

    @staticmethod
    def read_csv_dump(csv_file: str) -> tuple[list[str], list[list[str]]]:
        """Reads a dump CSV and returns (headers, rows)."""
        with open(csv_file, newline="", encoding="utf-8", errors="replace") as fh:
            reader = csv.reader(fh)
            rows = list(reader)
        if not rows:
            return [], []
        return rows[0], rows[1:]

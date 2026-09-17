"""
ModuleBase.py - Abstract base class for all modules.
Provides the COMMON FUNCTIONALITY to the six modules, which is currently duplicated:
  - Homogeneous constructor (target + optional job_id).
  - Access to the database (`self.db`) and the console (`self.console`).
  - `slug` derived automatically from the class name.
  - Management and verification of external tools (`self.require_tool`).
  - `execute()` TEMPLATE (Template Method pattern): fixes the skeleton
    validate -> load -> run -> report and centralizes error handling
"""

from __future__ import annotations

import io
import re
import sys
from abc import ABC, abstractmethod
from contextlib import redirect_stdout
from typing import Optional

from core.console import Console
from core.exceptions import ModuleError, ToolNotAvailable
from core.ModuleResult import ModuleResult, Status

# Centralized database API.
from db.database import DatabaseManager

# Cap on the size of the log persisted per execution; the tail is kept (the
# most recent is usually the most relevant for diagnosing a failure).
_MAX_LOG_CHARS = 20000


class _Tee(io.TextIOBase):
    """Writes to several streams at once: keeps the live output intact
    (terminal / restapi.py SSE) while accumulating it in a separate buffer."""

    def __init__(self, *streams):
        self._streams = streams

    def write(self, data):
        for stream in self._streams:
            stream.write(data)
        return len(data)

    def flush(self):
        for stream in self._streams:
            stream.flush()


def _truncate_log(text: str) -> str:
    text = text.strip()
    if len(text) > _MAX_LOG_CHARS:
        text = text[-_MAX_LOG_CHARS:]
    return text


class BaseModule(ABC):
    #: Subclasses MUST set a stable slug. Otherwise it is derived from the name.
    slug: str = ""

    def __init__(self, target_id=None, *, job_id: Optional[int] = None, quiet: bool = False):
        self.target_id = target_id
        self.job_id = job_id
        self.db = DatabaseManager
        self.console = Console(quiet=quiet)

        if not self.slug:
            # 'DBDumper' -> 'db_dumper', 'WebScanner' -> 'web_scanner'
            self.slug = self._default_slug(type(self).__name__)

    # ------------------------------------------------------------------
    # Abstract hooks: each module implements ONLY its own logic
    # ------------------------------------------------------------------

    @abstractmethod
    def validate(self) -> bool:
        """Preconditions. Returns False to abort."""

    @abstractmethod
    def load(self) -> bool:
        """Loads the context from the DB. Returns False to abort."""

    @abstractmethod
    def run(self) -> ModuleResult:
        """Actual work of the module. Returns a ModuleResult."""

    def report(self, result: ModuleResult) -> None:
        """
        Default summary. Subclasses may override it with a
        richer summary (tables, counters, etc.).
        """
        if result.succeeded:
            self.console.ok(result.message or f"{self.slug}: completed")
        else:
            self.console.error(result.message or f"{self.slug}: failed")

    # ------------------------------------------------------------------
    # Template Method: the algorithm shared by the six modules
    # ------------------------------------------------------------------

    def execute(self) -> ModuleResult:
        """
        Orchestrates the full lifecycle and NEVER propagates domain
        exceptions: it always returns a ModuleResult. This is the only thing the
        CLI/orchestrator needs to invoke.

        All console output of this cycle (validate/load/run/report) is
        captured in parallel with the real output, so it can be persisted as
        the execution "log" via `on_log()` without losing the live
        streaming (terminal / restapi.py SSE).
        """
        buffer = io.StringIO()
        real_stdout = sys.stdout
        with redirect_stdout(_Tee(real_stdout, buffer)):
            try:
                if not self.validate():
                    result = self._finish(ModuleResult.skip(self.slug, "Validation failed"))
                elif not self.load():
                    result = self._finish(ModuleResult.fail(self.slug, "Could not load the context"))
                else:
                    result = self._finish(self.run())
            except ToolNotAvailable as exc:
                result = self._finish(ModuleResult.skip(self.slug, str(exc)))
            except ModuleError as exc:
                result = self._finish(ModuleResult.fail(self.slug, str(exc)))
            except Exception as exc:  # safety net: never blow up the pipeline
                result = self._finish(ModuleResult.fail(self.slug, f"Unexpected error: {exc}"))

        try:
            self.on_log(result, _truncate_log(buffer.getvalue()))
        except Exception as exc:  # persisting the log must not hide the original result
            self.console.warn(f"Could not persist the log: {exc}")
        return result

    def _finish(self, result: ModuleResult) -> ModuleResult:
        """Common final hook: reports and returns. Single point for logging/DB."""
        try:
            self.report(result)
        except Exception as exc:  # a failure while printing must not change the result
            self.console.warn(f"Could not generate the report: {exc}")
        if result.status is Status.FAILED:
            try:
                self.on_failure(result)
            except Exception as exc:  # persisting the error must not hide the original result
                self.console.warn(f"Could not persist the error: {exc}")
        return result

    def on_failure(self, result: ModuleResult) -> None:
        """
        Hook for subclasses to persist the failure (state='error' +
        error_message) in the DB row that represents their unit of
        work. No-op by default: not all modules have a 1:1 row
        to update at this point (e.g. WebDetector already persists its
        own errors explicitly during `run()`).
        """

    def on_log(self, result: ModuleResult, log_text: str) -> None:
        """
        Hook for subclasses to save the full output of this
        execution (`log` column) in their DB row. It is always called,
        both on success and on failure — unlike `on_failure`, which only
        covers the state + short error message. No-op by default.
        """

    # ------------------------------------------------------------------
    # External tool management (composition, not inheritance)
    # ------------------------------------------------------------------

    def require_tool(self, tool) -> None:
        """
        Ensures a tool is available; if not, it raises
        ToolNotAvailable (which `execute()` turns into a SKIPPED result).
        Use it inside `validate()`.
        """
        if not tool.is_available():
            raise ToolNotAvailable(f"'{tool.binary}' is not installed or is not executable")

    # ------------------------------------------------------------------
    # Shared utilities
    # ------------------------------------------------------------------

    @staticmethod
    def _default_slug(class_name: str) -> str:
        """CamelCase -> snake_case ('SQLExploiter' -> 'sql_exploiter')."""
        s1 = re.sub(r"(.)([A-Z][a-z]+)", r"\1_\2", class_name)
        return re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", s1).lower()

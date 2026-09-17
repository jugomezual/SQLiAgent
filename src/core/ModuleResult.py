"""
ModuleResult.py - Uniform return type for all modules.
`ModuleResult` unifies that contract: every module ends up returning a
`ModuleResult`, so the orchestrator/CLI/tests always know what to expect.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Status(str, Enum):
    """Overall result of a module execution."""

    SUCCESS = "success"          # Finished and found/produced what was expected
    NO_FINDINGS = "no_findings"  # Finished fine but with no findings (not an error)
    FAILED = "failed"            # Execution failed (tool error, DB error, etc.)
    SKIPPED = "skipped"          # Did not run (precondition not met)


@dataclass
class ModuleResult:
    """
    Standard return value of any pipeline module.

    Attributes:
        status:   Overall status (see `Status`).
        module:   Slug of the module that produced the result (e.g. 'db_dumper').
        message:  Human-readable message / logs.
        data:     Free payload (dumped rows, sqli IDs, ports, etc.).
        findings: Number of relevant findings (vulns, pages, entries...).
        errors:   List of non-fatal errors accumulated during execution.
    """

    status: Status
    module: str
    message: str = ""
    data: dict[str, Any] = field(default_factory=dict)
    findings: int = 0
    errors: list[str] = field(default_factory=list)

    # ------------------------------------------------------------------
    # Convenience constructors (avoid repeating Status.* all over the code)
    # ------------------------------------------------------------------

    @classmethod
    def ok(cls, module: str, message: str = "", *, findings: int = 0, **data: Any) -> "ModuleResult":
        return cls(Status.SUCCESS, module, message, data=data, findings=findings)

    @classmethod
    def empty(cls, module: str, message: str = "No findings") -> "ModuleResult":
        return cls(Status.NO_FINDINGS, module, message)

    @classmethod
    def fail(cls, module: str, message: str, **data: Any) -> "ModuleResult":
        return cls(Status.FAILED, module, message, data=data, errors=[message])

    @classmethod
    def skip(cls, module: str, message: str) -> "ModuleResult":
        return cls(Status.SKIPPED, module, message)

    # ------------------------------------------------------------------
    # Utilities
    # ------------------------------------------------------------------

    @property
    def succeeded(self) -> bool:
        """True if the execution did not fail (success or success-without-findings)."""
        return self.status in (Status.SUCCESS, Status.NO_FINDINGS)

    def exit_code(self) -> int:
        """Exit code to use directly in the CLI (`sys.exit(...)`)."""
        return 0 if self.succeeded else 1

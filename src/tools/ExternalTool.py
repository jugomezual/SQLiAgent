"""
ExternalTool.py - Base adapter for external tools.
"""

from __future__ import annotations

import shlex
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass(frozen=True)
class ToolResult:
    """Normalized result of running an external tool."""

    command: list[str]
    command_preview: str
    returncode: int | None
    stdout: str
    stderr: str
    timed_out: bool = False


class ExternalTool(ABC):
    """Wrapper around an external system binary."""

    binary: str = ""
    version_args: list[str] = ["--version"]

    def is_available(self) -> bool:
        """True if the binary is installed and responds."""
        try:
            return subprocess.run(
                [self.binary, *self.version_args],
                capture_output=True,
                timeout=5,
                text=True,
                errors="replace",
            ).returncode == 0
        except Exception:
            return False

    def _run_command(self, command: list[str], max_time: int = 300) -> ToolResult:
        """Runs an external command safely, without shell=True."""
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                timeout=max_time,
                text=True,
                # A non-UTF8 byte in a tool's output (nikto/whatweb often echo
                # raw content from the scanned responses) must not take down the
                # entire execution with a UnicodeDecodeError.
                errors="replace",
            )

            return ToolResult(
                command=command,
                command_preview=shlex.join(command),
                returncode=completed.returncode,
                stdout=completed.stdout or "",
                stderr=completed.stderr or "",
                timed_out=False,
            )

        except subprocess.TimeoutExpired as exc:
            stdout = exc.stdout or ""
            stderr = exc.stderr or ""

            if isinstance(stdout, bytes):
                stdout = stdout.decode(errors="replace")
            if isinstance(stderr, bytes):
                stderr = stderr.decode(errors="replace")

            return ToolResult(
                command=command,
                command_preview=shlex.join(command),
                returncode=None,
                stdout=stdout,
                stderr=stderr,
                timed_out=True,
            )

        except OSError as exc:
            # Missing/non-executable binary (FileNotFoundError, PermissionError,
            # ...): previously this raised a raw exception that aborted the whole
            # module (see WebCrawler.run_nikto()). It is returned as a normal
            # failed result, just like a timeout, so the module can decide.
            return ToolResult(
                command=command,
                command_preview=shlex.join(command),
                returncode=None,
                stdout="",
                stderr=str(exc),
                timed_out=False,
            )

    @abstractmethod
    def run(self, *args, **kwargs) -> ToolResult:
        """Runs the tool. The concrete signature is defined by each adapter."""

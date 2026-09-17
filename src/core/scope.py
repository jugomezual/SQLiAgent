"""
scope.py - Per-host debugging guardrail.

If DEBUG_SCOPE_URL is defined in the environment, every target (IP, host or URL)
that reaches `assert_in_scope` must resolve to the same host, or it aborts with
OutOfDebugScope. Intended as a safety net so that a debug session against a
specific host does not touch anything outside it by mistake (mixed job/data,
IDs from another execution, etc.).

Without DEBUG_SCOPE_URL defined, `assert_in_scope` does nothing (normal
behavior, unrestricted).
"""

from __future__ import annotations

import os
from urllib.parse import urlparse

from dotenv import load_dotenv

from core.exceptions import OutOfDebugScope

load_dotenv()


def _host_of(target: str) -> str:
    target = (target or "").strip()
    if "://" in target:
        return (urlparse(target).hostname or "").lower()
    # Bare IP/hostname, or "host:port"
    return target.split(":")[0].split("/")[0].lower()


def debug_scope_host() -> str | None:
    """Host allowed by DEBUG_SCOPE_URL, or None if there is no restriction."""
    raw = os.getenv("DEBUG_SCOPE_URL", "").strip()
    return _host_of(raw) if raw else None


def assert_in_scope(target: str) -> None:
    """Abort with OutOfDebugScope if `target` does not belong to the DEBUG_SCOPE_URL host."""
    allowed = debug_scope_host()
    if not allowed:
        return
    if _host_of(target) != allowed:
        raise OutOfDebugScope(
            f"Out of debugging scope: '{target}' does not belong to "
            f"'{allowed}' (DEBUG_SCOPE_URL)"
        )

"""
console.py - Centralized console output.

In the current project, the `print("❌ ...")`, `print("✅ ...")`, `print("🔍 ...")`
calls and the `'='*80` banners are copied verbatim across the six modules.
Centralizing them here allows:
  - Changing the format (or silencing it in tests) in a single place.
  - Redirecting to `logging` down the road without touching the modules.

It is not a "textbook" pattern, but it removes real duplication and keeps the
modules focused on their logic.
"""

from __future__ import annotations

import shutil


class Console:
    """Printing helper. Instantiate it once per module (or share it)."""

    def __init__(self, *, quiet: bool = False):
        self.quiet = quiet

    def _print(self, text: str = "") -> None:
        if not self.quiet:
            print(text)

    # --- Level-based messages -----------------------------------------------

    def info(self, msg: str) -> None:
        self._print(f"🔍 {msg}")

    def ok(self, msg: str) -> None:
        self._print(f"✅ {msg}")

    def warn(self, msg: str) -> None:
        self._print(f"⚠️  {msg}")

    def error(self, msg: str) -> None:
        self._print(f"❌ {msg}")

    def step(self, msg: str) -> None:
        self._print(f"📊 {msg}")

    def plain(self, msg: str = "") -> None:
        self._print(msg)

    # --- Structure ----------------------------------------------------------

    def banner(self, title: str, char: str = "=") -> None:
        width = min(shutil.get_terminal_size((80, 20)).columns, 80)
        line = char * width
        self._print(f"\n{line}\n{title}\n{line}\n")

"""
exceptions.py - Domain exceptions of the pipeline.

`BaseModule.execute()` catches these exceptions in a centralized way and
converts them into a coherent `ModuleResult`.
"""

class ModuleError(Exception):
    """Base error of any pipeline module."""

class ToolNotAvailable(ModuleError):
    """The required external tool is not installed / not executable."""

class OutOfDebugScope(ModuleError):
    """The target is outside the host allowed by DEBUG_SCOPE_URL."""

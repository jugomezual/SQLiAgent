#!/usr/bin/env python3
"""Static page routes for the WebScanner UI (SQLiAgent, Tools, WebMap)."""

import re
import time
from pathlib import Path

from fastapi import APIRouter
from fastapi.responses import HTMLResponse

STATIC_DIR = Path(__file__).parent / "static"

router = APIRouter()


_NO_CACHE_HEADERS = {"Cache-Control": "no-cache"}

# Cache-busting stamp tied to process start: browsers that cached an asset
# under a *previous* run (before Cache-Control: no-cache existed on these
# responses) would otherwise keep serving it per their own stale heuristics
# until a hard refresh. Rewriting every /websqli/static/... reference to a
# ?v=<start time> URL makes each server restart mint genuinely new URLs, so
# stale disk-cache entries can never match regardless of browser behavior.
_ASSET_VERSION = str(int(time.time()))
_ASSET_REF_RE = re.compile(r'(href|src)="(/websqli/static/[^"]+)"')


def _serve(filename: str, fallback_title: str) -> HTMLResponse:
    path = STATIC_DIR / filename
    if not path.exists():
        return HTMLResponse(
            content=f"<h1>{fallback_title}</h1><p>{filename} not found</p>",
            status_code=404,
            headers=_NO_CACHE_HEADERS,
        )
    content = _ASSET_REF_RE.sub(rf'\1="\2?v={_ASSET_VERSION}"', path.read_text(encoding="utf-8"))
    return HTMLResponse(content=content, status_code=200, headers=_NO_CACHE_HEADERS)


@router.get("/", response_class=HTMLResponse)
async def root():
    """Serves the default page (SQLiAgent — the job-centric pipeline view)"""
    return _serve("index.html", "WebScanner")


@router.get("/tools", response_class=HTMLResponse)
async def tools_page():
    """Serves the Tools page"""
    return _serve("tool_pages/tools.html", "Tools")


@router.get("/webmap", response_class=HTMLResponse)
async def webmap_page():
    """Serves the WebMap page"""
    return _serve("tool_pages/webmap.html", "WebMap")


@router.get("/debug-gt", response_class=HTMLResponse)
async def debug_gt_page():
    """Serves the Debug GT page (ground-truth coverage check for a job)"""
    return _serve("debug_pages/debug_gt.html", "Debug GT")


@router.get("/debug-timeline", response_class=HTMLResponse)
async def debug_timeline_page():
    """Serves the Debug Timeline page (vulnerabilities found vs. job elapsed time)"""
    return _serve("debug_pages/debug_timeline.html", "Debug Timeline")

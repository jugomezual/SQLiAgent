#!/usr/bin/env python3
"""FastAPI entrypoint for WebScanner: wires the API and web routers together."""

import os

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

from restapi import router as api_router
from webroutes import router as web_router, STATIC_DIR

load_dotenv()


class NoCacheStaticFiles(StaticFiles):
    """Serves static files with Cache-Control: no-cache.

    The UI (HTML/CSS/JS) is still under active development; without this,
    browsers can serve a stale mix of files from their own cache without ever
    asking the server, since Starlette's default StaticFiles sends no
    Cache-Control header at all. `no-cache` still lets the browser cache the
    file, but forces it to revalidate via ETag/Last-Modified on every load -
    cheap (a 304 when unchanged), and guarantees changes are picked up
    immediately instead of requiring a hard refresh.
    """

    def file_response(self, *args, **kwargs):
        response = super().file_response(*args, **kwargs)
        response.headers["Cache-Control"] = "no-cache"
        return response


def _build_ui(with_cors: bool = True) -> FastAPI:
    """Builds the UI app: static mount + web/API routers (+ optional CORS)."""
    ui = FastAPI(title="WebScanner API", version="1.0.0")
    if with_cors:
        ui.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )
    ui.mount("/static", NoCacheStaticFiles(directory=str(STATIC_DIR)), name="static")
    ui.include_router(web_router)
    ui.include_router(api_router)
    return ui


# Served at the root ("/", "/static", "/api") — this is what the production
# reverse proxy forwards to after stripping the "/websqli" path prefix.
app = _build_ui()

# Local-dev convenience: the frontend references its assets/APIs under
# "/websqli/..." (the prefix the proxy adds in production). Expose the exact
# same UI under "/websqli" too, so the app is fully usable when opened
# directly at http://127.0.0.1:8000/websqli/ with no reverse proxy in front.
# Behind the production proxy this mount is simply never reached; CORS is
# already applied by the parent `app`, so the sub-app omits it.
app.mount("/websqli", _build_ui(with_cors=False))

if __name__ == "__main__":
    import uvicorn
    # Bind address is configurable via .env so the dashboard can be reached from
    # another machine. Default is loopback-only (127.0.0.1); set WEB_HOST=0.0.0.0
    # to listen on all interfaces for LAN/server access (the app has no auth, so
    # only expose it on a trusted network or behind a proxy/SSH tunnel).
    host = os.getenv("WEB_HOST", "127.0.0.1")
    port = int(os.getenv("WEB_PORT", "8000"))
    uvicorn.run(app, host=host, port=port, log_level="info")

#!/usr/bin/env python3
"""REST API for WebScanner: runs pipeline scripts and exposes DB status/reports."""

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse, FileResponse
from pydantic import BaseModel
from typing import Optional
import asyncio
import sys
import os
import uuid
import json
import requests
from pathlib import Path

# -- Python DB layer --
# .resolve() follows the Web/ symlink back to the real project root, so this
# works whether this file is loaded via /home/usuario/carpeta_oscar/Web or via
# whatever path Web/ is actually symlinked from in the deployment.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
_project_root = str(PROJECT_ROOT)
sys.path.insert(0, _project_root)
from db.database import DatabaseManager

router = APIRouter(prefix="/api")

# Global variable to store active processes
active_processes = {}

_SSE_HEADERS = {
    "Cache-Control": "no-cache",
    "Connection": "keep-alive",
    "X-Accel-Buffering": "no",
}


class ScanRequest(BaseModel):
    ip: str

class CrawlerRequest(BaseModel):
    url: str
    depth: Optional[int] = 3
    skip_nikto: Optional[bool] = False
    render: Optional[bool] = False

class DetectorRequest(BaseModel):
    mode: str  # 'url', 'webapp', or 'page'
    url: Optional[str] = None
    webapp_id: Optional[int] = None
    page_id: Optional[int] = None

class ExploiterRequest(BaseModel):
    sqli_id: int

class WebSQLIRequest(BaseModel):
    url: str
    mode: str = 'iterative'  # 'iterative' | 'ia'
    depth: Optional[int] = 4
    comment: Optional[str] = None

class DumpRequest(BaseModel):
    sqli_id: int
    db_name: str
    table_name: str
    job_id: Optional[int] = None

class ReporterRequest(BaseModel):
    job_id: int

class DBAnalyzerRequest(BaseModel):
    db_name: str
    job_id: Optional[int] = None

class DBCredentialHunterRequest(BaseModel):
    job_id: int

class DBAdminInyectorRequest(BaseModel):
    job_id: int

async def run_script(script_name: str, args: list, session_id: str = None):
    """Generic generator that runs a Python script and returns real-time output"""
    # Generate session_id if not provided
    if session_id is None:
        session_id = str(uuid.uuid4())

    # Send session_id to the client as the first message
    yield f"data: {{\"type\": \"session\", \"session_id\": \"{session_id}\"}}\n\n"

    # Path to the script (relative to the project root)
    script_path = PROJECT_ROOT / script_name

    if not script_path.exists():
        yield f"data: ERROR: {script_name} not found in {script_path}\n\n"
        return

    try:
        # Build command
        cmd = [sys.executable, str(script_path)] + args

        # Run the script with PYTHONUNBUFFERED for immediate output
        env = os.environ.copy()
        env['PYTHONUNBUFFERED'] = '1'

        # Run the script
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            env=env
        )

        # Register the process as active
        active_processes[session_id] = {
            'process': process,
            'script': script_name,
            'args': args
        }

        # Read output line by line
        while True:
            # Check if the process was cancelled
            if session_id not in active_processes:
                process.terminate()
                try:
                    await asyncio.wait_for(process.wait(), timeout=5)
                except asyncio.TimeoutError:
                    process.kill()
                    await process.wait()
                yield f"data: [CANCELLED] Execution stopped by the user\n\n"
                return

            line = await process.stdout.readline()
            if not line:
                break

            # Decode the line preserving format
            decoded_line = line.decode('utf-8', errors='replace')

            # Send as Server-Sent Event (already includes \n from readline)
            yield f"data: {decoded_line}\n\n"

        # Wait for the process to finish
        await process.wait()

        # Remove from active processes
        if session_id in active_processes:
            del active_processes[session_id]

        if process.returncode == 0:
            yield f"data: [DONE]\n\n"
        else:
            yield f"data: [ERROR] Process ended with code {process.returncode}\n\n"

    except Exception as e:
        # Clean up active process in case of error
        if session_id in active_processes:
            del active_processes[session_id]
        yield f"data: ERROR: {str(e)}\n\n"


@router.post("/scan")
async def scan_endpoint(request: ScanRequest):
    """Endpoint for WebScanner.py"""
    if not request.ip or not request.ip.strip():
        raise HTTPException(status_code=400, detail="IP address is required")

    ip = request.ip.strip()

    return StreamingResponse(
        run_script("modules/recon/WebScanner.py", [ip]),
        media_type="text/event-stream",
        headers=_SSE_HEADERS,
    )

@router.post("/crawler")
async def crawler_endpoint(request: CrawlerRequest):
    """Endpoint for WebCrawler.py"""
    if not request.url or not request.url.strip():
        raise HTTPException(status_code=400, detail="URL is required")

    url = request.url.strip()

    # Build arguments
    args = [url]

    if request.depth != 3:
        args.extend(['--depth', str(request.depth)])

    if request.skip_nikto:
        args.append('--skip-nikto')

    if request.render:
        args.append('--render')

    return StreamingResponse(
        run_script("modules/recon/WebCrawler.py", args),
        media_type="text/event-stream",
        headers=_SSE_HEADERS,
    )

@router.post("/detector")
async def detector_endpoint(request: DetectorRequest):
    """Endpoint for WebDetector.py"""
    # Validate mode and build arguments based on mode
    args = []

    if request.mode == 'url':
        if not request.url or not request.url.strip():
            raise HTTPException(status_code=400, detail="URL is required for URL mode")
        args = [request.url.strip()]

    elif request.mode == 'webapp':
        if request.webapp_id is None:
            raise HTTPException(status_code=400, detail="webapp_id is required for webapp mode")
        args = ['--web-app-id', str(request.webapp_id)]

    elif request.mode == 'page':
        if request.page_id is None:
            raise HTTPException(status_code=400, detail="page_id is required for page mode")
        args = ['--crawl-page-id', str(request.page_id)]

    else:
        raise HTTPException(status_code=400, detail="Invalid mode. Must be 'url', 'webapp', or 'page'")

    return StreamingResponse(
        run_script("modules/sqli/WebDetector.py", args),
        media_type="text/event-stream",
        headers=_SSE_HEADERS,
    )

@router.post("/exploiter")
async def exploiter_endpoint(request: ExploiterRequest):
    """Endpoint for SQLExploiter.py"""
    if request.sqli_id is None or request.sqli_id < 1:
        raise HTTPException(status_code=400, detail="sqli_id is required and must be a positive integer")

    # Build arguments
    args = ['--sqli-id', str(request.sqli_id)]

    return StreamingResponse(
        run_script("modules/sqli/SQLExploiter.py", args),
        media_type="text/event-stream",
        headers=_SSE_HEADERS,
    )

@router.post("/websqli/start")
async def websqli_start(request: WebSQLIRequest):
    """Starts WebScanner to create a webapp, which SQLiAgentOrchestrator will process"""
    if not request.url or not request.url.strip():
        raise HTTPException(status_code=400, detail="URL is required")

    url = request.url.strip()
    mode = (request.mode or 'iterative').strip().lower()

    args = [url]
    if mode == 'ia':
        args += ['--mode', 'IA']

    depth = request.depth if request.depth and request.depth > 0 else 4
    args += ['--depth', str(depth)]

    if request.comment and request.comment.strip():
        args += ['--comment', request.comment.strip()]

    # Run WebScanner to create the structure in the database
    return StreamingResponse(
        run_script("modules/recon/WebScanner.py", args),
        media_type="text/event-stream",
        headers=_SSE_HEADERS,
    )

@router.get("/websqli/status")
async def websqli_status(job_id: Optional[int] = None):
    """Gets the status of scanners, crawlers, detectors, exploiters and scorers, optionally filtered by job"""
    try:
        return DatabaseManager.get_websqli_status(job_id)
    except Exception as e:
        return {
            "scanners": [], "crawlers": [], "detectors": [], "exploiters": [], "scorers": [],
            "error": str(e)
        }

@router.get("/jobs")
async def get_jobs():
    """Returns all jobs ordered by most recent first"""
    try:
        return {'jobs': DatabaseManager.get_jobs()}
    except Exception as e:
        return {'jobs': [], 'error': str(e)}


@router.delete("/jobs/{job_id}")
async def delete_job(job_id: int):
    """Deletes a job and all associated data from every table"""
    try:
        DatabaseManager.delete_job(job_id)
        return {'deleted': job_id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/crawler/status")
async def crawler_status(job_id: Optional[int] = None):
    """Returns crawl_page and crawl_page_details, optionally filtered by job"""
    try:
        return DatabaseManager.get_crawler_status(job_id)
    except Exception as e:
        return {'pages': [], 'details': [], 'error': str(e)}


@router.get("/scanner/status")
async def scanner_status(job_id: Optional[int] = None):
    """Gets the current status of the scanner (jobs, hosts, webapps, nmap) from the database"""
    try:
        return DatabaseManager.get_scanner_status(job_id=job_id)
    except Exception as e:
        return {'jobs': [], 'hosts': [], 'webapps': [], 'nmap': [], 'error': str(e)}


@router.get("/exploiter/status")
async def exploiter_status(job_id: Optional[int] = None):
    """Returns sqli_exploit, sqli_exploit_tables, sqli_exploit_columns, optionally filtered by job"""
    try:
        return DatabaseManager.get_exploiter_status(job_id)
    except Exception as e:
        return {'exploits': [], 'tables': [], 'columns': [], 'error': str(e)}


@router.get("/detector/status")
async def detector_status(job_id: Optional[int] = None):
    """Returns sqli_detector entries, optionally filtered by job"""
    try:
        return DatabaseManager.get_detector_status(job_id)
    except Exception as e:
        return {'detections': [], 'error': str(e)}


_V2_LOG_GETTERS = {
    "scanner": DatabaseManager.get_host,
    "crawler": DatabaseManager.get_web_app,
    "detector": DatabaseManager.get_crawl_page,
    "scorer": DatabaseManager.get_crawl_page,
    "exploiter": DatabaseManager.get_sqli_exploit,
}


@router.get("/pipeline/log")
async def v2_log(stage: str, id: int):
    """Lazily fetches the full captured console log for a single V2 kanban
    card, keyed by the pipeline stage and the row id the module wrote it to.
    Kept out of /websqli/status (polled every few seconds) since a log can be
    tens of thousands of characters."""
    getter = _V2_LOG_GETTERS.get(stage)
    if not getter:
        raise HTTPException(status_code=400, detail=f"Unknown stage: {stage}")
    row = getter(id)
    if not row:
        raise HTTPException(status_code=404, detail="Not found")
    return {"log": row.get("log")}


@router.get("/dumper/status")
async def dumper_status(job_id: Optional[int] = None):
    """Returns sqli_exploit_data entries, optionally filtered by job"""
    try:
        status = DatabaseManager.get_dumper_status(job_id)
        return {'dumps': status.get('data', [])}
    except Exception as e:
        return {'dumps': [], 'error': str(e)}


@router.get("/obtain-data/databases")
async def obtain_data_databases(job_id: int = None):
    """Returns the list of available databases in sqli_exploit_tables"""
    try:
        return DatabaseManager.get_exploit_databases(job_id=job_id)
    except Exception as e:
        return {'databases': [], 'error': str(e)}


@router.get("/obtain-data/tables")
async def obtain_data_tables(db_name: str, job_id: int = None):
    """Returns the tables of a specific database from sqli_exploit_tables"""
    try:
        return DatabaseManager.get_exploit_tables_for_db(db_name, job_id=job_id)
    except Exception as e:
        return {'tables': [], 'error': str(e)}


@router.get("/obtain-data/result")
async def obtain_data_result(db_name: str, table_name: str, job_id: Optional[int] = None):
    """Returns the last stored data_json for a db+table, optionally filtered by job"""
    try:
        return DatabaseManager.get_obtain_data_result(db_name, table_name, job_id)
    except Exception as e:
        return {'data_json': None, 'error': str(e)}


@router.post("/dumper")
async def obtain_data_dump(request: DumpRequest):
    """Runs DBDumper.py --dump-db / --dump-table to obtain data from a table"""
    if not request.db_name or not request.table_name:
        raise HTTPException(status_code=400, detail="db_name and table_name are required")
    if request.sqli_id < 1:
        raise HTTPException(status_code=400, detail="sqli_id must be a positive integer")

    args = [
        '--sqli-id', str(request.sqli_id),
        '--dump-db', request.db_name,
        '--dump-table', request.table_name
    ]
    if request.job_id:
        args += ['--job-id', str(request.job_id)]

    return StreamingResponse(
        run_script("modules/sqli/DBDumper.py", args),
        media_type="text/event-stream",
        headers=_SSE_HEADERS,
    )


@router.get("/reporter/jobs")
async def reporter_jobs():
    """Returns all available jobs for generating reports"""
    try:
        jobs = DatabaseManager.get_jobs()
        for j in jobs:
            j['timestamp'] = str(j.get('timestamp', ''))
        return {"jobs": jobs}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/reporter")
async def reporter_generate(request: ReporterRequest):
    """Runs SQLWebReporter.py --id X and returns the name of the generated PDF"""
    script_path = PROJECT_ROOT / "modules" / "reports" / "SQLWebReporter.py"
    output_dir = PROJECT_ROOT / "modules" / "reports" / "output"

    if not script_path.exists():
        raise HTTPException(status_code=500, detail="SQLWebReporter.py not found")

    try:
        proc = await asyncio.create_subprocess_exec(
            sys.executable, str(script_path), "--id", str(request.job_id),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT
        )
        stdout, _ = await proc.communicate()
        output = stdout.decode(errors='replace')

        if proc.returncode != 0:
            raise HTTPException(status_code=500, detail=f"Error generating report: {output}")

        # Find the most recent PDF for this job_id
        pdfs = sorted(
            output_dir.glob(f"report_job{request.job_id}_*.pdf"),
            key=lambda p: p.stat().st_mtime,
            reverse=True
        )
        if not pdfs:
            raise HTTPException(status_code=500, detail="No generated PDF found")

        return {"filename": pdfs[0].name, "log": output.strip()}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/reporter/download")
async def reporter_download(filename: str):
    """Downloads a generated PDF report"""
    output_dir = (PROJECT_ROOT / "modules" / "reports" / "output").resolve()
    file_path = (output_dir / filename).resolve()

    # Prevent path traversal
    if not str(file_path).startswith(str(output_dir)):
        raise HTTPException(status_code=400, detail="Invalid filename")
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="File not found")
    return FileResponse(
        path=str(file_path),
        media_type="application/pdf",
        filename=filename,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )


@router.get("/reporter/csv")
async def reporter_csv(job_id: int):
    """Returns a CSV file with all crawled pages for a job (url, score, priority, result)."""
    try:
        import io, csv as _csv
        rows = DatabaseManager.get_report_pages(job_id)
        buf = io.StringIO()
        writer = _csv.writer(buf)
        writer.writerow(['host', 'webapp_url', 'page_url', 'priority_score', 'priority_level', 'status'])
        for r in rows:
            writer.writerow([
                r.get('target_host', ''),
                r.get('webapp_url', ''),
                r.get('page_url', ''),
                r.get('priority_score', ''),
                r.get('priority_level', ''),
                r.get('status', ''),
            ])
        csv_content = buf.getvalue()
        return StreamingResponse(
            iter([csv_content]),
            media_type='text/csv',
            headers={'Content-Disposition': f'attachment; filename="pages_job{job_id}.csv"'}
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/dbanalyzer/databases")
async def dbanalyzer_databases(job_id: int):
    """Returns the databases obtained in a specific job"""
    try:
        return DatabaseManager.get_dbanalyzer_databases(job_id)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/dbanalyzer")
async def dbanalyzer_analyse(request: DBAnalyzerRequest):
    """Runs DBSchemaAnalyzer.py --db X [--job N] and returns the AI output"""
    script_path = PROJECT_ROOT / "modules" / "sqli_ai_attack" / "DBSchemaAnalyzer.py"
    if not script_path.exists():
        raise HTTPException(status_code=500, detail="DBSchemaAnalyzer.py not found")

    try:
        args = [sys.executable, str(script_path), "--db", request.db_name]
        if request.job_id:
            args += ["--job", str(request.job_id)]
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT
        )
        stdout, _ = await proc.communicate()
        output = stdout.decode(errors='replace')

        if proc.returncode != 0:
            raise HTTPException(status_code=500, detail=f"Error in analysis: {output}")

        import re as _re
        result_json = None
        match = _re.search(r'---\s*RESULT\s*---\s*([\s\S]*?)(?:={10,}|$)', output)
        if match:
            try:
                result_json = json.loads(match.group(1).strip())
            except Exception:
                result_json = None

        return {"output": output.strip(), "result": result_json}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/dbcredentialhunter")
async def dbcredentialhunter_run(request: DBCredentialHunterRequest):
    """Runs DBCredentialHunter.py --job N and returns the AI output"""
    script_path = PROJECT_ROOT / "modules" / "sqli_ai_attack" / "DBCredentialHunter.py"
    if not script_path.exists():
        raise HTTPException(status_code=500, detail="DBCredentialHunter.py not found")
    try:
        proc = await asyncio.create_subprocess_exec(
            sys.executable, str(script_path), "--job", str(request.job_id),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT
        )
        stdout, _ = await proc.communicate()
        output = stdout.decode(errors='replace')
        if proc.returncode != 0:
            raise HTTPException(status_code=500, detail=f"Error: {output}")
        return {"output": output.strip()}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/dbadmininyector")
async def dbadmininyector_run(request: DBAdminInyectorRequest):
    """Runs DBAdminInyector.py --job N and returns the AI output"""
    script_path = PROJECT_ROOT / "modules" / "sqli_ai_attack" / "DBAdminInyector.py"
    if not script_path.exists():
        raise HTTPException(status_code=500, detail="DBAdminInyector.py not found")
    try:
        proc = await asyncio.create_subprocess_exec(
            sys.executable, str(script_path), "--job", str(request.job_id),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT
        )
        stdout, _ = await proc.communicate()
        output = stdout.decode(errors='replace')
        if proc.returncode != 0:
            raise HTTPException(status_code=500, detail=f"Error: {output}")
        return {"output": output.strip()}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/cancel/{session_id}")
async def cancel_execution(session_id: str):
    """Cancels an active execution"""
    if session_id not in active_processes:
        raise HTTPException(status_code=404, detail="No active execution found with that ID")

    # Remove from the dictionary (the loop in run_script will detect this and terminate the process)
    process_info = active_processes.pop(session_id)

    return {
        "status": "cancelled",
        "session_id": session_id,
        "script": process_info['script']
    }

@router.get("/stats")
async def get_stats(job_id: Optional[int] = None):
    """Returns statistics per job, optionally filtered to a single job_id."""
    try:
        return DatabaseManager.get_stats(job_id)
    except Exception as e:
        return {'stats': [], 'error': str(e)}


@router.get("/webmap")
async def webmap(job_id: Optional[int] = None):
    """Returns pages grouped for the WebMap tree visualization."""
    try:
        return DatabaseManager.get_webmap(job_id)
    except Exception as e:
        return {'pages': [], 'error': str(e)}


@router.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "ok", "service": "WebScanner API"}


@router.get("/config")
async def get_config():
    """Frontend-facing config values sourced from .env (New Job modal's
    default target URL, etc.), so they're changed in one place instead of
    being hardcoded into the JS."""
    return {"default_target_url": os.getenv("DEFAULT_TARGET_URL", "")}


# Static reference data for the Debug GT page - a fixed external baseline
# (ZAP) and the ground-truth URL list itself, neither tied to any job or our
# own pipeline, so they live as JSON files rather than in the DB.
DEBUG_DATA_DIR = Path(__file__).resolve().parent / "static" / "debug_pages" / "debug_data"


def _load_debug_json(filename: str, fallback: dict) -> dict:
    try:
        with open(DEBUG_DATA_DIR / filename, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"⚠️  Could not read debug_pages/debug_data/{filename}: {exc}")
        return fallback


@router.get("/debug-gt/zap")
async def debug_gt_zap():
    """Static ZAP baseline for Debug GT: which ground-truth URLs OWASP ZAP
    detected in a prior, independent scan of the same target."""
    return _load_debug_json("zap_detected.json", {"detected_urls": []})


@router.get("/debug-gt/urls")
async def debug_gt_urls():
    """The Debug GT ground-truth URL list itself (app + url, some with a
    `note`), served from disk so it's edited in one place instead of being
    hardcoded into the frontend."""
    return _load_debug_json("GT_URLS.json", {"gt_pages": []})


@router.get("/debug-gt/vuln-timeline")
async def debug_gt_vuln_timeline(job_ids: str):
    """Cumulative vulnerabilities-found-over-elapsed-time series, one per
    job, for the Debug Timeline chart. `job_ids` is a comma-separated list.
    """
    try:
        ids = [int(x) for x in job_ids.split(",") if x.strip()]
    except ValueError:
        raise HTTPException(status_code=400, detail="job_ids must be a comma-separated list of integers")
    return {"series": DatabaseManager.get_vulnerability_timeline(ids)}


def _probe_target(url: str) -> dict:
    """One quick, short-timeout GET — run off the event loop via
    asyncio.to_thread since `requests` is blocking."""
    try:
        r = requests.get(url, timeout=5, verify=False, allow_redirects=True)
        return {"ok": True, "status_code": r.status_code}
    except requests.exceptions.RequestException as exc:
        return {"ok": False, "error": type(exc).__name__}


@router.get("/debug-gt/target-health")
async def debug_gt_target_health():
    """Reachability check for the Debug GT benchmark target (the OWASP-BWA
    VM). A crawl against a saturated/hung target (e.g. Apache worker pool
    exhausted by requests stuck on a full-disk MySQL) produces a wall of
    'Not Found' rows and fetch errors that look like crawler/detector bugs
    but aren't — this lets the UI tell the two apart and point at the real
    cause instead. Checks two independent paths (root + a lightweight,
    non-DB-backed app) and only calls it "saturated" if *both* fail: one
    broken app shouldn't be reported as the whole VM being down.
    """
    base = (os.getenv("DEBUG_SCOPE_URL") or os.getenv("DEFAULT_TARGET_URL") or "http://10.0.0.12").rstrip("/")
    checks = {"root": base + "/", "vicnum": base + "/vicnum/"}
    results = dict(zip(
        checks.keys(),
        await asyncio.gather(*(asyncio.to_thread(_probe_target, url) for url in checks.values()))
    ))
    saturated = all(not r["ok"] for r in results.values())
    return {"saturated": saturated, "target": base, "checks": results}


@router.get("/sqli-agent-orchestrator/status")
async def sqli_agent_orchestrator_status():
    """Reports whether SQLiAgentOrchestrator.py is currently running as a process.

    SQLiAgentOrchestrator.py isn't a networked service, so this shells out to pgrep
    rather than pinging it - it's the only signal the web UI has that new
    jobs will actually get picked up and processed.
    """
    try:
        proc = await asyncio.create_subprocess_exec(
            "pgrep", "-f", "SQLiAgentOrchestrator.py",
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        returncode = await proc.wait()
        return {"running": returncode == 0}
    except Exception as e:
        return {"running": False, "error": str(e)}

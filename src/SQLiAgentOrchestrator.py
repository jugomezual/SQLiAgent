#!/usr/bin/env python3
"""
SQLiAgentOrchestrator.py - Automatic monitoring and analysis system.

Dispatch is driven by MySQL binlog events (CDC), not by polling the database
for pending work: a background thread tails host_web_app / crawl_page /
sqli_detector via replication and drops newly-pending rows into in-memory
queues; the main loop only drains those queues and does local process
bookkeeping (checking subprocess.poll(), which is unavoidably local since
child processes aren't observable from the database).

The binlog stream is a single point of failure: if the listener thread ever
dies (dropped connection, MySQL restart, ...) it logs and exits, and without
a safety net the main loop would keep running forever without ever seeing
new pending work again. To bound that failure window, a periodic
reconciliation poll (see `reconcile_interval`) independently re-queries the
DB for pending items and merges anything missing into the queues - the same
thing the old poll-only SQLiAgentOrchestrator did every tick, just at a coarser cadence
so it doesn't defeat the point of moving to CDC.

Requires: `pip install mysql-replication`, MySQL/MariaDB with
binlog_format=ROW and log_bin enabled, and a DB user with REPLICATION SLAVE /
REPLICATION CLIENT privileges (in addition to normal DML access).
"""

import sys
import socket
import subprocess
import re
import tempfile
import threading
import time
import os
from collections import deque
from datetime import datetime
from db.database import DatabaseManager

# Max characters of a crashed subprocess's captured output kept as error_message.
_ERROR_LOG_MAX_CHARS = 4000

# WebCrawler catches per-page fetch/parse/save failures internally and just
# print()s them so a handful of bad URLs don't abort an otherwise-successful
# crawl (see modules/recon/WebCrawler.py fetch_page/crawl/_save_page_to_db).
# That means the subprocess exits 0 and host_web_app.state never reflects
# these — the only trace is these lines in the captured log. Count them so a
# "successful" crawl with partial failures still shows a warning in the UI
# instead of a bare "done".
_CRAWL_WARNING_MARKERS = (
    "Error fetching page",
    "Error processing page:",
    "Timeout after 30 seconds",
    "Error saving to database:",
    "Error accessing robots.txt",
    "Database error:",
)

# Matches WebCrawler's "[N] Analyzing (depth D): <url>" line printed right
# before it works on that page, so a warning line found afterward (which
# never repeats the URL itself) can still be attributed to a specific page.
_CRAWL_URL_RE = re.compile(r"Analyzing \(depth \d+\): (\S+)")


def _summarize_crawl_warnings(output: str, max_samples: int = 8) -> tuple[int, list[str]]:
    """Counts per-page warning lines in a crawl's captured output and returns
    a handful of concrete "<url>: <reason>" samples alongside the count — a
    bare count ("158 page(s) had errors") gives no way to investigate; this
    does, without having to dig through the (tail-truncated) persisted log."""
    count = 0
    samples: list[str] = []
    current_url = None
    for line in output.splitlines():
        if m := _CRAWL_URL_RE.search(line):
            current_url = m.group(1)
            continue
        marker = next((mk for mk in _CRAWL_WARNING_MARKERS if mk in line), None)
        if not marker:
            continue
        count += 1
        if len(samples) < max_samples:
            reason = line.strip()
            samples.append(f"{current_url}: {reason}" if current_url else reason)
    return count, samples


def _open_subprocess_log(prefix: str):
    """Backs a subprocess's stdout/stderr with a temp file instead of a pipe,
    so a chatty child (nmap/sqlmap/crawler output) can never deadlock waiting
    on a full pipe buffer between our poll() calls."""
    return tempfile.NamedTemporaryFile(mode="w", delete=False, prefix=prefix, suffix=".log")


def _read_full_subprocess_log(path: str) -> str:
    """Reads a completed subprocess's full (untruncated) captured output and removes the temp file."""
    content = ""
    try:
        with open(path, "r", errors="replace") as f:
            content = f.read().strip()
    except OSError:
        pass
    finally:
        try:
            os.remove(path)
        except OSError:
            pass
    return content


def _truncate_tail(content: str) -> str:
    if len(content) > _ERROR_LOG_MAX_CHARS:
        content = content[-_ERROR_LOG_MAX_CHARS:]
    return content or "(sin salida capturada)"


def _read_and_discard_subprocess_log(path: str) -> str:
    """Reads the tail of a crashed subprocess's captured output and removes the temp file."""
    return _truncate_tail(_read_full_subprocess_log(path))

# ============================================================================
# ORCHESTRATOR CLASS
# ============================================================================

class SQLiAgentOrchestrator:
    """Monitors the database and automatically launches agents based on pending tasks."""

    def __init__(self, web_app_id=None, interval=3, max_concurrent=5, monitor_all=False,
                 reconcile_interval=30):
        self.web_app_id = web_app_id
        self.interval = interval  # Seconds between each check
        self.max_concurrent = max_concurrent  # Maximum concurrent processes
        self.monitor_all = monitor_all  # If True, monitors host_web_app
        self.reconcile_interval = reconcile_interval  # Seconds between DB reconciliation polls
        self._last_reconcile = 0.0
        # Tracking for pages (WebDetector)
        self.processed_pages = set()  # IDs of pages already processed
        self.running_detector_processes = {}  # {crawl_page_id: process_info}
        self.detector_completed_count = 0
        self.detector_launched_count = 0

        # Tracking for web apps (WebCrawler)
        self.processed_webapps = set()  # IDs of web apps already processed
        self.running_crawler_processes = {}  # {web_app_id: process_info}
        self.crawler_completed_count = 0
        self.crawler_launched_count = 0

        # Tracking for exploiter (SQLExploiter)
        self.running_exploiter_processes = {}  # {sqli_id: process_info}
        self.exploiter_completed_count = 0
        self.exploiter_launched_count = 0

        # Tracking for scorer (WebScorer)
        self.running_scorer_processes = {}  # {crawl_page_id: process_info}
        self.scorer_completed_count = 0
        self.scorer_launched_count = 0
        self.scorer_pages_dispatched = 0  # total pages sent across all batches

        # Initial maximum IDs - to detect only NEW entries
        self.initial_max_webapp_id = None  # Maximum ID of host_web_app at start
        self.initial_max_page_ids = {}  # {web_app_id: max_crawl_page_id} at start

        self.script_dir = os.path.dirname(os.path.abspath(__file__))
        self.detector_script = os.path.join(self.script_dir, 'modules/sqli/WebDetector.py')
        self.crawler_script = os.path.join(self.script_dir, 'modules/recon/WebCrawler.py')
        self.exploiter_script = os.path.join(self.script_dir, 'modules/sqli/SQLExploiter.py')
        self.scorer_script = os.path.join(self.script_dir, 'modules/scoring/WebScorer.py')
        self.web_app_script = os.path.join(self.script_dir, 'Web/app.py')

        # Tracking for the web dashboard (Web/app.py)
        self.web_app_process = None

        self._job_depth_cache = {}

        # --- Event-driven dispatch state (fed by the binlog listener thread) ---
        self._pending_lock = threading.Lock()
        self._pending_web_apps = deque()      # host_web_app rows that became 'pending'
        self._pending_crawl_pages = []        # crawl_page rows that became 'pending' (re-sorted by priority each tick)
        self._pending_score_pages = deque()   # crawl_page rows that became 'pending_score'
        self._pending_sqli = []               # sqli_detector rows that became vulnerable+pending

        # De-dupe guard for the narrow startup window between fixing the binlog
        # position and running the one-time backfill query (see initialize()):
        # a row inserted in that gap could otherwise be reported by both.
        self._startup_seen = {
            'web_app': set(),
            'crawl_page': set(),
            'score_page': set(),
            'sqli_vulnerable': set(),
        }

        self._binlog_stream = None
        self._binlog_thread = None
        self._stop_event = threading.Event()

    def get_job_depth(self, job_id: int) -> int:
        """Returns the crawl depth configured for a job (default 4 if not found)."""
        if job_id in self._job_depth_cache:
            return self._job_depth_cache[job_id]

        depth = 4
        job = DatabaseManager.get_job(job_id)
        if job and isinstance(job, (dict, list)):
            row = job[0] if isinstance(job, list) else job
            depth = int(row.get('depth') or 4)

        self._job_depth_cache[job_id] = depth
        return depth

    # ------------------------------------------------------------------
    # Binlog listener: turns MySQL row-change events into in-memory work
    # ------------------------------------------------------------------

    @staticmethod
    def _binlog_connection_settings():
        return {
            "host": os.getenv("DB_HOST", "localhost"),
            "port": int(os.getenv("DB_PORT", "3306")),
            "user": os.getenv("DB_USER"),
            "passwd": os.getenv("DB_PASSWORD", ""),
        }

    def _create_binlog_stream(self):
        """Attaches to the MySQL binlog. Must be called before initialize()'s
        backfill so the stream's starting position is fixed first - otherwise
        a row that becomes pending between the backfill query and stream
        attachment could be missed entirely."""
        try:
            from pymysqlreplication import BinLogStreamReader
            from pymysqlreplication.row_event import WriteRowsEvent, UpdateRowsEvent
        except ImportError:
            print("❌ Missing dependency: pip install mysql-replication", flush=True)
            sys.exit(1)

        db_name = os.getenv("DB_NAME", "sqli_tfg")
        server_id = int(os.getenv("BINLOG_SERVER_ID", "424242"))

        try:
            return BinLogStreamReader(
                connection_settings=self._binlog_connection_settings(),
                server_id=server_id,
                only_schemas=[db_name],
                only_tables=["host_web_app", "crawl_page", "sqli_detector"],
                only_events=[WriteRowsEvent, UpdateRowsEvent],
                blocking=True,
                resume_stream=True,
            )
        except Exception as exc:
            print(f"❌ Could not attach to the MySQL binlog: {exc}", flush=True)
            print("   Make sure binlog_format=ROW, log_bin is enabled, and the DB", flush=True)
            print("   user has REPLICATION SLAVE / REPLICATION CLIENT privileges.", flush=True)
            sys.exit(1)

    @staticmethod
    def _classify_host_web_app(before, after):
        if after.get('state') == 'pending' and (before is None or before.get('state') != 'pending'):
            return [('web_app', after)]
        return []

    @staticmethod
    def _classify_crawl_page(before, after):
        state = after.get('state')
        prev_state = before.get('state') if before else None
        if state == 'pending' and prev_state != 'pending':
            return [('crawl_page', after)]
        if state == 'pending_score' and prev_state != 'pending_score':
            return [('score_page', after)]
        return []

    @staticmethod
    def _classify_sqli_detector(before, after):
        if after.get('is_vulnerable') in (1, True) and after.get('state') == 'pending':
            prev_state = before.get('state') if before else None
            prev_vuln = before.get('is_vulnerable') if before else None
            if before is None or prev_state != 'pending' or prev_vuln not in (1, True):
                return [('sqli_vulnerable', after)]
        return []

    def _enqueue(self, queue_type, row):
        row_id = row['id']
        with self._pending_lock:
            startup_ids = self._startup_seen.get(queue_type)
            if startup_ids is not None and row_id in startup_ids:
                # Already picked up by the one-time startup backfill; drop
                # this duplicate but stop filtering future events for this id.
                startup_ids.discard(row_id)
                return
            if queue_type == 'web_app':
                self._pending_web_apps.append(row)
            elif queue_type == 'crawl_page':
                self._pending_crawl_pages.append(row)
            elif queue_type == 'score_page':
                self._pending_score_pages.append(row)
            elif queue_type == 'sqli_vulnerable':
                self._pending_sqli.append(row)

    def _run_binlog_listener(self):
        """Runs in a background thread; blocks on the binlog stream and
        classifies each row event, with no interval-based DB polling."""
        classifiers = {
            'host_web_app': self._classify_host_web_app,
            'crawl_page': self._classify_crawl_page,
            'sqli_detector': self._classify_sqli_detector,
        }
        try:
            for event in self._binlog_stream:
                if self._stop_event.is_set():
                    break
                classify = classifiers.get(event.table)
                if classify is None:
                    continue
                for row in event.rows:
                    if 'values' in row:
                        before, after = None, row['values']
                    else:
                        before, after = row.get('before_values'), row.get('after_values')
                    if after is None:
                        continue
                    for queue_type, payload in classify(before, after):
                        self._enqueue(queue_type, payload)
        except Exception as exc:
            if not self._stop_event.is_set():
                print(f"❌ Binlog listener crashed: {exc}", flush=True)

    def _shutdown_binlog_stream(self):
        # close() alone doesn't reliably interrupt a recv() blocked in the
        # listener thread; shutdown() first forces it to return immediately.
        stream = self._binlog_stream
        if stream is None:
            return
        for attr in ('_stream_connection', '_ctl_connection'):
            sock = getattr(getattr(stream, attr, None), '_sock', None)
            if sock is not None:
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
        stream.close()

    def launch_web_app(self):
        """Launches Web/app.py (the FastAPI dashboard) once, alongside the rest
        of the pipeline, so the web UI is available without a separate manual
        start."""
        if not os.path.exists(self.web_app_script):
            print(f"  ⚠️  Web/app.py not found at {self.web_app_script}, skipping dashboard launch", flush=True)
            return False
        try:
            process = subprocess.Popen(
                [sys.executable, self.web_app_script],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True
            )
            self.web_app_process = process
            print(f"  🌐 Launch Web/app.py", flush=True)
            print(f"     • PID: {process.pid}", flush=True)
            self._print_web_urls()
            return True
        except Exception as e:
            print(f"  ❌ Error launching Web/app.py: {e}", flush=True)
            return False

    # Path prefix the frontend/routes are served under (see the /websqli mount
    # in Web/app.py). The bind host/port come from WEB_HOST / WEB_PORT in .env
    # (read by Web/app.py); defaults are 127.0.0.1:8000.
    WEB_PREFIX = "/websqli"

    @staticmethod
    def _display_host():
        """Host to show in the printed URLs. WEB_HOST is the *bind* address; when
        it's a wildcard (0.0.0.0 / ::) that isn't a usable URL, so show the
        machine's primary LAN IP instead so the links are actually clickable."""
        host = os.getenv("WEB_HOST", "127.0.0.1").strip()
        if host in ("", "0.0.0.0", "::", "[::]", "*"):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))   # no traffic sent; just picks the outbound interface
                ip = s.getsockname()[0]
                s.close()
                return ip
            except Exception:
                try:
                    return socket.gethostbyname(socket.gethostname())
                except Exception:
                    return "127.0.0.1"
        return host

    def _print_web_urls(self):
        """Prints every browser-facing URL of the dashboard, so the user can
        open any page directly from the launch output."""
        host = self._display_host()
        port = int(os.getenv("WEB_PORT", "8000"))
        base = f"http://{host}:{port}{self.WEB_PREFIX}"
        pages = [
            ("Dashboard (SQLiAnalyzed)", "/"),
            ("WebMap",                   "/webmap"),
            ("Tools",                    "/tools"),
            ("Debug GT",                 "/debug-gt"),
            ("Debug Timeline",           "/debug-timeline"),
            ("API docs (Swagger)",       "/docs"),
            ("Health check",             "/api/health"),
        ]
        width = max(len(name) for name, _ in pages)
        print(f"     • Web URLs:", flush=True)
        for name, path in pages:
            print(f"         - {name.ljust(width)}  {base}{path}", flush=True)

    def launch_crawler(self, web_app_id, base_url):
        """Launches an instance of WebCrawler.py for a pending web app"""
        try:
            # Update state to 'running'
            DatabaseManager.update_web_app_state(web_app_id, 'running')

            depth = 4
            webapp = DatabaseManager.get_web_app(web_app_id)
            if webapp:
                row = webapp[0] if isinstance(webapp, list) else webapp
                host_id = row.get('host_id')
                if host_id:
                    host = DatabaseManager.get_host(host_id)
                    if host:
                        host_row = host[0] if isinstance(host, list) else host
                        job_id = host_row.get('jobs_id') or host_row.get('job_id')
                        if job_id:
                            depth = self.get_job_depth(job_id)

            cmd = [
                sys.executable, self.crawler_script,
                base_url,
                '--web-app-id', str(web_app_id),
                '--depth', str(depth),
            ]

            log_file = _open_subprocess_log("ad_crawler_")
            process = subprocess.Popen(
                cmd,
                stdout=log_file,
                stderr=subprocess.STDOUT,
                start_new_session=True
            )
            log_file.close()

            self.running_crawler_processes[web_app_id] = {
                'process': process,
                'pid': process.pid,
                'url': base_url,
                'started_at': datetime.now(),
                'log_path': log_file.name,
            }

            self.crawler_launched_count += 1

            print(f"  🌐 Launch WebCrawler.py", flush=True)
            print(f"     • PID: {process.pid}", flush=True)
            print(f"     • web_app_id: {web_app_id}", flush=True)
            print(f"     • URL: {base_url}", flush=True)
            print(f"     • Depth: {depth} (unlimited pages within scope)", flush=True)

            return True

        except Exception as e:
            print(f"  ❌ Error launching WebCrawler.py: {e}", flush=True)
            # Set back to pending if it fails
            DatabaseManager.update_web_app_state(web_app_id, 'pending')
            return False

    def launch_detector(self, crawl_page_id, page_url, reason):
        """Launches an instance of WebDetector.py for a pending page"""
        try:
            # Update state to 'running'
            DatabaseManager.update_crawl_page_state(crawl_page_id, 'running')

            log_file = _open_subprocess_log("ad_detector_")
            process = subprocess.Popen(
                [sys.executable, self.detector_script, '--crawl-page-id', str(crawl_page_id)],
                stdout=log_file,
                stderr=subprocess.STDOUT,
                start_new_session=True
            )
            log_file.close()

            self.running_detector_processes[crawl_page_id] = {
                'process': process,
                'pid': process.pid,
                'url': page_url,
                'reason': reason,
                'started_at': datetime.now(),
                'log_path': log_file.name,
            }

            self.detector_launched_count += 1

            print(f"  🚀 Launch WebDetector.py", flush=True)
            print(f"     • PID: {process.pid}", flush=True)
            print(f"     • crawl_page_id: {crawl_page_id}", flush=True)
            print(f"     • Reason: {reason}", flush=True)

            return True

        except Exception as e:
            print(f"  ❌ Error launching WebDetector.py: {e}", flush=True)
            # Sets pending again to allow reprocessing if it fails
            DatabaseManager.update_crawl_page_state(crawl_page_id, 'pending')
            return False

    def launch_exploiter(self, sqli_id, target_url):
        """Launches an instance of SQLExploiter.py for a detected vulnerability"""
        try:
            log_file = _open_subprocess_log("ad_exploiter_")
            process = subprocess.Popen(
                [sys.executable, self.exploiter_script, '--sqli-id', str(sqli_id), '--auto'],
                stdout=log_file,
                stderr=subprocess.STDOUT,
                start_new_session=True
            )
            log_file.close()

            self.running_exploiter_processes[sqli_id] = {
                'process': process,
                'pid': process.pid,
                'url': target_url,
                'started_at': datetime.now(),
                'log_path': log_file.name,
            }

            self.exploiter_launched_count += 1

            print(f"  💥 Launch SQLExploiter.py", flush=True)
            print(f"     • PID: {process.pid}", flush=True)
            print(f"     • sqli_id: {sqli_id}", flush=True)
            print(f"     • URL: {target_url}", flush=True)

            return True

        except Exception as e:
            print(f"  ❌ Error launching SQLExploiter.py: {e}", flush=True)
            return False

    def launch_scorer_batch(self, pages):
        """
        Launches ONE WebScorer.py process for a batch of pages (up to 50).
        pages: list of dicts with 'id' and 'url'.
        Dict key in running_scorer_processes is the first page's id.
        """
        if not pages:
            return False
        page_ids = [p['id'] for p in pages]
        ids_str = ','.join(str(i) for i in page_ids)
        try:
            for p in pages:
                DatabaseManager.update_crawl_page_state(p['id'], 'running_score')

            log_file = _open_subprocess_log("ad_scorer_")
            process = subprocess.Popen(
                [sys.executable, self.scorer_script, '--crawl-page-ids', ids_str],
                stdout=log_file,
                stderr=subprocess.STDOUT,
                start_new_session=True
            )
            log_file.close()

            batch_key = page_ids[0]
            self.running_scorer_processes[batch_key] = {
                'process': process,
                'pid': process.pid,
                'page_ids': page_ids,
                'started_at': datetime.now(),
                'log_path': log_file.name,
            }

            self.scorer_launched_count += 1

            print(f"  🏅 Launch WebScorer.py (batch {len(page_ids)} pages)", flush=True)
            print(f"     • PID: {process.pid}", flush=True)
            print(f"     • page_ids: {ids_str}", flush=True)

            return True

        except Exception as e:
            print(f"  ❌ Error launching WebScorer.py batch: {e}", flush=True)
            for page_id in page_ids:
                DatabaseManager.update_crawl_page_state(page_id, 'pending_score')
            return False

    def check_completed_processes(self):
        """Verifies which processes have completed and cleans up the lists"""

        # Verify WebCrawler processes
        for web_app_id, proc_info in list(self.running_crawler_processes.items()):
            poll_result = proc_info['process'].poll()

            if poll_result is not None:
                duration = (datetime.now() - proc_info['started_at']).total_seconds()
                # Full (untruncated) text: a tail-truncated 4000-char window can miss
                # early per-page warnings on a long crawl and undercount them.
                full_output = _read_full_subprocess_log(proc_info['log_path'])

                print(f"\n✅ WebCrawler completed:", flush=True)
                print(f"   • web_app_id: {web_app_id}", flush=True)
                print(f"   • PID: {proc_info['pid']}", flush=True)
                print(f"   • Duration: {duration:.1f}s", flush=True)
                print(f"   • Exit code: {poll_result}", flush=True)

                # Update state to 'done' if it finished successfully
                if poll_result == 0:
                    warning_count, warning_samples = _summarize_crawl_warnings(full_output)
                    note = None
                    if warning_count:
                        examples = "; ".join(warning_samples)
                        note = f"{warning_count} page(s) had fetch/parse errors during the crawl. Examples: {examples}"
                        print(f"   ⚠️  Crawler done with {warning_count} page-level warning(s)", flush=True)
                    DatabaseManager.update_web_app_state(web_app_id, 'done', error_message=note)
                else:
                    output = _truncate_tail(full_output)
                    print(f"   ⚠️  Crawler failed, storing error: {output[:200]}", flush=True)
                    DatabaseManager.update_web_app_state(web_app_id, 'error', error_message=output)
                    DatabaseManager.update_web_app_log(web_app_id, output)

                self.crawler_completed_count += 1
                del self.running_crawler_processes[web_app_id]

        # Verify WebDetector processes
        for crawl_page_id, proc_info in list(self.running_detector_processes.items()):
            poll_result = proc_info['process'].poll()

            if poll_result is not None:
                duration = (datetime.now() - proc_info['started_at']).total_seconds()
                output = _read_and_discard_subprocess_log(proc_info['log_path'])

                print(f"\n✅ WebDetector completed:", flush=True)
                print(f"   • crawl_page_id: {crawl_page_id}", flush=True)
                print(f"   • PID: {proc_info['pid']}", flush=True)
                print(f"   • Duration: {duration:.1f}s", flush=True)
                print(f"   • Exit code: {poll_result}", flush=True)

                # WebDetector already updates the state to 'done' when it finishes
                # Only update if it failed - but check first if sqli_detector records
                # were already created (means the page was actually scanned)
                if poll_result != 0:
                    existing = DatabaseManager.get_sqli_by_crawl_page(crawl_page_id) or []
                    if existing:
                        print(f"   ⚠️  Exit code {poll_result} but {len(existing)} sqli_detector record(s) exist → marking done", flush=True)
                        DatabaseManager.update_crawl_page_state(crawl_page_id, 'done')
                    else:
                        print(f"   ⚠️  Exit code {poll_result}, no sqli_detector records → marking error: {output[:200]}", flush=True)
                        DatabaseManager.update_crawl_page_state(crawl_page_id, 'error', error_message=output)
                        DatabaseManager.update_crawl_page_log(crawl_page_id, output)

                self.detector_completed_count += 1
                del self.running_detector_processes[crawl_page_id]

        # Verify SQLExploiter processes
        for sqli_id, proc_info in list(self.running_exploiter_processes.items()):
            poll_result = proc_info['process'].poll()

            if poll_result is not None:
                duration = (datetime.now() - proc_info['started_at']).total_seconds()
                output = _read_and_discard_subprocess_log(proc_info['log_path'])

                print(f"\n✅ SQLExploiter completed:", flush=True)
                print(f"   • sqli_id: {sqli_id}", flush=True)
                print(f"   • PID: {proc_info['pid']}", flush=True)
                print(f"   • Duration: {duration:.1f}s", flush=True)
                print(f"   • Exit code: {poll_result}", flush=True)

                # SQLExploiter persists its own error via ModuleBase.on_failure when it
                # can. This is the backstop for a process that died before that ran
                # (killed, OOM) and left no record, or left one stuck at 'running'.
                if poll_result != 0:
                    state_info = DatabaseManager.get_exploit_state(sqli_id)
                    if not state_info:
                        print(f"   ⚠️  Exit code {poll_result}, no sqli_exploit record → marking error: {output[:200]}", flush=True)
                        new_exploit_id = DatabaseManager.insert_sqli_exploit(sqli_id, None, 0, state="error", error_message=output)
                        if new_exploit_id:
                            DatabaseManager.update_sqli_exploit_log(new_exploit_id, output)
                    elif state_info.get("state") == "running":
                        print(f"   ⚠️  Exit code {poll_result}, exploit stuck running → marking error: {output[:200]}", flush=True)
                        DatabaseManager.update_sqli_exploit_state(state_info["exploit_id"], "error", error_message=output)
                        DatabaseManager.update_sqli_exploit_log(state_info["exploit_id"], output)

                self.exploiter_completed_count += 1
                del self.running_exploiter_processes[sqli_id]

        # Verify WebScorer processes (batch)
        for batch_key, proc_info in list(self.running_scorer_processes.items()):
            poll_result = proc_info['process'].poll()

            if poll_result is not None:
                duration = (datetime.now() - proc_info['started_at']).total_seconds()
                page_ids = proc_info.get('page_ids', [batch_key])
                output = _read_and_discard_subprocess_log(proc_info['log_path'])

                print(f"\n✅ WebScorer batch completed:", flush=True)
                print(f"   • page_ids: {page_ids}", flush=True)
                print(f"   • PID: {proc_info['pid']}", flush=True)
                print(f"   • Duration: {duration:.1f}s", flush=True)
                print(f"   • Exit code: {poll_result}", flush=True)

                # If the whole batch process died (crash/kill), mark every page in it
                # as error instead of silently retrying forever. Per-page scoring
                # failures are already retried individually inside WebScorer itself.
                if poll_result != 0:
                    print(f"   ⚠️  Exit code {poll_result}, batch crashed → marking {len(page_ids)} page(s) error: {output[:200]}", flush=True)
                    for page_id in page_ids:
                        DatabaseManager.update_crawl_page_state(page_id, 'error', error_message=output)
                        DatabaseManager.update_crawl_page_log(page_id, output)

                self.scorer_completed_count += 1
                del self.running_scorer_processes[batch_key]

    def initialize(self):
        """One-time backfill: seeds the in-memory queues with work that was
        already pending before the binlog listener attached. Must run AFTER
        _create_binlog_stream() fixed the stream's starting position, so the
        union of (this backfill) + (binlog events from that position onward)
        covers everything without gaps."""
        print("🔧 Backfilling work that was already pending...", flush=True)

        if self.monitor_all:
            for row in DatabaseManager.get_pending_web_apps() or []:
                self._pending_web_apps.append(row)
                self._startup_seen['web_app'].add(row['id'])

        for row in DatabaseManager.get_pending_crawl_pages() or []:
            self._pending_crawl_pages.append(row)
            self._startup_seen['crawl_page'].add(row['id'])

        for row in DatabaseManager.get_pending_score_pages() or []:
            self._pending_score_pages.append(row)
            self._startup_seen['score_page'].add(row['id'])

        for row in DatabaseManager.get_pending_vulnerable_sqli() or []:
            self._pending_sqli.append(row)
            self._startup_seen['sqli_vulnerable'].add(row['id'])

        self._last_reconcile = time.monotonic()

        if self.monitor_all:
            print(f"   • Web apps in queue: {len(self._pending_web_apps)}", flush=True)
        print(f"   • Pages in queue: {len(self._pending_crawl_pages)}", flush=True)
        print(f"   • Pages to score: {len(self._pending_score_pages)}", flush=True)
        print(f"   • Vulnerabilities in queue: {len(self._pending_sqli)}", flush=True)

        print(f"✅ System ready. Listening for database changes...\n", flush=True)

    def _reconcile_with_db(self):
        """Periodic safety net: re-query the DB directly for pending work and
        merge in anything the binlog listener might have missed - most
        importantly, everything if the listener thread has silently died.
        Runs independently of dispatch capacity (max_concurrent); it only
        tops up the queues, process_pending_* still enforces the limit and
        already skips anything currently running.
        """
        with self._pending_lock:
            queued_webapp_ids = {r['id'] for r in self._pending_web_apps}
            queued_page_ids = {r['id'] for r in self._pending_crawl_pages}
            queued_score_ids = {r['id'] for r in self._pending_score_pages}
            queued_sqli_ids = {r['id'] for r in self._pending_sqli}

        running_score_ids = {
            pid for info in self.running_scorer_processes.values()
            for pid in info.get('page_ids', [])
        }

        added = 0

        if self.monitor_all:
            for row in DatabaseManager.get_pending_web_apps() or []:
                if row['id'] in queued_webapp_ids or row['id'] in self.running_crawler_processes:
                    continue
                with self._pending_lock:
                    self._pending_web_apps.append(row)
                added += 1

        for row in DatabaseManager.get_pending_crawl_pages() or []:
            if row['id'] in queued_page_ids or row['id'] in self.running_detector_processes:
                continue
            with self._pending_lock:
                self._pending_crawl_pages.append(row)
            added += 1

        for row in DatabaseManager.get_pending_score_pages() or []:
            if row['id'] in queued_score_ids or row['id'] in running_score_ids:
                continue
            with self._pending_lock:
                self._pending_score_pages.append(row)
            added += 1

        for row in DatabaseManager.get_pending_vulnerable_sqli() or []:
            if row['id'] in queued_sqli_ids or row['id'] in self.running_exploiter_processes:
                continue
            with self._pending_lock:
                self._pending_sqli.append(row)
            added += 1

        if added:
            print(f"🔄 Reconciliation: {added} pending item(s) picked up from the DB "
                  f"(missed by the binlog stream, or the listener had stalled)", flush=True)

    def monitor(self):
        """Main event loop.

        Dispatch is event-driven (see _run_binlog_listener); this loop only
        drains the in-memory queues it fills and does local process
        bookkeeping (subprocess.poll(), job-completion aggregate checks) -
        it does not poll the database for pending work.
        """
        print(f"\n{'='*80}")
        if self.monitor_all:
            print(f"🌐 ORCHESTRATOR - Global Monitor Mode")
        else:
            print(f"🔍 ORCHESTRATOR - Specific Web App Mode")
        print(f"{'='*80}")
        print(f"📊 Configuration:")
        if self.monitor_all:
            print(f"   • Monitoring: ALL web apps")
        else:
            print(f"   • Web App ID: {self.web_app_id}")
        print(f"   • Dispatch tick: {self.interval}s (local process bookkeeping only, no DB polling)", flush=True)
        print(f"   • Maximum concurrent: {self.max_concurrent}")
        print(f"   • WebDetector script: {self.detector_script}")
        if self.monitor_all:
            print(f"   • WebCrawler script: {self.crawler_script}")
        print(f"{'='*80}\n")

        if self.monitor_all and not os.path.exists(self.crawler_script):
            print(f"❌ Error: {self.crawler_script} not found")
            sys.exit(1)
        if not os.path.exists(self.detector_script):
            print(f"❌ Error: {self.detector_script} not found")
            sys.exit(1)

        self.launch_web_app()

        # Fix the binlog starting position BEFORE the backfill query (see
        # initialize()'s docstring for why the ordering matters).
        print("🔌 Attaching to MySQL binlog...", flush=True)
        self._binlog_stream = self._create_binlog_stream()
        print("✅ Attached.", flush=True)

        self.initialize()

        self._binlog_thread = threading.Thread(target=self._run_binlog_listener, daemon=True)
        self._binlog_thread.start()

        print("🔄 Listening for database changes... (Ctrl+C to stop)\n", flush=True)

        try:
            iteration = 0
            while True:
                iteration += 1

                # Verify completed processes
                self.check_completed_processes()

                # PHASE 1: Dispatch web apps that became pending (launch crawlers)
                if self.monitor_all:
                    self.process_pending_web_apps()

                # PHASE 2: Dispatch pages that became pending_score (launch scorers)
                self.process_pending_score_pages()

                # PHASE 3: Dispatch crawled pages that became pending (launch detectors)
                self.process_pending_crawl_pages()

                # PHASE 4: Dispatch detected vulnerabilities (launch exploiters)
                self.process_vulnerable_sqli()

                # PHASE 5: Mark jobs as done when all pipeline work is complete
                self.check_completed_jobs()

                # Periodic safety net: re-query the DB directly in case the
                # binlog listener missed something or has died silently.
                if time.monotonic() - self._last_reconcile >= self.reconcile_interval:
                    self._reconcile_with_db()
                    self._last_reconcile = time.monotonic()

                # Show status every 10 iterations
                if iteration % 10 == 0:
                    self.print_status(iteration)

                # Local tick only - not a database poll.
                time.sleep(self.interval)

        except KeyboardInterrupt:
            print(f"\n\n{'='*80}")
            print(f"🛑 Monitoring stopped by user")
            print(f"{'='*80}")

            self._stop_event.set()
            self._shutdown_binlog_stream()
            if self._binlog_thread:
                self._binlog_thread.join(timeout=5)

            # Show final summary
            print(f"\n📊 FINAL SUMMARY:")

            if self.monitor_all:
                print(f"   • Web Apps processed: {len(self.processed_webapps)}")
                print(f"   • Crawlers launched: {self.crawler_launched_count}")
                print(f"   • Crawlers completed: {self.crawler_completed_count}")
                print(f"   • Crawlers running: {len(self.running_crawler_processes)}")

            print(f"   • Pages processed: {len(self.processed_pages)}")
            print(f"   • Detectors launched: {self.detector_launched_count}")
            print(f"   • Detectors completed: {self.detector_completed_count}")
            print(f"   • Detectors running: {len(self.running_detector_processes)}")

            print(f"   • Pages scored: {self.scorer_pages_dispatched}")
            print(f"   • Scorers launched: {self.scorer_launched_count}")
            print(f"   • Scorers completed: {self.scorer_completed_count}")
            print(f"   • Scorers running: {len(self.running_scorer_processes)}")

            print(f"   • Exploiters launched: {self.exploiter_launched_count}")
            print(f"   • Exploiters completed: {self.exploiter_completed_count}")
            print(f"   • Exploiters running: {len(self.running_exploiter_processes)}")

            if self.running_crawler_processes:
                print(f"\n⚠️  WebCrawler.py processes still running:")
                for wid, pinfo in self.running_crawler_processes.items():
                    print(f"   • PID {pinfo['pid']}: web_app_id={wid}")

            if self.running_detector_processes:
                print(f"\n⚠️  WebDetector.py processes still running:")
                for cpid, pinfo in self.running_detector_processes.items():
                    print(f"   • PID {pinfo['pid']}: crawl_page_id={cpid}")

            if self.running_exploiter_processes:
                print(f"\n⚠️  SQLExploiter.py processes still running:")
                for sqli_id, pinfo in self.running_exploiter_processes.items():
                    print(f"   • PID {pinfo['pid']}: sqli_id={sqli_id}")

            if self.running_scorer_processes:
                print(f"\n⚠️  WebScorer.py processes still running:")
                for bkey, pinfo in self.running_scorer_processes.items():
                    ids = pinfo.get('page_ids', [bkey])
                    print(f"   • PID {pinfo['pid']}: {len(ids)} pages {ids}")

            if self.running_detector_processes or self.running_exploiter_processes or self.running_scorer_processes:
                print(f"\n   The processes will continue running in the background.")

            if self.web_app_process and self.web_app_process.poll() is None:
                print(f"\n🌐 Web/app.py dashboard still running (PID {self.web_app_process.pid})")

            print(f"\n{'='*80}\n")
            sys.exit(0)

    def process_pending_web_apps(self):
        """Drain host_web_app rows that became pending, as reported by the
        binlog listener. On launch failure, launch_crawler reverts the row to
        'pending', which the listener observes as a fresh event and re-queues
        automatically - no explicit retry bookkeeping needed here.
        """
        while True:
            with self._pending_lock:
                if not self._pending_web_apps:
                    return
                total_processes = len(self.running_crawler_processes) + len(self.running_detector_processes)
                if total_processes >= self.max_concurrent:
                    return
                row = self._pending_web_apps.popleft()

            web_app_id = row['id']

            if web_app_id in self.running_crawler_processes:
                continue

            base_url = row.get('target_url') or ''
            if not base_url:
                print(f"⚠️  Web app {web_app_id} does not have a target_url, skipping...", flush=True)
                continue

            print(f"\n{'='*80}", flush=True)
            print(f"🎯 Processing pending Web App:", flush=True)
            print(f"   • ID: {web_app_id}", flush=True)
            print(f"   • URL: {base_url}", flush=True)
            print(f"{'='*80}", flush=True)

            self.launch_crawler(web_app_id, base_url)

    def process_pending_crawl_pages(self):
        """Drain crawl_page rows that became pending, as reported by the
        binlog listener. AI pages (with priority_level) are ordered:
        high → medium → low. Normal pages (without priority_level) go last.
        """
        _order = {'high': 0, 'medium': 1, 'low': 2}
        while True:
            with self._pending_lock:
                if not self._pending_crawl_pages:
                    return
                total_processes = len(self.running_crawler_processes) + len(self.running_detector_processes)
                if total_processes >= self.max_concurrent:
                    return
                self._pending_crawl_pages.sort(key=lambda p: (
                    _order.get(p.get('priority_level'), 3),
                    -(p.get('priority_score') or 0)
                ))
                page = self._pending_crawl_pages.pop(0)

            crawl_page_id = page['id']
            page_url = page['url']

            # Skip if already running (double check)
            if crawl_page_id in self.running_detector_processes:
                continue

            reason = "SQLi Analysis"
            priority_label = page.get('priority_level')

            print(f"\n{'='*80}", flush=True)
            print(f"🎯 Processing pending page:", flush=True)
            print(f"   • crawl_page_id: {crawl_page_id}", flush=True)
            print(f"   • URL: {page_url}", flush=True)
            if priority_label:
                print(f"   • priority_level: {priority_label}", flush=True)
                print(f"   • priority_score: {page.get('priority_score', 'N/A')}", flush=True)
            print(f"{'='*80}", flush=True)

            self.launch_detector(crawl_page_id, page_url, reason)

    def process_pending_score_pages(self):
        """Drain up to 20 crawl_page rows that became pending_score, launching
        one WebScorer batch. Only one scorer runs at a time (GPU constraint).
        A failed launch reverts the pages to pending_score, which the binlog
        listener observes as fresh events and re-queues for a later retry.
        """
        if self.running_scorer_processes:
            return

        total_processes = (len(self.running_crawler_processes) +
                           len(self.running_detector_processes) +
                           len(self.running_scorer_processes))
        if total_processes >= self.max_concurrent:
            return

        with self._pending_lock:
            if not self._pending_score_pages:
                return
            batch_rows = [self._pending_score_pages.popleft()
                          for _ in range(min(20, len(self._pending_score_pages)))]

        batch = [{'id': r['id'], 'url': r['url']} for r in batch_rows]

        print(f"\n{'='*80}", flush=True)
        print(f"🏅 Launching WebScorer batch: {len(batch)} pages", flush=True)
        for p in batch:
            print(f"   • id={p['id']} url={p['url']}", flush=True)
        print(f"{'='*80}", flush=True)

        self.scorer_pages_dispatched += len(batch)
        self.launch_scorer_batch(batch)

    def process_vulnerable_sqli(self):
        """Drain sqli_detector rows that became vulnerable+pending, launching
        SQLExploiter one at a time. Priority order: UNION query / error-based
        → boolean-based / time-based → others.

        Unlike the other dispatch paths, SQLExploiter never flips
        sqli_detector.state to 'running' before starting, so there's no state
        round-trip for the binlog listener to observe on failure - a failed
        launch is put back on the in-memory queue explicitly instead.
        """
        if self.running_exploiter_processes:
            return

        total_processes = (len(self.running_crawler_processes) +
                           len(self.running_detector_processes) +
                           len(self.running_exploiter_processes))
        if total_processes >= self.max_concurrent:
            return

        import json as _json

        # Sort by injection type priority:
        #   0 → UNION query or error-based  (fast, reliable)
        #   1 → boolean-based or time-based (slow)
        #   2 → anything else / unknown
        def _injection_priority(vuln):
            raw = vuln.get('injection_types_json') or '[]'
            try:
                types = _json.loads(raw) if isinstance(raw, str) else (raw or [])
            except Exception:
                types = []
            types_lower = [t.lower() for t in types]
            if any('union' in t or 'error' in t for t in types_lower):
                return 0
            if any('boolean' in t or 'time' in t for t in types_lower):
                return 1
            return 2

        with self._pending_lock:
            if not self._pending_sqli:
                return
            self._pending_sqli.sort(key=_injection_priority)
            vuln = self._pending_sqli.pop(0)

        sqli_id = vuln['id']
        target_url = vuln['target_url']

        # If the only injection type is time-based, check whether the target
        # job's DB schema was already dumped via a faster technique.  If so,
        # there is nothing new to gain: mark this record as done and move on.
        raw = vuln.get('injection_types_json') or '[]'
        try:
            itypes = _json.loads(raw) if isinstance(raw, str) else (raw or [])
        except Exception:
            itypes = []
        itypes_lower = [t.lower() for t in itypes]
        only_time_based = bool(itypes_lower) and all('time' in t for t in itypes_lower)
        if only_time_based and DatabaseManager.check_db_already_exploited(sqli_id):
            print(f"\n⏭️  Skipping sqli_id={sqli_id} (time-based only): DB already dumped for this job.", flush=True)
            DatabaseManager.update_sqli_detector_state(sqli_id, 'done')
            return

        print(f"\n{'='*80}", flush=True)
        print(f"💥 Processing pending SQLi vulnerability:", flush=True)
        print(f"   • sqli_id: {sqli_id}", flush=True)
        print(f"   • URL: {target_url}", flush=True)
        print(f"{'='*80}", flush=True)

        if self.launch_exploiter(sqli_id, target_url):
            print(f"   ℹ️  SQLExploiter launched for sqli_id={sqli_id}.", flush=True)
        else:
            with self._pending_lock:
                self._pending_sqli.append(vuln)

    def check_completed_jobs(self):
        """Marks jobs as 'done' when all their associated pipeline work is complete"""
        try:
            running_jobs = DatabaseManager.get_running_jobs()

            for job in running_jobs:
                job_id = job['id']

                # get_pending_work_count() includes the host itself (pending/running),
                # so a scan that's still running is correctly kept out of this branch;
                # once it's not pending, an all-done job with zero web apps found
                # (e.g. no open ports, or nothing returned HTTP 200) is legitimately
                # finished too, not "too early to tell" — don't require webapps > 0.
                if DatabaseManager.get_pending_work_count(job_id) > 0:
                    continue

                # Don't mark done if there are still active subprocesses for this job
                if self.running_crawler_processes or self.running_detector_processes or \
                        self.running_exploiter_processes or self.running_scorer_processes:
                    continue

                DatabaseManager.finish_job(job_id, 'done')
                print(f"\n✅ Job {job_id} fully completed — marked as 'done'.", flush=True)

        except Exception as e:
            print(f"⚠️  Error checking completed jobs: {e}", flush=True)

    def get_all_webapp_ids(self):
        """Gets the IDs of all web apps (for monitor-all mode)"""
        web_apps = DatabaseManager.get_web_apps()
        if not web_apps:
            return []
        return [wa['id'] for wa in web_apps]


    def print_status(self, iteration):
        """Prints the current monitoring status"""
        total_crawler = len(self.running_crawler_processes)
        total_detector = len(self.running_detector_processes)
        total_exploiter = len(self.running_exploiter_processes)

        # Backlog sizes come from the in-memory queues the binlog listener
        # fills, not from re-scanning host_web_app/crawl_page/sqli_detector.
        with self._pending_lock:
            pending_webapps_count = len(self._pending_web_apps)
            pending_pages_count = len(self._pending_crawl_pages)
            pending_score_count = len(self._pending_score_pages)
            vulnerable_count = len(self._pending_sqli)

        print(f"\n📊 Status (iter {iteration}):", flush=True)

        if self.monitor_all:
            print(f"   • Web Apps Queue: {pending_webapps_count} pending", flush=True)
            print(f"   • Active Crawlers: {total_crawler}", flush=True)
            print(f"   • Completed Crawlers: {self.crawler_completed_count}", flush=True)
            print(f"   • Total Crawlers Launched: {self.crawler_launched_count}", flush=True)

        print(f"   • Pages Queue: {pending_pages_count} pending", flush=True)
        print(f"   • Active Detectors: {total_detector}", flush=True)
        print(f"   • Completed Detectors: {self.detector_completed_count}", flush=True)
        print(f"   • Total Detectors Launched: {self.detector_launched_count}", flush=True)

        total_scorer = len(self.running_scorer_processes)

        print(f"   • Scorer Queue: {pending_score_count} pending", flush=True)
        print(f"   • Active Scorers: {total_scorer}", flush=True)
        print(f"   • Completed Scorers: {self.scorer_completed_count}", flush=True)
        print(f"   • Total Scorers Launched: {self.scorer_launched_count}", flush=True)

        print(f"   • Vulnerabilities Queue: {vulnerable_count} pending", flush=True)
        print(f"   • Active Exploiters: {total_exploiter}", flush=True)
        print(f"   • Completed Exploiters: {self.exploiter_completed_count}", flush=True)
        print(f"   • Total Exploiters Launched: {self.exploiter_launched_count}", flush=True)

        if self.running_crawler_processes:
            print(f"\n   🌐 WebCrawlers executing:", flush=True)
            for wid, pinfo in self.running_crawler_processes.items():
                elapsed = (datetime.now() - pinfo['started_at']).total_seconds()
                print(f"      • PID {pinfo['pid']}: webapp={wid}, {elapsed:.0f}s, {pinfo['url']}", flush=True)

        if self.running_detector_processes:
            print(f"\n   🔍 WebDetectors executing:", flush=True)
            for cpid, pinfo in self.running_detector_processes.items():
                elapsed = (datetime.now() - pinfo['started_at']).total_seconds()
                print(f"      • PID {pinfo['pid']}: page={cpid}, {elapsed:.0f}s", flush=True)

        if self.running_exploiter_processes:
            print(f"\n   💥 SQLExploiters executing:", flush=True)
            for sqli_id, pinfo in self.running_exploiter_processes.items():
                elapsed = (datetime.now() - pinfo['started_at']).total_seconds()
                print(f"      • PID {pinfo['pid']}: sqli={sqli_id}, {elapsed:.0f}s", flush=True)

        if self.running_scorer_processes:
            print(f"\n   🏅 WebScorers executing:", flush=True)
            for bkey, pinfo in self.running_scorer_processes.items():
                elapsed = (datetime.now() - pinfo['started_at']).total_seconds()
                ids = pinfo.get('page_ids', [bkey])
                print(f"      • PID {pinfo['pid']}: {len(ids)} pages {ids}, {elapsed:.0f}s", flush=True)
        print()

        print(f"   • Active Crawlers: {total_crawler}")
        print(f"   • Completed Crawlers: {self.crawler_completed_count}")
        print(f"   • Total Crawlers Launched: {self.crawler_launched_count}")

        print(f"   • Pages Processed: {len(self.processed_pages)}")
        print(f"   • Active Detectors: {total_detector}")
        print(f"   • Completed Detectors: {self.detector_completed_count}")
        print(f"   • Total Detectors Launched: {self.detector_launched_count}")

        if self.running_crawler_processes:
            print(f"\n   🌐 WebCrawlers executing:")
            for wid, pinfo in self.running_crawler_processes.items():
                elapsed = (datetime.now() - pinfo['started_at']).total_seconds()
                print(f"      • PID {pinfo['pid']}: webapp={wid}, {elapsed:.0f}s, {pinfo['url']}")

        if self.running_detector_processes:
            print(f"\n   🔍 WebDetectors executing:")
            for cpid, pinfo in self.running_detector_processes.items():
                elapsed = (datetime.now() - pinfo['started_at']).total_seconds()
                print(f"      • PID {pinfo['pid']}: page={cpid}, {elapsed:.0f}s")
        print()

# ============================================================================
# MAIN
# ============================================================================

def main():
    # Show help if explicitly requested
    if '--help' in sys.argv or '-h' in sys.argv:
        print("Uso:")
        print("  python3 SQLiAgentOrchestrator.py [--interval S] [--max-concurrent N] [--reconcile-interval S]")
        print("  python3 SQLiAgentOrchestrator.py --web-app-id <ID> [--interval S] [--max-concurrent N]\n")
        print("Options:")
        print("  --web-app-id ID          ID of host_web_app to monitor (specific mode)")
        print("  --interval SECONDS       Seconds between checks (default: 3)")
        print("  --max-concurrent N       Maximum concurrent processes (default: 5)")
        print("  --reconcile-interval S   Seconds between DB reconciliation polls, a safety")
        print("                           net in case the binlog listener misses/loses events")
        print("                           (default: 30)")
        print("")
        print("Examples:")
        print("  python3 SQLiAgentOrchestrator.py")
        print("  python3 SQLiAgentOrchestrator.py --interval 10")
        print("  python3 SQLiAgentOrchestrator.py --web-app-id 5")
        print("  python3 SQLiAgentOrchestrator.py --web-app-id 5 --interval 5 --max-concurrent 3")
        sys.exit(0)

    # Parse mode - monitor_all by default
    web_app_id = None
    monitor_all = True

    # If --web-app-id is specified, switch to specific mode
    if '--web-app-id' in sys.argv:
        monitor_all = False
        try:
            webapp_idx = sys.argv.index('--web-app-id')
            web_app_id = int(sys.argv[webapp_idx + 1])
        except (IndexError, ValueError):
            print("❌ Invalid value for --web-app-id")
            sys.exit(1)

    # Parse interval
    interval = 3
    if '--interval' in sys.argv:
        try:
            interval_idx = sys.argv.index('--interval')
            interval = int(sys.argv[interval_idx + 1])
        except (IndexError, ValueError):
            print("❌ Invalid value for --interval")
            sys.exit(1)

    # Parse max_concurrent
    max_concurrent = 5
    if '--max-concurrent' in sys.argv:
        try:
            concurrent_idx = sys.argv.index('--max-concurrent')
            max_concurrent = int(sys.argv[concurrent_idx + 1])
        except (IndexError, ValueError):
            print("❌ Invalid value for --max-concurrent")
            sys.exit(1)

    # Parse reconcile_interval
    reconcile_interval = 30
    if '--reconcile-interval' in sys.argv:
        try:
            reconcile_idx = sys.argv.index('--reconcile-interval')
            reconcile_interval = int(sys.argv[reconcile_idx + 1])
        except (IndexError, ValueError):
            print("❌ Invalid value for --reconcile-interval")
            sys.exit(1)

    # Create and run auto-detector
    detector = SQLiAgentOrchestrator(
        web_app_id=web_app_id,
        interval=interval,
        max_concurrent=max_concurrent,
        monitor_all=monitor_all,
        reconcile_interval=reconcile_interval,
    )
    detector.monitor()

if __name__ == "__main__":
    main()

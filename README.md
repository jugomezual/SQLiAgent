# SQLiAgent

SQLiAgent is a SQL-injection pentesting system with a web UI: it scans a target,
crawls it, prioritizes what's worth attacking, detects and exploits SQL
injection with `sqlmap`, optionally uses an LLM to go deeper once inside the
database, and produces a report — all tracked in a MySQL/MariaDB database. A
background daemon automates crawling → scoring → detection → exploitation
after a scan; the UI also runs individual modules, table dumps, AI-assisted
analysis and reports.

AI prompts in the post-exploitation modules have been removed to prevent potential offensive or malicious misuse of SQLiAgent.

## Installation and first use

**Requirements:** Linux/WSL2 with Bash (the code uses Linux paths and process
commands); Python 3.10+ with `pip`/`venv`; MariaDB (schema uses the
`utf8mb4_uca1400_ai_ci` collation — MySQL works but needs the dump's collation
adapted); `nmap`, `whatweb`, `nikto`, `sqlmap` on `PATH`; Chromium for
Playwright if the crawler needs JS rendering; an LLM service for AI features
(not needed for local scoring).

### 1. Dependencies

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip mariadb-server mariadb-client nmap whatweb nikto sqlmap
python3 -m venv .venv && source .venv/bin/activate
python -m pip install -r requirements.txt
python -m playwright install --with-deps chromium   # only if JS rendering is needed
command -v nmap whatweb nikto sqlmap                 # confirm tools are found
sudo install -d -o "$(id -un)" -g "$(id -gn)" -m 0750 /var/lib/sqlmap_output
```

### 2. Database

For the automatic pipeline, enable binlog in MariaDB's `[mysqld]` section
(e.g. `/etc/mysql/mariadb.conf.d/50-server.cnf`), then restart:

```ini
[mysqld]
server_id=1
log_bin=mysql-bin
binlog_format=ROW
binlog_row_image=FULL
```

```sql
CREATE DATABASE sqli_tfg CHARACTER SET utf8mb4 COLLATE utf8mb4_uca1400_ai_ci;
CREATE USER 'sqliagent'@'localhost' IDENTIFIED BY 'REPLACE_WITH_YOUR_PASSWORD';
GRANT SELECT, INSERT, UPDATE, DELETE ON sqli_tfg.* TO 'sqliagent'@'localhost';
GRANT REPLICATION SLAVE, REPLICATION CLIENT ON *.* TO 'sqliagent'@'localhost';
```

Import the schema (fresh DB — the file has `DROP TABLE IF EXISTS`):

```bash
sudo mariadb sqli_tfg < src/db/sqli_tfg.sql
```

Manual UI operation needs the database but not the binlog/replication grants.

### 3. Configure `.env` (repository root)

```dotenv
DB_DRIVER=mysql+pymysql
DB_HOST=localhost
DB_PORT=3306
DB_NAME=sqli_tfg
DB_USER=sqliagent
DB_PASSWORD=REPLACE_WITH_YOUR_PASSWORD
BINLOG_SERVER_ID=424242          # replication client ID; unique per client
DEFAULT_TARGET_URL=http://192.0.2.10   # optional: pre-fills New Job modal
DEBUG_SCOPE_URL=http://192.0.2.10      # optional hostname check at assert_in_scope sites
CRAWLER_MAX_URL_PATTERN_VARIANTS=5
CRAWLER_MAX_REDIRECT_HOPS=10
CRAWLER_LEGACY_TLS=true

# Web server bind. 127.0.0.1 = local only; use 0.0.0.0 for LAN/server access
WEB_HOST=127.0.0.1
WEB_PORT=8000

# AI / LLM (only for AI features; not needed for local scoring)
IA_MODELO=gemma3:12b
IA_LLAMA_API_URL=http://10.0.1.4:11434/api/generate
IA_API_KEY=
IA_LLAMA_API_KEY=
```

Set the `DB_*` vars even if using `DATABASE_URL`: the binlog client reads them
directly.

For AI features, configure the LLM through the `IA_*` variables (read by
`src/ai/ai.py`). The backend is selected automatically from the values:

| Variable | Meaning |
|---|---|
| `IA_MODELO` | Model name; its prefix/port selects the backend (e.g. `gemma3:12b`, `gemini-2.5-flash`, `deepseek-r1:14b`) |
| `IA_LLAMA_API_URL` | Ollama endpoint on `:11434` (e.g. `http://host:11434/api/generate`) or OpenWebUI on `:8080` (`.../api/chat/completions`) |
| `IA_API_KEY` | Gemini API key — used only when `IA_MODELO` starts with `gemini` |
| `IA_LLAMA_API_KEY` | OpenWebUI bearer token — used only for the `:8080` endpoint |

A `gemini-*` model uses Gemini; otherwise the URL port decides (`:11434`
Ollama, `:8080` OpenWebUI). Set only what your chosen backend needs.

### 4. Run

```bash
source .venv/bin/activate
export PYTHONPATH="$PWD/src${PYTHONPATH:+:$PYTHONPATH}"
python src/SQLiAgentOrchestrator.py
```

The orchestrator starts the web app and dispatches pending work. Open the
dashboard at <http://127.0.0.1:8000/websqli/> (the `/websqli` mount serves the
frontend's path prefix without a reverse proxy). API docs at `/docs`; health
check at `GET /api/health` (API only, not DB/tools).

For the manual Tools workflow only, run `python src/Web/app.py` instead — but
never both on the same port (the orchestrator already launches the web app).
Starting a pipeline job without the daemon runs the scanner, but its automatic
stages won't advance. Dumps, AI post-exploitation and reports are always
manual. Reports are written under `src/modules/reports/output/`, LLM logs under
`src/ia_logs/`.

### Run as a service (server, boot-persistent)

`deploy/sqli.initd` is an LSB init script that runs the orchestrator
(`SQLiAgentOrchestrator.py --monitor-all`, which also launches the web app) in
the background and logs to `sqli-service.log`. Edit `APPDIR` and `RUN_USER` at
the top of both files for your install.

**Install / update (one command).** `deploy/install-service.sh` installs the
init script to `/etc/init.d/sqli`, enables it on boot, stops any previous or
duplicate orchestrator, frees the web port, starts the service and prints a
verification summary:

```bash
sudo bash "deploy/install-service.sh"
```

Or do it by hand:

```bash
sudo cp deploy/sqli.initd /etc/init.d/sqli
sudo chmod +x /etc/init.d/sqli
sudo systemctl daemon-reload
sudo systemctl enable --now sqli.service     # start now + on boot
```

**Manage it** (always via systemd once installed — not the init script
directly, or you can end up with duplicate orchestrators):

```bash
sudo systemctl {start|stop|restart|status} sqli
tail -f "<APPDIR>/sqli-service.log"          # live orchestrator/web-app log
```

Notes:
- `RUN_USER` must own and be able to traverse `APPDIR`. A home directory
  (`/home/<user>`, usually `drwxr-x---`) is **not** traversable by `www-data`,
  so run the service as the owning user, not `www-data`.
- Only one process can hold `WEB_PORT`. Stop any manually-started web app or
  extra orchestrator first (`sudo pkill -f SQLiAgentOrchestrator; sudo fuser -k
  8000/tcp`), or the orchestrator's web app won't bind — `install-service.sh`
  does this for you.
- For remote access, set `WEB_HOST=0.0.0.0` in `.env` and open the port
  (`sudo ufw allow 8000/tcp`); otherwise reach it via an SSH tunnel. The server
  speaks plain HTTP — browse `http://<host>:<port>/websqli/` (not `https://`).

### Web URLs

The web server binds `WEB_HOST:WEB_PORT` (default `127.0.0.1:8000`) and the
frontend is served under the `/websqli` prefix. The orchestrator prints the
full list at launch, using the machine's LAN IP when `WEB_HOST=0.0.0.0`.

| Page | URL (default local bind) |
|---|---|
| Dashboard (SQLiAnalyzed) | http://127.0.0.1:8000/websqli/ |
| WebMap | http://127.0.0.1:8000/websqli/webmap |
| Tools | http://127.0.0.1:8000/websqli/tools |
| Debug GT | http://127.0.0.1:8000/websqli/debug-gt |
| Debug Timeline | http://127.0.0.1:8000/websqli/debug-timeline |
| API docs (Swagger) | http://127.0.0.1:8000/websqli/docs |
| Health check | http://127.0.0.1:8000/websqli/api/health |

**Accessing it from another machine (e.g. a server).** The default
`127.0.0.1` bind only accepts connections from the host itself, so
`http://<server-ip>:8000/websqli/` will not connect from your workstation.
Either:

- **Bind on all interfaces:** set `WEB_HOST=0.0.0.0` in the server's `.env`,
  restart, and open `WEB_PORT` in the server firewall. Then browse
  `http://<server-ip>:8000/websqli/`. The dashboard has **no authentication**,
  so only do this on a trusted network.
- **SSH tunnel (no firewall change):** from your workstation run
  `ssh -N -L 8000:localhost:8000 <user>@<server-ip>`, leave `WEB_HOST=127.0.0.1`
  on the server, and browse `http://127.0.0.1:8000/websqli/` locally.

## Pipeline and components

```
recon  →  scoring  →  sqli (detect → exploit → dump)  →  sqli_ai_attack  →  reports
```

Automatic dispatch covers crawling, scoring, detection and exploitation after
the initial scan; dumping, AI post-exploitation and reporting are manual.

| Phase | Module | What it does |
|---|---|---|
| Recon | `modules/recon/WebScanner.py` | Port scan (nmap) + fingerprinting (whatweb) → creates the `job` / `host` / `host_web_app` rows |
| Recon | `modules/recon/WebCrawler.py` | Crawls the target (+ Nikto discovery) → pages, forms, URL parameters, per-app session-scoped requests |
| Scoring | `modules/scoring/WebScorer.py` | Prioritizes crawled pages (heuristic or LLM-assisted) |
| SQLi | `modules/sqli/WebDetector.py` | Runs `sqlmap` against prioritized pages to confirm injection |
| SQLi | `modules/sqli/SQLExploiter.py` | Exploits a confirmed injection: databases → tables → columns |
| SQLi | `modules/sqli/DBDumper.py` | Dumps the data of a specific table |
| AI post-exploit | `modules/sqli_ai_attack/*` | `DBSchemaAnalyzer`, `DBCredentialHunter`, `DBAdminInyector` — LLM-driven analysis once inside the DB |
| Reports | `modules/reports/SQLWebReporter.py` | Renders findings into an HTML/PDF report (Jinja2 + `xhtml2pdf`) |

Refactored modules inherit from `core.ModuleBase`, a
`validate → load → run → report` lifecycle that persists each module's console
output as a log and turns errors into a `ModuleResult` instead of crashing the
pipeline (see [the module-layer map](src/modules/README.md)). Some standalone
scripts (e.g. `SQLWebReporter.py`) also live in the module tree.

**Orchestration** (`SQLiAgentOrchestrator.py`) is event-driven: a background
thread tails MySQL's binlog (via `mysql-replication`; needs `binlog_format=ROW`
+ `log_bin`) for newly-pending `host_web_app` / `crawl_page` / `sqli_detector`
rows and dispatches the right module as a subprocess, capped at
`--max-concurrent` (default 5). A periodic reconciliation poll re-queries the DB
as a safety net if the listener drops.

## Project structure

Application code lives under `src/` (the paths below are relative to it,
except `scripts/` and `deploy/` which are noted as repo-root). The repo root
holds `.env`, `requirements.txt`, this `README.md`, `deploy/` (service files)
and `scripts/` (maintenance CLIs).

```
core/       Module framework: ModuleBase, ModuleResult, Console, exceptions,
            scope.py (DEBUG_SCOPE_URL hostname check at explicit tool entry points)
modules/    Pipeline modules, one subfolder per phase (see table above)
tools/      Adapters around external binaries (nmap/whatweb/nikto/sqlmap) via ExternalTool base
db/         SQLAlchemy models (db/models.py) + DatabaseManager, composed from one
            mixin per domain (db/domains/{jobs,crawl,sqli,exploit,reporting,status}.py)
ai/         Shared LLM client used by the AI-assisted modules
utils/      Standalone manual detector.py/exploiter.py CLI scripts + shared helpers
Web/        FastAPI app: app.py (entrypoint), restapi.py (JSON API), webroutes.py.
            static/ has index.html at its root; the rest is sorted into
            static/_common/ (styles.css, api.js, vendor/), static/tool_pages/
            (tools/webmap pages + JS) and static/debug_pages/ (OWASP-analysis
            pages + debug_data/ ground truth: GT_URLS.json + zap_detected.json)
SQLiAgentOrchestrator.py   The orchestration daemon

(repo root, outside src/)
scripts/    Maintenance one-offs: list/mark pending work, kill stray processes
deploy/     Service files: sqli.initd (LSB init script) + install-service.sh
```

### Web UI (`Web/static/`)

| Page           | Route | Purpose |
|----------------|---|---|
| SQLiAnalyzed   | `/` | Unified, job-centric view of the whole pipeline — the default page |
| WebMap         | `/webmap` | Tree view of a job's crawled site structure with per-page vulnerability status |
| Tools          | `/tools` | One panel per module for manual, one-off runs |
| Debug GT       | `/debug-gt` | Job detections vs. curated ground truth + an OWASP ZAP baseline; coverage tables, extra findings, CSV export, target-VM health |
| Debug Timeline | `/debug-timeline` | Cumulative vulnerabilities found vs. elapsed job time, one line per job |

## Database

MySQL/MariaDB; full MariaDB schema in `src/db/sqli_tfg.sql` (structure only, no
data — see its header for how to regenerate after a change; no migrations
folder). Core tables: `jobs` → `hosts` → `host_web_app` → `crawl_page` →
`crawl_page_details` / `sqli_detector` → `sqli_exploit` → `sqli_exploit_tables`
→ `sqli_exploit_columns` / `sqli_exploit_data`, plus `host_nmap`,
`host_web_app_nikto`, `activity_logs`. The orchestrator needs binlog
replication access on top of normal DML privileges.

## REST API (`Web/restapi.py`)

Everything is under `/api`:

- **Streaming actions** (`POST /scan`, `/crawler`, `/detector`, `/exploiter`,
  `/dumper`, `/websqli/start`) run a module subprocess via `run_script()` and
  stream stdout as Server-Sent Events, tracked in the in-memory
  `active_processes` under a `session_id` (cancellable via `POST /cancel/{id}`).
  These power the Tools page and **don't need the daemon**, except
  `/websqli/start`: it only runs `WebScanner.py`, and the rest of that job is
  driven by the orchestrator picking up the new pending row.
- **JSON actions** (`POST /reporter`, `/dbanalyzer`, `/dbcredentialhunter`,
  `/dbadmininyector`) wait for the subprocess and return JSON; a separate
  endpoint downloads the generated report PDF.
- **Status** (`GET /jobs`, `/websqli/status`, `/{crawler,scanner,exploiter,detector,dumper}/status`,
  `/stats`, `/webmap`, `/pipeline/log`, …) are read-only wrappers over
  `DatabaseManager.get_*`, each returning an empty-shaped fallback instead of a
  500.
- **Other**: `/config`, `/health`, `/sqli-agent-orchestrator/status`,
  `/debug-gt/*` (ground truth, ZAP baseline, timeline, target-VM health),
  `DELETE /jobs/{id}` (cascades).

`Web/app.py` is a plain FastAPI + `uvicorn` app on `:8000`. The orchestrator
`Popen`s it (same interpreter, detached, no auto-restart). Nothing auto-reloads
on code changes — restart the process after editing code it loaded. Static
files are re-read per request (`Cache-Control: no-cache`), so a browser refresh
is enough for HTML/CSS/JS edits.

## Session handling

- **Crawler HTTP sessions:** `WebCrawler._session_for()` lazily creates a
  `requests.Session` per application key (first non-empty, lowercased path
  segment), preserving cookies and successful Basic Auth within an app while
  isolating different keys. In-memory only; not shared with sqlmap.
- **API execution sessions:** a UUID `session_id` maps to the running
  subprocess in `active_processes` for progress/cancellation. Not user logins;
  not restored after a restart.
- **Database sessions:** `DatabaseConnection` uses SQLAlchemy `scoped_session`
  with pre-ping and pool recycling; `_session()` ends the prior transaction
  first so reads see other processes' committed changes.

## Version history (simulated)

A **simulated history for documentation**, organized around development
milestones — it does not assert that Git tags or dated releases exist.

| Version | Milestone | Description |
|---|---|---|
| **v1.0** | Base system | Initial workflow: discovery, crawling, detection and DB enumeration via external tools, stored results, manual execution. Includes the web UI (dashboard, Tools panels, WebMap) and the main standalone utilities (`utils/` detector/exploiter CLI scripts + shared helpers). |
| **v1.1** | Refactor into modules | Organization by phase (`recon`, `scoring`, `sqli`, `sqli_ai_attack`, `reports`); shared `ModuleBase` lifecycle, structured results, logs, tool adapters. |
| **v1.2** | Database improvements | SQLAlchemy models + `DatabaseManager` from domain mixins; consolidated schema; binlog-driven orchestration with reconciliation. |
| **v1.3** | Session handling | Crawler HTTP sessions scoped by application-path key; UUID API execution tracking; refreshed SQLAlchemy transaction visibility. |
| **v1.4** | Debug pages & API | A few new pages, notably the debug ones (Debug GT, Debug Timeline); REST endpoints for execution/state/logs (streaming + JSON); shared frontend assets and the `/websqli` mount. |

## Authorship

Version 1 was developed as the final degree project (Trabajo Fin de Grado) of
**Daniel Penco-Hernández**, supervised by **Julio Gómez** and **Óscar Gómez**.
Subsequent versions were developed by **Julio Gómez** and **Óscar Gómez**.

## Where to make changes

| Change | Files |
|---|---|
| Add/modify a pipeline module | New file under `modules/<phase>/` subclassing `core.ModuleBase`; wire into `SQLiAgentOrchestrator.py` for auto-dispatch; add a `POST` handler in `Web/restapi.py` + a panel in `Web/static/tool_pages/tools.html` for manual UI use. |
| Add/modify a REST endpoint | `Web/restapi.py` (route) + a wrapper in `Web/static/_common/api.js`. |
| Add a new UI page | New `Web/static/tool_pages/<name>.html` + `<name>.js`; register in `Web/webroutes.py` (`_serve("tool_pages/<name>.html", ...)`); **add the nav tab by hand to every page** — there's no shared header partial (the HTML files under `Web/static/tool_pages/` and `Web/static/debug_pages/`). |
| Change shared styling | `Web/static/_common/styles.css`. |
| Change the DB schema | Edit the model in `db/models.py`, apply the `ALTER`/`CREATE` by hand, regenerate `db/sqli_tfg.sql`, and extend the owning mixin in `db/domains/*` (`db/database.py` composes them). |
| Change crawler behavior | `modules/recon/WebCrawler.py` (knobs via `CRAWLER_*` in `.env`). |
| Change an external tool's flags | `tools/{NmapTool,WhatWebTool,NiktoTool,SqlmapTool}.py` (via `tools/ExternalTool.py`). |
| Change AI behavior/prompts | `modules/scoring/WebScorerAIPromt.py`, `modules/sqli_ai_attack/*Promt.py`; `ai/ai.py` for the client (LLM endpoint/model/keys are set via the `IA_*` vars in `.env`). |
| Change ground-truth data | `Web/static/debug_pages/debug_data/{GT_URLS,zap_detected}.json` (served by `GET /api/debug-gt/{urls,zap}`, no code change). |

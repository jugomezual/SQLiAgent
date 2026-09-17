"""Live pipeline status/dashboard views used by the Web UI (Web/app.py)."""

from sqlalchemy import case, func, select

from ..base import DatabaseCore, page_status
from ..models import (
    CrawlPage,
    CrawlPageDetails,
    Host,
    HostNmap,
    HostWebApp,
    HostWebAppNikto,
    Job,
    SqliDetector,
    SqliExploit,
    SqliExploitColumns,
    SqliExploitData,
    SqliExploitTables,
)


class StatusMixin(DatabaseCore):
    @classmethod
    def _exploit_rows(cls, job_id=None, order_by=None):
        """Same shape as _list_rows(SqliExploit, ...) minus `log`: a capture
        can run tens of thousands of characters and isn't rendered in the
        list/status views (it's fetched on demand via GET /pipeline/log, see
        exploit.py's get_sqli_exploit) — for job 72 alone this column plus
        databases_json accounted for ~30MB pulled on every poll of
        /websqli/status and /exploiter/status."""
        stmt = select(
            SqliExploit.id,
            SqliExploit.sqli_detector_id,
            SqliExploit.databases_json,
            SqliExploit.total_databases,
            SqliExploit.state,
            SqliExploit.error_message,
            SqliExploit.timestamp,
            SqliExploit.jobs_id,
        )
        if job_id is not None:
            stmt = stmt.where(SqliExploit.jobs_id == job_id)
        if order_by is not None:
            stmt = stmt.order_by(order_by)
        return cls._rows(cls._session().execute(stmt))

    @classmethod
    def get_scanner_status(cls, job_id=None):
        return cls._try(lambda: cls._scanner_status(job_id), {
            "jobs": [], "hosts": [], "webapps": [], "nmap": [],
        })

    @classmethod
    def _scanner_status(cls, job_id=None):
        if job_id:
            return {
                "jobs": cls._get_jobs(job_id=job_id),
                "hosts": cls._list_rows(Host, job_id, Host.timestamp.desc(), 50),
                "webapps": cls._list_rows(HostWebApp, job_id, HostWebApp.id.desc(), 50),
                "nmap": cls._list_rows(HostNmap, job_id, HostNmap.id.desc(), 100),
            }
        return {
            "jobs": cls._list_rows(Job, order_by=Job.timestamp.desc(), limit=20),
            "hosts": cls._list_rows(Host, order_by=Host.timestamp.desc(), limit=50),
            "webapps": cls._list_rows(HostWebApp, order_by=HostWebApp.id.desc(), limit=50),
            "nmap": cls._list_rows(HostNmap, order_by=HostNmap.id.desc(), limit=100),
        }

    @classmethod
    def get_report_pages(cls, job_id: int) -> list:
        return cls._try(lambda: cls._report_pages(job_id), [])

    @classmethod
    def _report_pages(cls, job_id: int) -> list:
        rows = cls._rows(cls._session().execute(
            select(
                Host.target_host,
                HostWebApp.target_url.label("webapp_url"),
                CrawlPage.url.label("page_url"),
                CrawlPage.priority_score,
                CrawlPage.priority_level,
                CrawlPage.state.label("page_state"),
                func.count(func.distinct(SqliExploit.id)).label("exploit_count"),
                func.max(SqliDetector.is_vulnerable).label("max_vulnerable"),
                func.max(case((SqliDetector.state == "discarded", 1), else_=0)).label("has_discarded"),
                func.max(case(((SqliDetector.is_vulnerable.is_(True)) & (SqliDetector.state == "pending"), 1), else_=0)).label("has_pending_vuln"),
            )
            .join(HostWebApp, CrawlPage.web_app_id == HostWebApp.id)
            .join(Host, HostWebApp.host_id == Host.id)
            .outerjoin(SqliDetector, SqliDetector.crawl_page_id == CrawlPage.id)
            .outerjoin(SqliExploit, SqliExploit.sqli_detector_id == SqliDetector.id)
            .where(CrawlPage.jobs_id == job_id)
            .group_by(CrawlPage.id, Host.target_host, HostWebApp.target_url, CrawlPage.url, CrawlPage.priority_score, CrawlPage.priority_level, CrawlPage.state)
            .order_by(Host.target_host.asc(), HostWebApp.target_url.asc(), CrawlPage.url.asc())
        ))
        for row in rows:
            row["status"] = page_status(row)
        return rows

    @classmethod
    def get_websqli_status(cls, job_id=None):
        return cls._try(lambda: cls._websqli_status(job_id), {
            "scanners": [], "crawlers": [], "detectors": [], "exploiters": [], "scorers": [],
        })

    @classmethod
    def _websqli_status(cls, job_id: int = None) -> dict:
        effective_job_id = job_id or cls._latest_job_id()
        if not effective_job_id:
            return {"scanners": [], "crawlers": [], "detectors": [], "exploiters": [], "scorers": []}

        session = cls._session()
        scanners = cls._rows(session.execute(
            select(Host.id, Host.target_host, Host.state, Host.error_message).where(Host.jobs_id == effective_job_id)
        ))
        crawlers = cls._rows(session.execute(
            select(HostWebApp.id, HostWebApp.target_url, HostWebApp.state, HostWebApp.error_message)
            .where(HostWebApp.jobs_id == effective_job_id)
            .order_by(HostWebApp.id.asc())
        ))
        # Pages that failed to fetch/parse during the crawl itself (never got a
        # crawl_page_details row written) — shown as error cards in the Crawler
        # column, one per failed URL, distinct from the per-web-app rows above.
        crawl_fetch_errors = cls._rows(session.execute(
            select(
                CrawlPage.id,
                CrawlPage.url.label("target_url"),
                CrawlPage.state,
                CrawlPage.error_message,
                CrawlPage.web_app_id,
            )
            .outerjoin(CrawlPageDetails, CrawlPageDetails.crawl_page_id == CrawlPage.id)
            .where(
                CrawlPage.jobs_id == effective_job_id,
                CrawlPage.state == "error",
                CrawlPageDetails.id.is_(None),
            )
            .order_by(CrawlPage.id.desc())
        ))
        crawlers = crawlers + crawl_fetch_errors
        detectors = cls._rows(session.execute(
            select(
                CrawlPage.id,
                CrawlPage.url,
                CrawlPage.state,
                CrawlPage.error_message,
                CrawlPage.priority_score,
                CrawlPage.priority_level,
                func.max(SqliDetector.is_vulnerable).label("is_vulnerable"),
            )
            .outerjoin(SqliDetector, SqliDetector.crawl_page_id == CrawlPage.id)
            .outerjoin(CrawlPageDetails, CrawlPageDetails.crawl_page_id == CrawlPage.id)
            .where(
                CrawlPage.jobs_id == effective_job_id,
                (CrawlPage.state.in_(["running", "pending"])) |
                # A page that errored during the crawl itself (never got a
                # crawl_page_details row) never reached scoring/detection - it
                # belongs only in the Crawler column, not here too.
                ((CrawlPage.state == "error") & CrawlPageDetails.id.is_not(None)) |
                ((CrawlPage.state == "done") & SqliDetector.id.is_not(None)),
            )
            .group_by(CrawlPage.id)
            .order_by(CrawlPage.id.desc())
        ))
        exploiters = cls._exploit_rows(effective_job_id, SqliExploit.id.desc())
        scorer_rows = cls._rows(session.execute(
            select(CrawlPage.id, CrawlPage.url, CrawlPage.state, CrawlPage.error_message)
            .outerjoin(CrawlPageDetails, CrawlPageDetails.crawl_page_id == CrawlPage.id)
            .where(
                CrawlPage.jobs_id == effective_job_id,
                (CrawlPage.state.in_(["pending_score", "running_score", "pending"])) |
                # Same crawl-time-error exclusion as the detectors query above.
                ((CrawlPage.state == "error") & CrawlPageDetails.id.is_not(None)),
            )
            .order_by(CrawlPage.id.asc())
        ))
        scorers = []
        for page in scorer_rows:
            state = page.get("state", "")
            mapped_state = "pending" if state == "pending_score" else "running" if state == "running_score" else "error" if state == "error" else "done"
            scorers.append({
                "id": page.get("id"),
                "target_url": page.get("url", ""),
                "state": mapped_state,
                "error_message": page.get("error_message"),
            })
        return {
            "scanners": scanners,
            "crawlers": crawlers,
            "detectors": detectors,
            "exploiters": exploiters,
            "scorers": scorers,
        }

    @classmethod
    def get_crawler_status(cls, job_id=None):
        return {
            "pages": cls._list_rows(CrawlPage, job_id, CrawlPage.id.asc()),
            "details": cls._list_rows(CrawlPageDetails, job_id, CrawlPageDetails.id.asc()),
            "nikto": cls._list_rows(HostWebAppNikto, job_id, HostWebAppNikto.id.asc()),
        }

    @classmethod
    def get_exploiter_status(cls, job_id=None):
        return {
            "exploits": cls._exploit_rows(job_id, SqliExploit.id.asc()),
            "tables": cls._list_rows(SqliExploitTables, job_id, SqliExploitTables.id.asc()),
            "columns": cls._list_rows(SqliExploitColumns, job_id, SqliExploitColumns.id.asc()),
        }

    @classmethod
    def get_detector_status(cls, job_id=None):
        return {"detections": cls._list_rows(SqliDetector, job_id, SqliDetector.id.asc())}

    @classmethod
    def get_dumper_status(cls, job_id=None):
        return {"data": cls._list_rows(SqliExploitData, job_id, SqliExploitData.id.asc(), 500)}

    @classmethod
    def get_obtain_data_result(cls, db_name, table_name, job_id=None):
        return {"data_json": cls._latest_dump_data(db_name, table_name, job_id)}

    @classmethod
    def _latest_dump_data(cls, db_name: str, table_name: str, job_id: int = None):
        stmt = select(SqliExploitData.data_json).where(
            SqliExploitData.db_name == db_name,
            SqliExploitData.table_name == table_name,
            SqliExploitData.dump_success.is_(True),
        )
        if job_id:
            stmt = stmt.where(SqliExploitData.jobs_id == job_id)
        return cls._session().execute(stmt.order_by(SqliExploitData.id.desc()).limit(1)).scalar()

    @classmethod
    def get_dbanalyzer_databases(cls, job_id: int):
        rows = cls._exploit_databases(job_id)
        return {"databases": [row["db_name"] for row in rows]}

    @classmethod
    def get_stats(cls, job_id=None):
        return {"stats": cls._stats(job_id)}

    @classmethod
    def _stats(cls, job_id: int = None) -> list:
        stats = []
        for job in cls._get_jobs(job_id=job_id, ascending=True, reporter=True):
            jid = job["id"]
            metrics = cls._report_metrics(jid)
            stats.append({
                "job_id": jid,
                "job_type": job.get("job_type"),
                "model": job.get("model"),
                "depth": job.get("depth"),
                "comment": job.get("comment"),
                "state": job.get("state", "done"),
                "finished_at": str(job.get("finished_at", "") or ""),
                "timestamp": str(job.get("timestamp", "")),
                "hosts": metrics["hosts_total"],
                "webapps": metrics["webapps_total"],
                "pages": metrics["pages_crawled"],
                "sqli_vulnerable": metrics["sqli_confirmed"],
                "databases": metrics["obtained_dbs"],
                "tables": metrics["obtained_tables"],
                "columns": metrics["obtained_columns"],
            })
        return stats

    @classmethod
    def get_webmap(cls, job_id=None):
        return {"pages": cls._webmap_pages(job_id)}

    @classmethod
    def _webmap_pages(cls, job_id: int = None) -> list:
        stmt = select(
            Host.id.label("host_id"),
            Host.target_host,
            HostWebApp.id.label("webapp_id"),
            HostWebApp.target_url.label("webapp_url"),
            CrawlPage.id.label("page_id"),
            CrawlPage.url.label("page_url"),
            CrawlPage.priority_score,
            CrawlPage.depth.label("page_depth"),
            CrawlPage.state.label("page_state"),
            func.count(func.distinct(SqliExploit.id)).label("exploit_count"),
            func.max(SqliDetector.is_vulnerable).label("max_vulnerable"),
            func.max(case((SqliDetector.state == "discarded", 1), else_=0)).label("has_discarded"),
        ).join(HostWebApp, CrawlPage.web_app_id == HostWebApp.id).join(
            Host, HostWebApp.host_id == Host.id
        ).outerjoin(SqliDetector, SqliDetector.crawl_page_id == CrawlPage.id).outerjoin(
            SqliExploit, SqliExploit.sqli_detector_id == SqliDetector.id
        )
        if job_id:
            stmt = stmt.where(CrawlPage.jobs_id == job_id)
        rows = cls._rows(cls._session().execute(
            stmt.group_by(CrawlPage.id, Host.id, Host.target_host, HostWebApp.id, HostWebApp.target_url,
                          CrawlPage.url, CrawlPage.priority_score, CrawlPage.depth, CrawlPage.state)
            .order_by(Host.id.asc(), HostWebApp.id.asc(), CrawlPage.url.asc())
        ))
        for row in rows:
            row["status"] = page_status(row)
        return rows

    @classmethod
    def get_exploit_schema_rows(cls, db_name=None, job_id=None):
        return cls._exploit_schema_rows(db_name, job_id)

    @classmethod
    def _exploit_schema_rows(cls, db_name: str = None, job_id: int = None):
        tables_stmt = select(
            SqliExploitTables.id.label("exploit_tables_id"),
            SqliExploitTables.db_name,
            SqliExploitTables.tables_json,
        )
        columns_stmt = select(
            SqliExploitColumns.sqli_exploit_tables_id,
            SqliExploitColumns.table_name,
            SqliExploitColumns.columns_json,
        ).join(SqliExploitTables, SqliExploitColumns.sqli_exploit_tables_id == SqliExploitTables.id)
        filters = []
        if db_name:
            filters.append(SqliExploitTables.db_name == db_name)
        if job_id:
            filters.append(SqliExploitTables.jobs_id == job_id)
        if filters:
            tables_stmt = tables_stmt.where(*filters)
            columns_stmt = columns_stmt.where(*filters)
        session = cls._session()
        return (
            cls._rows(session.execute(tables_stmt.order_by(SqliExploitTables.id.asc()))),
            cls._rows(session.execute(columns_stmt.order_by(SqliExploitColumns.sqli_exploit_tables_id.asc(), SqliExploitColumns.table_name.asc()))),
        )

    @classmethod
    def get_pending_work_count(cls, job_id: int):
        session = cls._session()
        hosts = session.execute(select(func.count()).select_from(Host).where(Host.jobs_id == job_id, Host.state.in_(["pending", "running"]))).scalar() or 0
        webapps = session.execute(select(func.count()).select_from(HostWebApp).where(HostWebApp.jobs_id == job_id, HostWebApp.state.in_(["pending", "running"]))).scalar() or 0
        pages = session.execute(select(func.count()).select_from(CrawlPage).where(CrawlPage.jobs_id == job_id, CrawlPage.state.in_(["pending", "running", "pending_score", "running_score"]))).scalar() or 0
        detections = session.execute(select(func.count()).select_from(SqliDetector).where(SqliDetector.jobs_id == job_id, SqliDetector.state == "pending")).scalar() or 0
        return hosts + webapps + pages + detections

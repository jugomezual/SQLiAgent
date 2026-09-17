"""Report generation: the exportable findings/metrics used by SQLWebReporter."""

import json

from sqlalchemy import case, func, select

from ..base import DatabaseCore, json_list, json_to_text
from ..models import (
    ActivityLog,
    CrawlPage,
    Host,
    HostNmap,
    HostWebApp,
    Job,
    SqliDetector,
    SqliExploit,
    SqliExploitColumns,
    SqliExploitTables,
)
from utils.common import url_pattern


def _finding_group_key(row):
    """Identity of "one vulnerability" for grouping SqliDetector rows: same
    page pattern, same HTTP method, same injected field(s). Keeps distinct
    vulnerable fields on the same URL pattern separate while collapsing
    the same field hit through different parameter values into one."""
    points = tuple(sorted(json_list(row.get("injection_points_json"))))
    return (url_pattern(row.get("target_url") or ""), row.get("method") or "", points)


class ReportingMixin(DatabaseCore):
    @classmethod
    def insert_activity_log(cls, jobs_id, event_type, reference_id, reference_table, details):
        return cls._try(lambda: cls._insert(
            ActivityLog,
            jobs_id=jobs_id,
            event_type=event_type,
            reference_id=reference_id,
            reference_table=reference_table,
            details_json=json.dumps(details) if not isinstance(details, str) else details,
        ))

    @classmethod
    def get_report_activity_logs(cls, job_id):
        return cls._try(lambda: cls._activity_logs(job_id), [])

    @classmethod
    def _activity_logs(cls, job_id):
        return cls._rows(cls._session().execute(
            select(ActivityLog.id, ActivityLog.event_type, ActivityLog.reference_id,
                   ActivityLog.reference_table, ActivityLog.details_json, ActivityLog.timestamp)
            .where(ActivityLog.jobs_id == job_id)
            .order_by(ActivityLog.timestamp.asc(), ActivityLog.id.asc())
        ))

    @classmethod
    def get_report_metrics(cls, job_id: int = None) -> dict:
        return cls._try(lambda: cls._report_metrics(job_id), {
            "hosts_total": 0, "hosts_done": 0, "webapps_total": 0,
            "pages_crawled": 0, "pages_tested": 0, "sqli_confirmed": 0,
            "exploits_success": 0, "obtained_dbs": 0,
            "obtained_tables": 0, "obtained_columns": 0,
        })

    @classmethod
    def _report_metrics(cls, job_id: int = None) -> dict:
        session = cls._session()
        job_filter = [Host.jobs_id == job_id] if job_id else []
        page_job_filter = [CrawlPage.jobs_id == job_id] if job_id else []
        webapp_job_filter = [HostWebApp.jobs_id == job_id] if job_id else []
        sqli_job_filter = [SqliDetector.jobs_id == job_id] if job_id else []
        exploit_job_filter = [SqliExploit.jobs_id == job_id] if job_id else []

        hosts_total = session.execute(select(func.count()).select_from(Host).where(*job_filter)).scalar() or 0
        hosts_done = session.execute(select(func.count()).select_from(Host).where(*job_filter, Host.state == "done")).scalar() or 0
        webapps_total = session.execute(select(func.count()).select_from(HostWebApp).where(*webapp_job_filter)).scalar() or 0
        pages_crawled = session.execute(select(func.count()).select_from(CrawlPage).where(*page_job_filter)).scalar() or 0
        pages_tested = session.execute(select(func.count()).select_from(SqliDetector).where(*sqli_job_filter)).scalar() or 0
        # Grouped by (url_pattern, method, injection points) rather than
        # exact target_url: the same injectable field hit through different
        # parameter values (?bID=1, ?bID=2, ...) is one vulnerability, not N.
        # injection_points is part of the key too so two genuinely different
        # vulnerable fields that happen to share a url_pattern still count
        # separately.
        vulnerable_rows = cls._rows(session.execute(
            select(SqliDetector.target_url, SqliDetector.method, SqliDetector.injection_points_json)
            .where(*sqli_job_filter, SqliDetector.is_vulnerable.is_(True))
        ))
        sqli_confirmed = len({_finding_group_key(row) for row in vulnerable_rows if row.get("target_url")})
        exploits_success = session.execute(
            select(func.count()).select_from(SqliExploit).where(*exploit_job_filter, SqliExploit.state == "done")
        ).scalar() or 0
        obtained_dbs = session.execute(
            select(func.coalesce(func.max(SqliExploit.total_databases), 0)).where(*exploit_job_filter)
        ).scalar() or 0
        table_rows = cls._list_rows(SqliExploitTables, job_id)
        unique_tables = {(row.get("db_name") or "", table) for row in table_rows for table in json_list(row.get("tables_json"))}
        column_rows = cls._rows(session.execute(
            select(SqliExploitTables.db_name, SqliExploitColumns.table_name, SqliExploitColumns.columns_json)
            .join(SqliExploitColumns, SqliExploitColumns.sqli_exploit_tables_id == SqliExploitTables.id)
            .where(*([SqliExploitTables.jobs_id == job_id] if job_id else []))
        ))
        unique_columns = set()
        for row in column_rows:
            for col in json_list(row.get("columns_json")):
                col_name = col.get("name") if isinstance(col, dict) else str(col)
                unique_columns.add((row.get("db_name") or "", row.get("table_name") or "", col_name))
        return {
            "hosts_total": hosts_total,
            "hosts_done": hosts_done,
            "webapps_total": webapps_total,
            "pages_crawled": pages_crawled,
            "pages_tested": pages_tested,
            "sqli_confirmed": sqli_confirmed,
            "exploits_success": exploits_success,
            "obtained_dbs": obtained_dbs,
            "obtained_tables": len(unique_tables),
            "obtained_columns": len(unique_columns),
        }

    @classmethod
    def get_report_findings(cls, job_id: int = None) -> list:
        return cls._try(lambda: cls._report_findings(job_id), [])

    @classmethod
    def _report_findings(cls, job_id: int = None) -> list:
        stmt = select(SqliDetector.target_url, SqliDetector.method,
                      SqliDetector.injection_points_json, SqliDetector.injection_types_json).where(
            SqliDetector.is_vulnerable.is_(True)
        )
        if job_id:
            stmt = stmt.where(SqliDetector.jobs_id == job_id)
        rows = cls._rows(cls._session().execute(stmt.order_by(SqliDetector.id.asc())))
        seen_groups = set()
        findings = []
        for row in rows:
            # Group by (url_pattern, method, injection points): the same
            # injectable field tested with different parameter values is one
            # finding, reported once using its first-seen concrete URL.
            group_key = _finding_group_key(row)
            if group_key in seen_groups:
                continue
            seen_groups.add(group_key)
            findings.append({
                "url": row.get("target_url") or "",
                "method": row.get("method") or "",
                "injection_points": json_to_text(row.get("injection_points_json")),
                "injection_types": json_to_text(row.get("injection_types_json")),
            })
        return findings

    @classmethod
    def get_report_exploitation_results(cls, job_id: int = None) -> list:
        return cls._try(lambda: cls._report_exploitation_results(job_id), [])

    @classmethod
    def _report_exploitation_results(cls, job_id: int = None) -> list:
        db_tables = {}
        for row in cls._list_rows(SqliExploitTables, job_id, SqliExploitTables.id.asc()):
            db_name = row.get("db_name") or ""
            db_tables.setdefault(db_name, set()).update(json_list(row.get("tables_json")))
        return [
            {"db_name": db_name, "tables_count": len(tables), "tables": sorted(tables)}
            for db_name, tables in db_tables.items()
        ]

    @classmethod
    def get_report_ports(cls, job_id: int = None) -> list:
        return cls._try(lambda: cls._report_ports(job_id), [])

    @classmethod
    def _report_ports(cls, job_id: int = None) -> list:
        stmt = select(Host.target_host, HostNmap.port, HostNmap.nmap_state, HostNmap.nmap_service, HostNmap.nmap_version).join(
            Host, HostNmap.host_id == Host.id
        ).where(HostNmap.nmap_state == "open")
        if job_id:
            stmt = stmt.where(Host.jobs_id == job_id)
        rows = cls._rows(cls._session().execute(stmt.order_by(Host.target_host.asc(), HostNmap.port.asc())))
        return [
            {
                "host": row.get("target_host") or "",
                "port": row.get("port") or "",
                "nmap_state": row.get("nmap_state") or "",
                "nmap_service": row.get("nmap_service") or "",
                "nmap_version": row.get("nmap_version") or "",
            }
            for row in rows
        ]

    @classmethod
    def get_report_webs(cls, job_id: int = None) -> list:
        return cls._try(lambda: cls._report_webs(job_id), [])

    @classmethod
    def _report_webs(cls, job_id: int = None) -> list:
        rows = cls._list_rows(HostWebApp, job_id, HostWebApp.id.asc())
        return [
            {
                "url": row.get("target_url") or "",
                "technologies": json_to_text(row.get("technologies_json")),
                "cookies": json_to_text(row.get("cookies_json")),
                "headers": json_to_text(row.get("headers_json")),
                "uncommon_headers": json_to_text(row.get("uncommon_headers_json")),
            }
            for row in rows
        ]

    @classmethod
    def get_sqli_context_for_job(cls, jobs_id: int) -> dict:
        return cls._try(lambda: cls._sqli_context_for_job(jobs_id), {"vulnerable": [], "exploited": []})

    @classmethod
    def _sqli_context_for_job(cls, jobs_id: int) -> dict:
        rows = cls._rows(cls._session().execute(
            select(
                SqliDetector.target_url,
                SqliDetector.injection_types_json,
                case((SqliExploit.id.is_not(None), 1), else_=0).label("is_exploited"),
            )
            .outerjoin(SqliExploit, (SqliExploit.sqli_detector_id == SqliDetector.id) & (SqliExploit.state == "done"))
            .where(SqliDetector.jobs_id == jobs_id, SqliDetector.is_vulnerable.is_(True), SqliDetector.state != "discarded")
        ))
        vulnerable, exploited = [], []
        for row in rows:
            entry = {"url": row["target_url"], "injection_types": json_list(row.get("injection_types_json"))}
            (exploited if row.get("is_exploited") else vulnerable).append(entry)
        return {"vulnerable": vulnerable, "exploited": exploited}

    @classmethod
    def get_vulnerability_timeline(cls, job_ids: list) -> dict:
        """One cumulative-vulnerability-count-over-time series per job, for
        the Debug Timeline chart. Reuses _finding_group_key so the count at
        any point matches what reporting/Debug GT count as "one
        vulnerability" (e.g. ?bID=1 vs ?bID=2 only bump the count once)."""
        return cls._try(lambda: cls._vulnerability_timeline(job_ids), {})

    @classmethod
    def _vulnerability_timeline(cls, job_ids: list) -> dict:
        if not job_ids:
            return {}
        session = cls._session()
        jobs = cls._rows(session.execute(
            select(Job.id, Job.timestamp, Job.finished_at, Job.state, Job.target_url)
            .where(Job.id.in_(job_ids))
        ))
        result = {}
        for job in jobs:
            jid = job["id"]
            start = job.get("timestamp")
            if not start:
                continue
            rows = cls._rows(session.execute(
                select(SqliDetector.target_url, SqliDetector.method,
                       SqliDetector.injection_points_json, SqliDetector.timestamp)
                .where(SqliDetector.jobs_id == jid, SqliDetector.is_vulnerable.is_(True))
                .order_by(SqliDetector.timestamp.asc(), SqliDetector.id.asc())
            ))
            seen_groups = set()
            points = [{"t": 0, "count": 0}]
            count = 0
            for row in rows:
                group_key = _finding_group_key(row)
                if group_key in seen_groups:
                    continue
                seen_groups.add(group_key)
                count += 1
                ts = row.get("timestamp")
                elapsed = max((ts - start).total_seconds(), 0) if ts else points[-1]["t"]
                points.append({"t": elapsed, "count": count, "url": row.get("target_url")})
            # Ends at the last actual detection, not stretched flat out to
            # finished_at — a job that stopped finding anything early should
            # visibly stop, not look like it kept running to the same count.
            end = job.get("finished_at")
            result[jid] = {
                "start": str(start),
                "finished_at": str(end) if end else None,
                "state": job.get("state"),
                "target_url": job.get("target_url"),
                "points": points,
            }
        return result

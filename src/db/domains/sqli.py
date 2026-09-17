"""SQLi detection: candidate pages, dedup checks, detector results."""

import json
from urllib.parse import urlparse

from sqlalchemy import select

from ..base import DatabaseCore, now, to_dict
from ..models import SqliDetector


class SqliMixin(DatabaseCore):
    @classmethod
    def get_sqli_detector(cls, sqli_id):
        return cls._try(lambda: cls._find_one(SqliDetector, id=sqli_id))

    @classmethod
    def get_sqli_by_crawl_page(cls, crawl_page_id):
        return cls._try(
            lambda: cls._find_many(SqliDetector, order_by=SqliDetector.timestamp.desc(), crawl_page_id=crawl_page_id),
            [],
        )

    @classmethod
    def insert_sqli_detector(cls, crawl_page_id, target_url, method, is_vulnerable=0,
                             injection_points=None, injection_types=None, dbms=None,
                             error_message=None, state="done"):
        def action():
            return cls._insert(
                SqliDetector,
                crawl_page_id=crawl_page_id,
                target_url=target_url,
                method=method,
                jobs_id=cls._resolve_jobs_id("crawl_page", crawl_page_id),
                is_vulnerable=is_vulnerable,
                injection_points_json=json.dumps(injection_points) if injection_points else None,
                injection_types_json=json.dumps(injection_types) if injection_types else None,
                dbms=dbms,
                error_message=error_message,
                state=state,
                timestamp=now(),
            )
        return cls._try(action)

    @classmethod
    def update_sqli_detector_state(cls, sqli_id, state):
        return cls._try(lambda: cls._update(SqliDetector, sqli_id, state=state))

    @classmethod
    def update_sqli_detector_results(cls, sqli_id, is_vulnerable, injection_points=None,
                                     injection_types=None, dbms=None, error_message=None, state="done"):
        return cls._try(lambda: cls._update(
            SqliDetector, sqli_id,
            is_vulnerable=is_vulnerable,
            injection_points_json=json.dumps(injection_points) if injection_points else None,
            injection_types_json=json.dumps(injection_types) if injection_types else None,
            dbms=dbms,
            error_message=error_message,
            state=state,
        ))

    @classmethod
    def get_vulnerable_sqli(cls):
        return cls._try(lambda: cls._find_many(SqliDetector, order_by=SqliDetector.timestamp.desc(), is_vulnerable=1), [])

    @classmethod
    def get_pending_vulnerable_sqli(cls):
        """One-time startup backfill (see CrawlMixin.get_pending_web_apps)."""
        return cls._try(
            lambda: cls._find_many(SqliDetector, order_by=SqliDetector.id.asc(), is_vulnerable=1, state="pending"),
            [],
        )

    @classmethod
    def discard_same_level_pages(cls, exploited_sqli_id, databases):
        def action():
            count, base, discarded = cls._discard_same_level_pages(exploited_sqli_id)
            if count:
                print(f"Discarded {count} page(s) with same base path: {base}")
                print(f"DBs found: {databases}")
                for row in discarded:
                    print(f"sqli_detector #{row['id']}: {row['target_url']}")
            return count
        return cls._try(action, 0)

    @classmethod
    def _discard_same_level_pages(cls, exploited_sqli_id):
        session = cls._session()
        exploited = session.get(SqliDetector, exploited_sqli_id)
        if not exploited:
            return 0, "", []
        parsed = urlparse(exploited.target_url)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        candidates = session.scalars(
            select(SqliDetector).where(
                SqliDetector.jobs_id == exploited.jobs_id,
                SqliDetector.is_vulnerable.is_(True),
                SqliDetector.state == "pending",
                SqliDetector.id != exploited_sqli_id,
            )
        ).all()
        discarded = []
        for candidate in candidates:
            parsed_candidate = urlparse(candidate.target_url)
            candidate_base = f"{parsed_candidate.scheme}://{parsed_candidate.netloc}{parsed_candidate.path}"
            if candidate_base == base:
                candidate.state = "discarded"
                discarded.append(candidate)
        if discarded:
            session.commit()
        return len(discarded), base, [to_dict(candidate) for candidate in discarded]

"""Web apps and crawled pages."""

import json

from ..base import DatabaseCore, now
from ..models import CrawlPage, CrawlPageDetails, HostWebApp, HostWebAppNikto


class CrawlMixin(DatabaseCore):
    @classmethod
    def insert_web_app(cls, host_id, target_url, http_status=None, redirect_location=None,
                       technologies=None, cookies=None, headers=None, uncommon_headers=None, state="pending"):
        def action():
            return cls._insert(
                HostWebApp,
                host_id=host_id,
                target_url=target_url,
                jobs_id=cls._resolve_jobs_id("hosts", host_id),
                http_status=http_status,
                redirect_location=redirect_location,
                technologies_json=json.dumps(technologies) if technologies else None,
                cookies_json=json.dumps(cookies) if cookies else None,
                headers_json=json.dumps(headers) if headers else None,
                uncommon_headers_json=json.dumps(uncommon_headers) if uncommon_headers else None,
                state=state,
                timestamp=now(),
            )
        return cls._try(action)

    @classmethod
    def get_web_app(cls, web_app_id):
        return cls._try(lambda: cls._find_one(HostWebApp, id=web_app_id))

    @classmethod
    def get_web_apps(cls):
        return cls._try(lambda: cls._find_many(HostWebApp, order_by=HostWebApp.timestamp.desc()), [])

    @classmethod
    def get_pending_web_apps(cls):
        """One-time startup backfill: work already pending before the binlog
        listener attached (see SQLiAgentOrchestrator.py). Not used for steady-state polling."""
        return cls._try(lambda: cls._find_many(HostWebApp, order_by=HostWebApp.id.asc(), state="pending"), [])

    @classmethod
    def update_web_app_state(cls, web_app_id, state, error_message=None):
        return cls._try(lambda: cls._update(HostWebApp, web_app_id, state=state, error_message=error_message))

    @classmethod
    def update_web_app_log(cls, web_app_id, log):
        return cls._try(lambda: cls._update(HostWebApp, web_app_id, log=log))

    @classmethod
    def insert_nikto_results(cls, web_app_id, urls: list[str]):
        """One row per URL Nikto discovered for this web app's crawl."""
        def action():
            jobs_id = cls._resolve_jobs_id("host_web_app", web_app_id)
            saved = 0
            for url in urls:
                if cls._insert(HostWebAppNikto, web_app_id=web_app_id, url=url,
                                jobs_id=jobs_id, timestamp=now()):
                    saved += 1
            return saved
        return cls._try(action, 0)

    @classmethod
    def insert_crawl_page(cls, web_app_id, url, base_url=None, **kwargs):
        def action():
            jobs_id = kwargs.get("jobs_id")
            if jobs_id is None and "jobs_id" not in kwargs:
                jobs_id = cls._resolve_jobs_id("host_web_app", web_app_id)
            return cls._insert(
                CrawlPage,
                web_app_id=web_app_id,
                base_url=base_url,
                url=url,
                is_admin_path=kwargs.get("is_admin_path", 0),
                has_login_form=kwargs.get("has_login_form", 0),
                has_register_form=kwargs.get("has_register_form", 0),
                has_search_form=kwargs.get("has_search_form", 0),
                has_upload_form=kwargs.get("has_upload_form", 0),
                has_form_without_csrf=kwargs.get("has_form_without_csrf", 0),
                has_errors=kwargs.get("has_errors", 0),
                has_parametres_url=kwargs.get("has_parametres_url", 0),
                is_referred_robots=kwargs.get("is_referred_robots", 0),
                has_get_params=kwargs.get("has_get_params", 0),
                has_post_params=kwargs.get("has_post_params", 0),
                priority_score=kwargs.get("priority_score"),
                priority_level=kwargs.get("priority_level"),
                state=kwargs.get("state", "done"),
                error_message=kwargs.get("error_message"),
                jobs_id=jobs_id,
                depth=kwargs.get("depth"),
                timestamp=now(),
            )
        return cls._try(action)

    @classmethod
    def insert_crawl_page_details(cls, crawl_page_id, forms=None, standalone_inputs=None,
                                  url_params=None, error_details=None, state="done"):
        def action():
            return cls._insert(
                CrawlPageDetails,
                crawl_page_id=crawl_page_id,
                jobs_id=cls._resolve_jobs_id("crawl_page", crawl_page_id),
                forms_json=json.dumps(forms) if forms else None,
                standalone_inputs_json=json.dumps(standalone_inputs) if standalone_inputs else None,
                url_params_json=json.dumps(url_params) if url_params else None,
                error_details_json=json.dumps(error_details) if error_details else None,
                state=state,
                timestamp=now(),
            )
        return cls._try(action)

    @classmethod
    def get_crawl_pages(cls, web_app_id):
        return cls._try(lambda: cls._find_many(CrawlPage, order_by=CrawlPage.timestamp.desc(), web_app_id=web_app_id), [])

    @classmethod
    def get_pending_crawl_pages(cls):
        """One-time startup backfill (see get_pending_web_apps)."""
        return cls._try(lambda: cls._find_many(CrawlPage, order_by=CrawlPage.id.asc(), state="pending"), [])

    @classmethod
    def get_pending_score_pages(cls):
        """One-time startup backfill (see get_pending_web_apps)."""
        return cls._try(lambda: cls._find_many(CrawlPage, order_by=CrawlPage.id.desc(), state="pending_score"), [])

    @classmethod
    def get_crawl_page(cls, crawl_page_id):
        return cls._try(lambda: cls._find_one(CrawlPage, id=crawl_page_id))

    @classmethod
    def get_crawl_page_details(cls, crawl_page_id):
        return cls._try(lambda: cls._find_one(CrawlPageDetails, crawl_page_id=crawl_page_id))

    @classmethod
    def update_crawl_page_state(cls, crawl_page_id, state, error_message=None):
        return cls._try(lambda: cls._update(CrawlPage, crawl_page_id, state=state, error_message=error_message))

    @classmethod
    def update_crawl_page_log(cls, crawl_page_id, log):
        return cls._try(lambda: cls._update(CrawlPage, crawl_page_id, log=log))

    @classmethod
    def update_crawl_page_priority(cls, crawl_page_id, priority_score, priority_level):
        return cls._try(
            lambda: cls._update(CrawlPage, crawl_page_id, priority_score=priority_score, priority_level=priority_level)
        )

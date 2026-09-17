"""Shared connection and generic ORM helpers used by every DatabaseManager mixin.

To add a new domain of DB methods: create db/domains/<name>.py with a class
that subclasses DatabaseCore, implement methods using the helpers below, then
list it in db/domains/__init__.py and add it to DatabaseManager's bases in
db/database.py.
"""

import json
import os
from datetime import datetime

from dotenv import load_dotenv
from sqlalchemy import create_engine, inspect, select
from sqlalchemy.engine import URL
from sqlalchemy.orm import scoped_session, sessionmaker

load_dotenv()

from .models import (
    CrawlPage,
    CrawlPageDetails,
    Host,
    HostWebApp,
    Job,
    SqliDetector,
    SqliExploit,
    SqliExploitColumns,
    SqliExploitTables,
)


class DatabaseConnection:
    """Engine/session singleton, configured from DATABASE_URL or DB_* env vars."""

    _instance = None

    DEFAULT_HOST = "localhost"
    DEFAULT_PORT = 3306
    DEFAULT_DBNAME = "sqli_tfg"
    DEFAULT_DRIVER = "mysql+pymysql"

    def __init__(self, host=None, dbname=None, username=None, password=None, port=None, url=None):
        self._database_url = url or os.getenv("DATABASE_URL")
        if not self._database_url:
            self._host = host or os.getenv("DB_HOST", self.DEFAULT_HOST)
            self._port = int(port or os.getenv("DB_PORT", self.DEFAULT_PORT))
            self._dbname = dbname or os.getenv("DB_NAME", self.DEFAULT_DBNAME)
            self._username = username if username is not None else self._required_env("DB_USER")
            self._password = password if password is not None else self._required_env("DB_PASSWORD", allow_empty=True)
            self._driver = os.getenv("DB_DRIVER", self.DEFAULT_DRIVER)

        self.engine = create_engine(
            self._build_url(),
            pool_pre_ping=True,
            pool_recycle=3600,
            future=True,
        )
        self._session_factory = scoped_session(
            sessionmaker(bind=self.engine, autoflush=False, expire_on_commit=False, future=True)
        )

    @classmethod
    def get_instance(cls, host=None, dbname=None, username=None, password=None, port=None, url=None):
        if cls._instance is None:
            cls._instance = cls(host, dbname, username, password, port, url)
        return cls._instance

    @staticmethod
    def _required_env(name: str, allow_empty: bool = False) -> str:
        if name not in os.environ or (not allow_empty and os.environ[name] == ""):
            raise RuntimeError(
                f"Missing environment variable {name}. "
                "Set DATABASE_URL or define DB_USER and DB_PASSWORD."
            )
        return os.environ[name]

    def _build_url(self):
        if self._database_url:
            return self._database_url

        return URL.create(
            self._driver,
            username=self._username,
            password=self._password,
            host=self._host,
            port=self._port,
            database=self._dbname,
            query={"charset": "utf8mb4"},
        )

    @property
    def session(self):
        return self._session_factory()

    def disconnect(self):
        self._session_factory.remove()
        self.engine.dispose()
        DatabaseConnection._instance = None


JOBS_ID_MODEL_BY_TABLE = {
    "hosts": Host,
    "host_web_app": HostWebApp,
    "crawl_page": CrawlPage,
    "crawl_page_details": CrawlPageDetails,
    "sqli_detector": SqliDetector,
    "sqli_exploit": SqliExploit,
    "sqli_exploit_tables": SqliExploitTables,
    "sqli_exploit_columns": SqliExploitColumns,
}


def now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def to_dict(obj) -> dict:
    return {attr.key: getattr(obj, attr.key) for attr in inspect(obj).mapper.column_attrs}


def json_list(value) -> list:
    try:
        parsed = json.loads(value) if isinstance(value, str) else value
        return parsed if isinstance(parsed, list) else []
    except Exception:
        return []


def json_to_text(value) -> str:
    if not value:
        return ""
    try:
        parsed = json.loads(value) if isinstance(value, str) else value
        if isinstance(parsed, list):
            return ", ".join(str(item) for item in parsed)
        if isinstance(parsed, dict):
            return ", ".join(f"{key}: {val}" for key, val in parsed.items())
        return str(parsed)
    except Exception:
        return str(value)


def page_status(row: dict) -> str:
    if row.get("exploit_count", 0) > 0:
        return "exploited"
    if row.get("has_discarded") and not row.get("has_pending_vuln"):
        return "discarded"
    if row.get("max_vulnerable") is True or row.get("max_vulnerable") == 1:
        return "vulnerable"
    if row.get("max_vulnerable") is False or row.get("max_vulnerable") == 0:
        return "safe"
    if row.get("page_state") == "done":
        return "discarded"
    return "pending"


class DatabaseCore:
    """Session access + generic CRUD helpers shared by every domain mixin."""

    _db = None

    @classmethod
    def _session(cls):
        if cls._db is None:
            cls._db = DatabaseConnection.get_instance()
        session = cls._db.session
        # The scoped_session is reused for the whole life of the process (the
        # Web API keeps it open across requests). Under MySQL's default
        # REPEATABLE READ isolation, the first SELECT pins a snapshot that
        # persists until an explicit COMMIT/ROLLBACK, so a long-lived process
        # would keep re-reading the data as of its very first query and never
        # see rows committed afterwards by other connections (CLI scripts).
        # Closing out any leftover transaction here gives every call to
        # _session() a fresh snapshot. If the previous call left the session
        # in a "must rollback" state (e.g. a failed flush/IntegrityError),
        # commit() itself raises — roll back instead so the session heals
        # and future calls don't fail forever because of one bad write.
        try:
            session.commit()
        except Exception:
            session.rollback()
        return session

    @classmethod
    def disconnect(cls):
        if cls._db is not None:
            cls._db.disconnect()
        cls._db = None

    @staticmethod
    def _try(action, fallback=None):
        try:
            return action()
        except Exception as exc:
            print(f"Database error: {exc}")
            return fallback

    @classmethod
    def _resolve_jobs_id(cls, table: str, row_id: int):
        model = JOBS_ID_MODEL_BY_TABLE.get(table)
        if model is None:
            return None
        row = cls._session().get(model, row_id)
        return getattr(row, "jobs_id", None) if row else None

    @classmethod
    def _insert(cls, model_cls, /, **fields):
        session = cls._session()
        try:
            obj = model_cls(**fields)
            session.add(obj)
            session.flush()
            new_id = obj.id
            session.commit()
            return new_id
        except Exception:
            session.rollback()
            raise

    @classmethod
    def _update(cls, model_cls, row_id, /, **fields) -> int:
        session = cls._session()
        try:
            obj = session.get(model_cls, row_id)
            if obj is None:
                return 0
            for key, value in fields.items():
                setattr(obj, key, value)
            session.commit()
            return 1
        except Exception:
            session.rollback()
            raise

    @classmethod
    def _find_one(cls, model_cls, /, **where):
        stmt = select(model_cls)
        for key, value in where.items():
            stmt = stmt.where(getattr(model_cls, key) == value)
        obj = cls._session().scalars(stmt.limit(1)).first()
        return to_dict(obj) if obj else None

    @classmethod
    def _find_one_ordered(cls, model_cls, order_by):
        rows = cls._find_many(model_cls, order_by=order_by, limit=1)
        return rows[0] if rows else None

    @classmethod
    def _find_many(cls, model_cls, /, order_by=None, limit=None, **where) -> list:
        stmt = select(model_cls)
        for key, value in where.items():
            stmt = stmt.where(getattr(model_cls, key) == value)
        if order_by is not None:
            order_by = order_by if isinstance(order_by, (list, tuple)) else [order_by]
            stmt = stmt.order_by(*order_by)
        if limit:
            stmt = stmt.limit(limit)
        return [to_dict(o) for o in cls._session().scalars(stmt).all()]

    @classmethod
    def _list_rows(cls, model_cls, /, job_id: int = None, order_by=None, limit: int = None) -> list:
        stmt = select(model_cls)
        if job_id is not None:
            stmt = stmt.where(model_cls.jobs_id == job_id)
        if order_by is not None:
            order_by = order_by if isinstance(order_by, (list, tuple)) else [order_by]
            stmt = stmt.order_by(*order_by)
        if limit is not None:
            stmt = stmt.limit(limit)
        return [to_dict(row) for row in cls._session().scalars(stmt).all()]

    @classmethod
    def _rows(cls, result) -> list:
        return [dict(row) for row in result.mappings().all()]

    @classmethod
    def _latest_job_id(cls):
        job = cls._session().scalars(select(Job).order_by(Job.id.desc()).limit(1)).first()
        return job.id if job else None

    @classmethod
    def _job_id_for_page(cls, crawl_page_id: int):
        return cls._session().execute(
            select(Host.jobs_id)
            .select_from(CrawlPage)
            .join(HostWebApp, CrawlPage.web_app_id == HostWebApp.id)
            .join(Host, HostWebApp.host_id == Host.id)
            .where(CrawlPage.id == crawl_page_id)
        ).scalar()

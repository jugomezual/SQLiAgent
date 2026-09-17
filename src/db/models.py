"""SQLAlchemy 2.0 ORM models for the application database."""

from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from sqlalchemy import Boolean, DateTime, Enum, ForeignKey, Integer, String, Text, TIMESTAMP, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class Job(Base):
    __tablename__ = "jobs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    type: Mapped[Optional[str]] = mapped_column(Enum("Normal", "IA"), default="Normal")
    model: Mapped[Optional[str]] = mapped_column(String(255))
    timestamp: Mapped[Optional[datetime]] = mapped_column(TIMESTAMP, server_default=func.current_timestamp())
    depth: Mapped[int] = mapped_column(Integer, nullable=False, default=4)
    comment: Mapped[Optional[str]] = mapped_column(String(500))
    target_url: Mapped[Optional[str]] = mapped_column(String(500))
    state: Mapped[str] = mapped_column(Enum("running", "done", "error"), nullable=False, default="running")
    error_message: Mapped[Optional[str]] = mapped_column(Text)
    finished_at: Mapped[Optional[datetime]] = mapped_column(TIMESTAMP)

    hosts: Mapped[List["Host"]] = relationship(back_populates="job", cascade="all, delete-orphan")


class Host(Base):
    __tablename__ = "hosts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    jobs_id: Mapped[int] = mapped_column(Integer, ForeignKey("jobs.id", ondelete="CASCADE"), nullable=False)
    target_host: Mapped[str] = mapped_column(String(255), nullable=False)
    state: Mapped[Optional[str]] = mapped_column(Enum("pending", "running", "error", "done"), default="pending")
    error_message: Mapped[Optional[str]] = mapped_column(Text)
    log: Mapped[Optional[str]] = mapped_column(Text)
    timestamp: Mapped[Optional[datetime]] = mapped_column(TIMESTAMP, server_default=func.current_timestamp())

    job: Mapped["Job"] = relationship(back_populates="hosts")
    web_apps: Mapped[List["HostWebApp"]] = relationship(back_populates="host", cascade="all, delete-orphan")
    nmap_results: Mapped[List["HostNmap"]] = relationship(back_populates="host", cascade="all, delete-orphan")


class HostNmap(Base):
    __tablename__ = "host_nmap"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    host_id: Mapped[int] = mapped_column(Integer, ForeignKey("hosts.id", ondelete="CASCADE"), nullable=False)
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    nmap_state: Mapped[Optional[str]] = mapped_column(String(50))
    nmap_service: Mapped[Optional[str]] = mapped_column(String(100))
    nmap_version: Mapped[Optional[str]] = mapped_column(String(255))
    state: Mapped[Optional[str]] = mapped_column(Enum("pending", "running", "error", "done"), default="pending")
    timestamp: Mapped[Optional[datetime]] = mapped_column(TIMESTAMP, server_default=func.current_timestamp())
    jobs_id: Mapped[Optional[int]] = mapped_column(Integer)

    host: Mapped["Host"] = relationship(back_populates="nmap_results")


class HostWebApp(Base):
    __tablename__ = "host_web_app"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    host_id: Mapped[int] = mapped_column(Integer, ForeignKey("hosts.id", ondelete="CASCADE"), nullable=False)
    target_url: Mapped[str] = mapped_column(String(1000), nullable=False)
    http_status: Mapped[Optional[int]] = mapped_column(Integer)
    redirect_location: Mapped[Optional[str]] = mapped_column(String(1000))
    technologies_json: Mapped[Optional[str]] = mapped_column(Text)
    cookies_json: Mapped[Optional[str]] = mapped_column(Text)
    headers_json: Mapped[Optional[str]] = mapped_column(Text)
    uncommon_headers_json: Mapped[Optional[str]] = mapped_column(Text)
    state: Mapped[Optional[str]] = mapped_column(Enum("pending", "running", "error", "done"), default="pending")
    error_message: Mapped[Optional[str]] = mapped_column(Text)
    log: Mapped[Optional[str]] = mapped_column(Text)
    timestamp: Mapped[Optional[datetime]] = mapped_column(TIMESTAMP, server_default=func.current_timestamp())
    jobs_id: Mapped[Optional[int]] = mapped_column(Integer)

    host: Mapped["Host"] = relationship(back_populates="web_apps")
    crawl_pages: Mapped[List["CrawlPage"]] = relationship(back_populates="web_app", cascade="all, delete-orphan")
    nikto_results: Mapped[List["HostWebAppNikto"]] = relationship(back_populates="web_app", cascade="all, delete-orphan")


class HostWebAppNikto(Base):
    __tablename__ = "host_web_app_nikto"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    web_app_id: Mapped[int] = mapped_column(Integer, ForeignKey("host_web_app.id", ondelete="CASCADE"), nullable=False)
    url: Mapped[str] = mapped_column(String(1000), nullable=False)
    timestamp: Mapped[Optional[datetime]] = mapped_column(TIMESTAMP, server_default=func.current_timestamp())
    jobs_id: Mapped[Optional[int]] = mapped_column(Integer)

    web_app: Mapped["HostWebApp"] = relationship(back_populates="nikto_results")


class CrawlPage(Base):
    __tablename__ = "crawl_page"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    web_app_id: Mapped[int] = mapped_column(Integer, ForeignKey("host_web_app.id", ondelete="CASCADE"), nullable=False)
    base_url: Mapped[Optional[str]] = mapped_column(String(1000))
    url: Mapped[str] = mapped_column(String(1000), nullable=False)
    is_admin_path: Mapped[Optional[bool]] = mapped_column(Boolean, default=False)
    has_login_form: Mapped[Optional[bool]] = mapped_column(Boolean, default=False)
    has_register_form: Mapped[Optional[bool]] = mapped_column(Boolean, default=False)
    has_search_form: Mapped[Optional[bool]] = mapped_column(Boolean, default=False)
    has_upload_form: Mapped[Optional[bool]] = mapped_column(Boolean, default=False)
    has_form_without_csrf: Mapped[Optional[bool]] = mapped_column(Boolean, default=False)
    has_errors: Mapped[Optional[bool]] = mapped_column(Boolean, default=False)
    has_parametres_url: Mapped[Optional[bool]] = mapped_column(Boolean, default=False)
    is_referred_robots: Mapped[Optional[bool]] = mapped_column(Boolean, default=False)
    has_get_params: Mapped[Optional[bool]] = mapped_column(Boolean, default=False)
    has_post_params: Mapped[Optional[bool]] = mapped_column(Boolean, default=False)
    priority_score: Mapped[Optional[int]] = mapped_column(Integer)
    priority_level: Mapped[Optional[str]] = mapped_column(Enum("low", "medium", "high"))
    state: Mapped[Optional[str]] = mapped_column(
        Enum("pending", "pending_score", "running", "running_score", "error", "done"),
        default="pending",
    )
    error_message: Mapped[Optional[str]] = mapped_column(Text)
    log: Mapped[Optional[str]] = mapped_column(Text)
    timestamp: Mapped[Optional[datetime]] = mapped_column(TIMESTAMP, server_default=func.current_timestamp())
    jobs_id: Mapped[Optional[int]] = mapped_column(Integer)
    depth: Mapped[Optional[int]] = mapped_column(Integer)

    web_app: Mapped["HostWebApp"] = relationship(back_populates="crawl_pages")
    details: Mapped[Optional["CrawlPageDetails"]] = relationship(
        back_populates="crawl_page", uselist=False, cascade="all, delete-orphan"
    )
    sqli_detections: Mapped[List["SqliDetector"]] = relationship(
        back_populates="crawl_page",
        cascade="all, delete-orphan",
    )


class CrawlPageDetails(Base):
    __tablename__ = "crawl_page_details"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    crawl_page_id: Mapped[int] = mapped_column(Integer, ForeignKey("crawl_page.id", ondelete="CASCADE"), nullable=False)
    forms_json: Mapped[Optional[str]] = mapped_column(Text)
    standalone_inputs_json: Mapped[Optional[str]] = mapped_column(Text)
    url_params_json: Mapped[Optional[str]] = mapped_column(Text)
    error_details_json: Mapped[Optional[str]] = mapped_column(Text)
    state: Mapped[Optional[str]] = mapped_column(Enum("pending", "running", "error", "done"), default="pending")
    timestamp: Mapped[Optional[datetime]] = mapped_column(TIMESTAMP, server_default=func.current_timestamp())
    jobs_id: Mapped[Optional[int]] = mapped_column(Integer)

    crawl_page: Mapped["CrawlPage"] = relationship(back_populates="details")


class SqliDetector(Base):
    __tablename__ = "sqli_detector"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    crawl_page_id: Mapped[int] = mapped_column(Integer, ForeignKey("crawl_page.id", ondelete="CASCADE"), nullable=False)
    target_url: Mapped[str] = mapped_column(String(1000), nullable=False)
    method: Mapped[str] = mapped_column(Enum("GET", "POST"), nullable=False)
    is_vulnerable: Mapped[Optional[bool]] = mapped_column(Boolean, default=False)
    injection_points_json: Mapped[Optional[str]] = mapped_column(Text)
    injection_types_json: Mapped[Optional[str]] = mapped_column(Text)
    dbms: Mapped[Optional[str]] = mapped_column(String(50))
    error_message: Mapped[Optional[str]] = mapped_column(Text)
    state: Mapped[Optional[str]] = mapped_column(
        Enum("pending", "running", "error", "done", "discarded"),
        default="pending",
    )
    timestamp: Mapped[Optional[datetime]] = mapped_column(TIMESTAMP, server_default=func.current_timestamp())
    jobs_id: Mapped[Optional[int]] = mapped_column(Integer)

    crawl_page: Mapped["CrawlPage"] = relationship(back_populates="sqli_detections")
    exploits: Mapped[List["SqliExploit"]] = relationship(back_populates="detector", cascade="all, delete-orphan")


class SqliExploit(Base):
    __tablename__ = "sqli_exploit"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    sqli_detector_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("sqli_detector.id", ondelete="CASCADE"),
        nullable=False,
    )
    databases_json: Mapped[Optional[str]] = mapped_column(Text)
    total_databases: Mapped[Optional[int]] = mapped_column(Integer, default=0)
    state: Mapped[Optional[str]] = mapped_column(Enum("pending", "running", "error", "done"), default="pending")
    error_message: Mapped[Optional[str]] = mapped_column(Text)
    log: Mapped[Optional[str]] = mapped_column(Text)
    timestamp: Mapped[Optional[datetime]] = mapped_column(TIMESTAMP, server_default=func.current_timestamp())
    jobs_id: Mapped[Optional[int]] = mapped_column(Integer)

    detector: Mapped["SqliDetector"] = relationship(back_populates="exploits")
    tables: Mapped[List["SqliExploitTables"]] = relationship(back_populates="exploit", cascade="all, delete-orphan")


class SqliExploitTables(Base):
    __tablename__ = "sqli_exploit_tables"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    sqli_exploit_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("sqli_exploit.id", ondelete="CASCADE"),
        nullable=False,
    )
    db_name: Mapped[str] = mapped_column(String(255), nullable=False)
    tables_json: Mapped[Optional[str]] = mapped_column(Text)
    state: Mapped[Optional[str]] = mapped_column(Enum("pending", "running", "error", "done"), default="pending")
    timestamp: Mapped[Optional[datetime]] = mapped_column(TIMESTAMP, server_default=func.current_timestamp())
    jobs_id: Mapped[Optional[int]] = mapped_column(Integer)

    exploit: Mapped["SqliExploit"] = relationship(back_populates="tables")
    columns: Mapped[List["SqliExploitColumns"]] = relationship(
        back_populates="tables_ref",
        cascade="all, delete-orphan",
    )


class SqliExploitColumns(Base):
    __tablename__ = "sqli_exploit_columns"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    sqli_exploit_tables_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("sqli_exploit_tables.id", ondelete="CASCADE"),
        nullable=False,
    )
    table_name: Mapped[str] = mapped_column(String(255), nullable=False)
    columns_json: Mapped[Optional[str]] = mapped_column(Text)
    state: Mapped[Optional[str]] = mapped_column(Enum("pending", "running", "error", "done"), default="pending")
    timestamp: Mapped[Optional[datetime]] = mapped_column(TIMESTAMP, server_default=func.current_timestamp())
    jobs_id: Mapped[Optional[int]] = mapped_column(Integer)

    tables_ref: Mapped["SqliExploitTables"] = relationship(back_populates="columns")
    data_rows: Mapped[List["SqliExploitData"]] = relationship(back_populates="columns_ref", cascade="all, delete-orphan")


class SqliExploitData(Base):
    __tablename__ = "sqli_exploit_data"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    sqli_exploit_columns_id: Mapped[Optional[int]] = mapped_column(
        Integer,
        ForeignKey("sqli_exploit_columns.id", ondelete="CASCADE"),
    )
    db_name: Mapped[str] = mapped_column(String(255), nullable=False)
    table_name: Mapped[str] = mapped_column(String(255), nullable=False)
    data_json: Mapped[Optional[str]] = mapped_column(Text)
    dump_success: Mapped[Optional[bool]] = mapped_column(Boolean, default=True)
    timestamp: Mapped[Optional[datetime]] = mapped_column(TIMESTAMP, server_default=func.current_timestamp())
    jobs_id: Mapped[Optional[int]] = mapped_column(Integer)

    columns_ref: Mapped[Optional["SqliExploitColumns"]] = relationship(back_populates="data_rows")


class ActivityLog(Base):
    __tablename__ = "activity_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    jobs_id: Mapped[int] = mapped_column(Integer, ForeignKey("jobs.id", ondelete="CASCADE"), nullable=False)
    event_type: Mapped[str] = mapped_column(
        Enum("host_identified", "webapp_identified", "vulnerable_page_found", "dbs_obtained"),
        nullable=False,
    )
    reference_id: Mapped[int] = mapped_column(Integer, nullable=False)
    reference_table: Mapped[str] = mapped_column(String(30), nullable=False)
    details_json: Mapped[str] = mapped_column(Text, nullable=False)
    timestamp: Mapped[Optional[datetime]] = mapped_column(DateTime, server_default=func.current_timestamp())


MODEL_BY_TABLE = {
    cls.__tablename__: cls
    for cls in (
        ActivityLog,
        CrawlPage,
        CrawlPageDetails,
        Host,
        HostNmap,
        HostWebApp,
        Job,
        SqliDetector,
        SqliExploit,
        SqliExploitColumns,
        SqliExploitData,
        SqliExploitTables,
    )
}

"""Application-facing DatabaseManager: composed from one mixin per domain.

To add a new domain of DB methods: create db/domains/<name>.py with a class
that subclasses DatabaseCore (see db/base.py), then list it below.
"""

from .base import DatabaseConnection
from .domains import CrawlMixin, ExploitMixin, JobsMixin, ReportingMixin, SqliMixin, StatusMixin

__all__ = ["DatabaseConnection", "DatabaseManager"]


class DatabaseManager(JobsMixin, CrawlMixin, SqliMixin, ExploitMixin, ReportingMixin, StatusMixin):
    """Talks to the ORM session directly - no repository layer, one hop per call."""

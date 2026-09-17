"""One mixin per domain, each extending DatabaseCore (db/base.py).

To add a new domain: create db/domains/<name>.py with a class that
subclasses DatabaseCore, then list it here and in db/database.py.
"""

from .crawl import CrawlMixin
from .exploit import ExploitMixin
from .jobs import JobsMixin
from .reporting import ReportingMixin
from .sqli import SqliMixin
from .status import StatusMixin

__all__ = [
    "CrawlMixin",
    "ExploitMixin",
    "JobsMixin",
    "ReportingMixin",
    "SqliMixin",
    "StatusMixin",
]

#!/usr/bin/env python3
"""WebCrawler.py - Nikto Discovery + Complete Crawling with SQLi Testing"""
import sys, requests, re, ssl, subprocess, time, signal, json, os, traceback
from urllib.parse import urlparse, urljoin, parse_qs, urlunparse
from bs4 import BeautifulSoup
from collections import deque
from dotenv import load_dotenv
from requests.adapters import HTTPAdapter

if __name__ == "__main__":
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

load_dotenv()

from db.database import DatabaseManager

from core import ModuleBase, ModuleResult
from core.scope import assert_in_scope
from tools import NiktoTool
from utils.common import url_pattern, _PATTERN_PAGINATION_PARAMS as PAGINATION_LIKE_PARAMS

try:
    from playwright.sync_api import sync_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False
    sync_playwright = None

requests.packages.urllib3.disable_warnings()


def _env_int(name, default):
    try:
        return int(os.getenv(name, default))
    except (TypeError, ValueError):
        return default


def _env_bool(name, default):
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() not in ("0", "false", "no", "off", "")


def _env_credential_pairs(name, default):
    raw = os.getenv(name, default)
    pairs = []
    for chunk in raw.split(","):
        chunk = chunk.strip()
        if not chunk or ":" not in chunk:
            continue
        user, _, password = chunk.partition(":")
        pairs.append((user, password))
    return pairs


# Crawler tuning, overridable via .env — see .env for descriptions.
CRAWLER_MAX_URL_PATTERN_VARIANTS = _env_int("CRAWLER_MAX_URL_PATTERN_VARIANTS", 5)
CRAWLER_MAX_REDIRECT_HOPS = _env_int("CRAWLER_MAX_REDIRECT_HOPS", 10)
CRAWLER_LEGACY_TLS = _env_bool("CRAWLER_LEGACY_TLS", True)

# Common default credentials tried against an HTTP Basic Auth challenge (401
# with a WWW-Authenticate: Basic header) — e.g. Java WebGoat gates its entire
# app behind Basic Auth with guest/guest, so without this every WebGoat page
# beyond the login challenge is invisible to the crawler. Testing well-known
# default credentials is standard recon, not exploitation. Override via
# CRAWLER_BASIC_AUTH_CREDENTIALS in .env (comma-separated user:password pairs).
CRAWLER_BASIC_AUTH_CREDENTIALS = _env_credential_pairs(
    "CRAWLER_BASIC_AUTH_CREDENTIALS",
    "guest:guest,webgoat:webgoat,admin:admin,tomcat:tomcat,admin:password"
)


# ============================================================================
# TIMEOUT HANDLER
# ============================================================================

class TimeoutError(Exception):
    pass

def timeout_handler(signum, frame):
    raise TimeoutError("Operation timed out")


class LegacyTLSAdapter(HTTPAdapter):
    """Some scan targets (e.g. old OWASP-BWA VMs running Apache/OpenSSL 0.9.8k)
    only speak TLSv1.0/SSLv3. Modern OpenSSL (3.x) refuses that handshake by
    default ("unsupported protocol"/"no protocols available"), even with
    verify=False, because it's a protocol-negotiation failure, not a cert
    validation one. This adapter builds an SSLContext with the security level
    lowered so those legacy handshakes are still allowed, instead of every
    https:// request to such hosts hard-failing as a "fetch error"."""

    def init_poolmanager(self, *args, **kwargs):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_ciphers('DEFAULT@SECLEVEL=0')
        ctx.minimum_version = ssl.TLSVersion.TLSv1
        kwargs['ssl_context'] = ctx
        return super().init_poolmanager(*args, **kwargs)

    def proxy_manager_for(self, *args, **kwargs):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_ciphers('DEFAULT@SECLEVEL=0')
        ctx.minimum_version = ssl.TLSVersion.TLSv1
        kwargs['ssl_context'] = ctx
        return super().proxy_manager_for(*args, **kwargs)


class WebCrawler(ModuleBase):
    """Nikto discovery + complete crawling with SQLi testing (migrated to BaseModule)."""

    slug = "web_crawler"

    # How many *unproductive* URLs sharing the same path+param-names pattern
    # get crawled before later ones are treated as duplicates (see
    # _record_pattern_attempt). >1 so that e.g. ?bID=1 vs ?bID=2 (or a blank
    # vs a filled-in value) aren't collapsed into "already visited" after
    # only the first is seen, while still bounding runaway growth on params
    # with hundreds of legitimate values (pagination, project/product IDs,
    # ...). Configurable via CRAWLER_MAX_URL_PATTERN_VARIANTS in .env.
    MAX_URL_PATTERN_VARIANTS = CRAWLER_MAX_URL_PATTERN_VARIANTS

    ADMIN_KEYWORDS = ['admin', 'administrator', 'administrador', 'administracion', 'panel', 'dashboard',
                      'control', 'manage', 'manager', 'backend', 'backoffice', 'cms', 'wp-admin',
                      'phpmyadmin', 'cpanel', 'webadmin', 'sysadmin', 'root', 'staff', 'moderator',
                      'mod', 'super', 'master', 'owner']
    SECURITY_HEADERS = ['User-Agent', 'X-Frame-Options', 'Referer', 'X-Forwarded-For', 'X-Real-IP']
    ERROR_PATTERNS = {
        'SQL': [r'SQL syntax.*MySQL', r'Warning.*mysql_.*', r'MySQLSyntaxErrorException', r'valid MySQL result',
                r'PostgreSQL.*ERROR', r'Warning.*pg_.*', r'valid PostgreSQL result', r'Npgsql\.',
                r'Driver.*SQL.*Server', r'OLE DB.*SQL Server', r'SQLServer JDBC Driver', r'SqlClient\.',
                r'Oracle error', r'Oracle.*Driver', r'Warning.*oci_.*', r'Warning.*ora_.*',
                r'SQLite.*error', r'sqlite3\.', r'SQLiteException', r'Microsoft Access Driver',
                r'JET Database Engine', r'Access Database Engine', r'Unclosed quotation mark',
                r'quoted string not properly terminated', r'You have an error in your SQL syntax',
                r'Error executing query', r'mysql_fetch', r'SQL error', r'syntax error'],
        'Database': [r'database error', r'database connection', r'connection.*failed', r'could not connect',
                     r'unable to connect', r"can\'t connect to.*server", r'Connection refused',
                     r'SQLSTATE\[.*\]', r'DB\:\:.*Error', r'Doctrine\\DBAL'],
        'Stack Trace': [r'Stack trace:', r'Traceback \(most recent call last\):', r'at.*\(.*\.java:\d+\)',
                        r'\.php on line \d+', r'\.asp on line \d+', r'\.aspx\.cs:line \d+',
                        r'Exception.*in.*line', r'Fatal error:', r'Warning:.*in.*on line', r'Parse error:',
                        r'Notice:.*in.*on line', r'Undefined.*in.*on line', r'Call to undefined']
    }
    FORM_PATTERNS = {
        'LOGIN': ['login', 'signin', 'log-in', 'sign-in', 'iniciar sesión', 'ingresar'],
        'REGISTER': ['register', 'signup', 'sign-up', 'registro', 'crear cuenta'],
        'SEARCH': ['search', 'buscar', 'busqueda'],
        'CONTACT': ['contact', 'contacto', 'mensaje', 'email'],
        'COMMENT': ['comment', 'comentario', 'reply', 'respuesta'],
        'UPLOAD': ['upload', 'subir', 'file', 'archivo'],
        'PAYMENT': ['payment', 'pago', 'checkout', 'compra', 'cart', 'carrito']
    }
    CSRF_PATTERNS = ['csrf', 'token', '_token', 'authenticity_token', 'csrfmiddlewaretoken',
                     '__requestverificationtoken', 'anti-csrf', 'xsrf', '_csrf_token', 'security_token']
    AJAX_PATTERNS = {'$.ajax': 'jQuery', '$.post': 'jQuery', '$.get': 'jQuery',
                     'fetch(': 'Fetch API', 'XMLHttpRequest': 'XMLHttpRequest', 'axios.': 'Axios'}

    def __init__(self, start_url, max_depth=3, delay=0.5, use_render=False, web_app_id=None, max_pages=None):
        super().__init__(target_id=web_app_id)
        self.nikto = NiktoTool()
        self.skip_nikto = False

        # One requests.Session per top-level app path (/ghost/, /mutillidae/,
        # /webgoat.net/, ...), not one shared across the whole crawl and not a
        # fresh one per fetch. Whole-crawl sharing let one page's cookie (e.g.
        # Mutillidae's "toggle-security" link) hang every later request across
        # every unrelated app; a fresh session per fetch (the previous fix)
        # went too far the other way and threw away legitimate login state -
        # e.g. Ghost sets a session cookie on any login-form submission
        # (valid or not), and our own test_form_for_errors submits exactly
        # that kind of form while crawling, so the very next fetch needs that
        # cookie to still see the gated content it unlocked. Scoping the
        # session per app keeps a hang/poison contained to its own app while
        # letting that kind of legitimate cross-page session state persist
        # within it. See _session_for(). Each session mounts LegacyTLSAdapter
        # so https:// targets with ancient TLS-only servers don't hard-fail
        # every request; disable via CRAWLER_LEGACY_TLS=false in .env if a
        # target's real cert/TLS setup should be validated normally instead.
        self._app_sessions = {}

        # Normalize https → http to avoid crawling both schemes as separate pages
        if start_url.startswith('https://'):
            start_url = 'http://' + start_url[8:]
        parsed = urlparse(start_url)
        self.start_url, self.max_depth, self.delay = start_url, max_depth, delay
        self.visited, self.pages_data, self.admin_paths, self.nikto_discovered = set(), [], [], []
        self.visited_url_patterns = {}  # normalized path+param-names -> count of variants crawled so far
        self.visited_param_values = set()  # (param_name, param_value) pairs already sent, for _repeats_known_action
        self.current_depth = 0
        self.base_netloc = parsed.netloc
        # base_path should be the DIRECTORY portion of the start URL, never a filename.
        _raw_path = parsed.path.rstrip('/')
        _last_segment = _raw_path.split('/')[-1] if _raw_path else ''
        if '.' in _last_segment:
            # Last segment looks like a file (index.jsp, index.php …) — use parent dir
            self.base_path = _raw_path.rsplit('/', 1)[0]
        else:
            self.base_path = _raw_path
        self.base_url, self.robots_paths = f"{parsed.scheme}://{parsed.netloc}", []
        self.tested_url_bases = {}  # Cache: {url_base: {param_name: test_result}}
        self.use_render_flag = use_render  # Store flag to adjust scope behavior
        self.web_app_id = web_app_id  # Database web_app_id for saving crawl results

        self.use_render = bool(use_render) and PLAYWRIGHT_AVAILABLE
        self.playwright = None
        self.browser = None
        self.context = None

        if use_render and not PLAYWRIGHT_AVAILABLE:
            print("⚠️  Playwright not available. Install with: pip install playwright && playwright install chromium")
        elif self.use_render:
            try:
                self.playwright = sync_playwright().start()
                # Try Playwright's bundled Chromium first, fall back to system if not available
                try:
                    self.browser = self.playwright.chromium.launch(headless=True)
                    print("✅ JS rendering mode activated (Playwright Chromium)")
                except Exception:
                    # Fall back to system Chromium
                    import os
                    chromium_paths = ['/usr/bin/chromium', '/usr/bin/chromium-browser', '/snap/bin/chromium']
                    chromium_path = next((path for path in chromium_paths if os.path.exists(path)), None)
                    if chromium_path:
                        self.browser = self.playwright.chromium.launch(headless=True, executable_path=chromium_path)
                        print(f"✅ JS rendering mode activated (System Chromium: {chromium_path})")
                    else:
                        raise Exception("Chromium not found. Install with: playwright install chromium")

                self.context = self.browser.new_context(
                    viewport={'width': 1920, 'height': 1080},
                    user_agent='Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
                )
            except Exception as e:
                print(f"⚠️  Error initializing Playwright: {e}")
                self.use_render = False
                if self.browser:
                    self.browser.close()
                if self.playwright:
                    self.playwright.stop()

    def is_page_interesting(self, page_data):
        """Determines if a page has testable elements (to mark it as 'pending')"""
        forms = page_data.get('forms', [])
        url_params = page_data.get('url_parameters', [])

        # Check forms with testable fields
        testable_forms = []
        for form in forms:
            testable_fields = [f for f in form.get('fields', [])
                               if f.get('name') and f.get('type') not in ['button', 'reset', 'image', 'submit']]
            if testable_fields:
                testable_forms.append(form)

        # Check URL parameters susceptible to SQLi
        sqli_params = []
        for param in url_params:
            param_name = param.get('name', '')
            param_value = param.get('value', '')

            # Patterns of typically vulnerable parameters
            vulnerable_pattern = re.match(
                r'^(id|.*_id|id_.*|.*id|user|num(ero)?|code|codigo|key|.*_key|ref(erencia)?|item|cat(egoria)?|prod(ucto)?|article|post|uid|pid|cid|gid|aid)$',
                param_name, re.IGNORECASE
            )

            # Exclude parameters that are clearly for includes/routing
            is_file_include = re.search(r'\.(php|html|htm|asp|aspx|jsp)$', param_value, re.IGNORECASE)
            is_routing_param = param_name.lower() in ['page', 'view', 'action', 'do', 'task', 'mode', 'section']

            # Only add if it matches vulnerable pattern AND is not include/routing
            if vulnerable_pattern and not is_file_include and not is_routing_param:
                sqli_params.append(param)

        if testable_forms or sqli_params:
            return True

        return False

    def _url_pattern(self, url):
        """Returns a canonical key: scheme+host+path + sorted param NAMES (no values).
        Used to detect duplicate URLs that differ only in parameter values.
        Exception: routing params (value ends in .php/.html) are kept with their value.
        Shared with reporting (db/domains/reporting.py), which groups SQLi
        findings that only differ by parameter value into one vulnerability
        using this same key — see utils/common.url_pattern.
        """
        return url_pattern(url)

    @staticmethod
    def _normalize_scheme(url):
        """Rewrites https:// to http:// so both schemes are treated as the same page."""
        if url.startswith('https://'):
            return 'http://' + url[8:]
        return url

    @staticmethod
    def _app_key(url):
        """First path segment identifies which app a URL belongs to (e.g.
        /ghost/index.php and /ghost/iframe.php are both 'ghost'), used to
        scope session/cookie state — see _session_for()."""
        segments = [s for s in urlparse(url).path.split('/') if s]
        return segments[0].lower() if segments else ''

    def _session_for(self, url):
        """The requests.Session for url's app (see _app_key), created lazily
        with LegacyTLSAdapter mounted. Reused across all requests to that
        app so app-scoped login state persists; never shared with other
        apps, so one app's session getting poisoned/hung can't affect any
        other app's testing."""
        key = self._app_key(url)
        session = self._app_sessions.get(key)
        if session is None:
            session = requests.Session()
            if CRAWLER_LEGACY_TLS:
                session.mount('https://', LegacyTLSAdapter())
            self._app_sessions[key] = session
        return session

    def _record_pattern_attempt(self, pattern, found_new_links):
        """Charges one unit of MAX_URL_PATTERN_VARIANTS budget to `pattern`,
        but only if this variant was unproductive (fetch failed, or the page
        led to no in-scope URL we hadn't already seen). A variant that does
        surface new links is free — it's evidence the parameter value is
        driving real content differences, not just noise, so it shouldn't
        push the pattern toward being marked fully seen."""
        if not found_new_links:
            self.visited_url_patterns[pattern] = self.visited_url_patterns.get(pattern, 0) + 1

    def _repeats_known_action(self, url):
        """True if `url` carries a non-pagination query param whose literal
        value has already been sent to the server on some *other* URL during
        this crawl. Catches one-shot admin/action links repeated identically
        across many otherwise-different pages — e.g. Mutillidae exposes
        do=toggle-security, do=toggle-enforce-ssl, do=toggle-hints in a
        footer widget present on every single page, and following each of
        those on every page flips the app's own security level mid-crawl,
        hiding the very vulnerabilities being tested for on every page
        crawled afterwards.

        Deliberately narrower than MAX_URL_PATTERN_VARIANTS: that budget
        governs *value* variants of a parameter (?id=1 vs ?id=2 - distinct
        records, not duplicates) and is scoped per page= target, so it never
        catches this case (only 4 distinct 'do' values exist, well under the
        default budget of 5, and each page= value gets its own fresh budget).
        This check instead looks for a literal (name, value) pair recurring
        verbatim across different pages - the signature of a fixed action
        name, not a per-record identifier. Numeric values (id=1, id=2, ...)
        and pagination/routing params (page=, offset=, ...; already handled
        by url_pattern's own routing exception) are excluded so legitimate
        recurring identifiers are never suppressed.
        """
        for key, values in parse_qs(urlparse(url).query).items():
            if key.lower() in PAGINATION_LIKE_PARAMS:
                continue
            value = values[0] if values else ''
            if not value or value.isdigit():
                continue
            if (key.lower(), value.lower()) in self.visited_param_values:
                return True
        return False

    def _record_param_values(self, url):
        """Records url's non-pagination, non-numeric (name, value) query
        pairs as sent, for _repeats_known_action to catch on later pages."""
        for key, values in parse_qs(urlparse(url).query).items():
            if key.lower() in PAGINATION_LIKE_PARAMS:
                continue
            value = values[0] if values else ''
            if not value or value.isdigit():
                continue
            self.visited_param_values.add((key.lower(), value.lower()))

    def is_in_scope(self, url):
        """Checks if a URL is within the crawler's scope"""
        parsed = urlparse(url)
        # Same netloc is required always
        if parsed.netloc != self.base_netloc:
            return False

        # If using --render mode and base_path is nested (not root),
        # accept any path on same server (JS may generate links to root-level files)
        if self.use_render_flag and self.base_path and self.base_path != '/':
            return True

        # Standard behavior: path must start with base_path
        return parsed.path.rstrip('/').startswith(self.base_path)

    def run_nikto(self):
        """Discovers paths with Nikto (parsing in NiktoTool) and filters by scope."""
        print(f"\n{'='*80}\n🔍 PHASE 1: NIKTO - Path discovery\n{'='*80}")
        print(f"🚀 Running Nikto against {self.start_url}...\n")

        # The tool parses its output; the module applies its scope policy.
        candidates = self.nikto.discover(self.start_url)
        found_paths = []
        for url in candidates:
            url = self._normalize_scheme(url)
            if url and self.is_in_scope(url) and url not in found_paths:
                found_paths.append(url)

        self.nikto_discovered = found_paths
        print(f"✅ Nikto completed: {len(found_paths)} paths discovered\n")

        if self.web_app_id and found_paths:
            DatabaseManager.insert_nikto_results(self.web_app_id, found_paths)

    def check_robots_txt(self):
        """Searches and parses robots.txt"""
        robots_url = self.start_url.rstrip('/') + '/robots.txt'
        print(f"\n🤖 Checking robots.txt at {robots_url}...")

        try:
            response = self._session_for(robots_url).get(robots_url, timeout=10, verify=False)
            if response.status_code != 200:
                print(f"⚠️  robots.txt not found (HTTP {response.status_code})")
                return False

            print("✅ robots.txt found")
            disallow_paths, allow_paths, sitemaps = [], [], []

            for line in response.text.split('\n'):
                if not (line := line.strip()) or line.startswith('#'):
                    continue
                key, _, value = line.partition(':')
                if not (value := value.strip()):
                    continue

                key_lower = key.lower()
                if key_lower == 'disallow' and value != '/':
                    disallow_paths.append(value)
                elif key_lower == 'allow':
                    allow_paths.append(value)
                elif key_lower == 'sitemap':
                    sitemaps.append(value)

            self.robots_paths = {'disallow': disallow_paths, 'allow': allow_paths, 'sitemaps': sitemaps}
            print(f"   📍 Blocked: {len(disallow_paths)} | ✓ Allowed: {len(allow_paths)} | 🗺️  Sitemaps: {len(sitemaps)}")

            if disallow_paths:
                print("   Interesting blocked paths:")
                for path in disallow_paths[:10]:
                    print(f"      • {path}")
                    if self.is_admin_path(path) and self.is_in_scope(full_path := urljoin(self.base_url, path.rstrip('*'))):
                        self.admin_paths.append({'path': full_path, 'source': 'robots.txt'})

            if sitemaps:
                print("   Sitemaps found:")
                for sitemap in sitemaps:
                    print(f"      • {sitemap}")
            return True
        except:
            print("❌ Error accessing robots.txt")
            return False

    def is_admin_path(self, path):
        """Check if a path is an admin path, with special handling for phpMyAdmin"""
        path_lower = path.lower()

        # For phpMyAdmin, only detect the login page
        if 'phpmyadmin' in path_lower:
            # Check if it's the login page (root or index.php)
            # Match: /phpmyadmin, /phpmyadmin/, /phpmyadmin/index.php
            # Don't match: /phpmyadmin/db_structure.php, /phpmyadmin/server_status.php, etc.
            if re.match(r'.*/phpmyadmin/?(?:index\.php)?$', path_lower):
                return True
            return False

        # For other admin keywords, use the original logic
        return any(kw in path_lower for kw in self.ADMIN_KEYWORDS if kw != 'phpmyadmin')

    def fetch_page(self, url):
        # Session is scoped to url's app (see _session_for) — cookies persist
        # across all of that app's pages (needed for e.g. a login-form
        # submission's cookie to still apply on the next fetch) without
        # leaking into any other app's requests.
        session = self._session_for(url)
        try:
            r = session.get(url, timeout=15, verify=False, allow_redirects=False)
            # Follow redirects ourselves, but stop as soon as one points
            # outside scope: letting requests auto-follow into an external
            # host means that host's own failure (403, DNS, ...) sinks the
            # whole fetch, even though the in-scope page we actually wanted
            # responded fine. Keep the last in-scope response instead.
            # Scheme is deliberately NOT normalized here (unlike everywhere
            # else): a server that redirects http -> https to enforce SSL
            # (e.g. Mutillidae's "toggle-enforce-ssl") needs that https hop
            # actually taken, or normalizing it back to http bounces forever
            # between the two.
            hops = 0
            while r.is_redirect and hops < CRAWLER_MAX_REDIRECT_HOPS:
                location = r.headers.get('Location')
                if not location:
                    break
                next_url = urljoin(r.url, location)
                if urlparse(next_url).netloc != self.base_netloc:
                    break
                r = session.get(next_url, timeout=15, verify=False, allow_redirects=False)
                hops += 1

            # A Basic Auth challenge on an app we haven't already authenticated
            # to: try common default credentials (see
            # CRAWLER_BASIC_AUTH_CREDENTIALS) instead of giving up - e.g. Java
            # WebGoat gates its entire app behind guest/guest, and without this
            # every page past that 401 is invisible to the crawler. Testing
            # well-known default credentials is standard recon, not exploitation.
            if (r.status_code == 401 and session.auth is None
                    and 'basic' in r.headers.get('WWW-Authenticate', '').lower()):
                for cred_user, cred_password in CRAWLER_BASIC_AUTH_CREDENTIALS:
                    candidate = session.get(r.url, timeout=15, verify=False,
                                             allow_redirects=False, auth=(cred_user, cred_password))
                    if candidate.status_code != 401:
                        session.auth = (cred_user, cred_password)  # persists for the rest of this app's session
                        r = candidate
                        break

            # Accept successful status codes (2xx and 3xx)
            if 200 <= r.status_code < 400:
                return r
            return None
        except requests.exceptions.Timeout:
            return None
        except requests.exceptions.ConnectionError:
            return None
        except requests.exceptions.RequestException:
            return None
        except Exception:
            return None

    def check_security_headers(self, response):
        present = {h: response.headers.get(h) for h in self.SECURITY_HEADERS if response.headers.get(h)}
        missing = [h for h in self.SECURITY_HEADERS if not response.headers.get(h)]
        return {'present': present, 'missing': missing, 'total_missing': len(missing),
                'security_score': round(len(present) / len(self.SECURITY_HEADERS) * 100, 1)}

    def detect_error_messages(self, response_text):
        """Detects SQL, DB error messages and stack traces"""
        detected_errors = []
        for category, patterns in self.ERROR_PATTERNS.items():
            for pattern in patterns:
                if matches := re.findall(pattern, response_text, re.IGNORECASE | re.DOTALL):
                    detected_errors.append({'category': category, 'pattern': pattern,
                                            'matches': len(matches), 'sample': matches[0][:200]})

        # HTML error tables and details
        if error_tables := re.findall(r'<table>.*?<td\s+class=["\']error-header["\']>(.*?)</td>.*?</table>',
                                      response_text, re.IGNORECASE | re.DOTALL):
            for error_msg in error_tables:
                detected_errors.append({'category': 'HTML Error Table', 'pattern': 'Error table structure',
                                        'matches': 1, 'sample': error_msg[:200]})

        if error_details := re.findall(r'<td\s+class=["\']error-detail["\']>(.*?)</td>',
                                       response_text, re.IGNORECASE | re.DOTALL):
            for detail in error_details:
                if (clean_detail := re.sub(r'<[^>]+>', '', detail).strip()) and len(clean_detail) > 10:
                    detected_errors.append({'category': 'Error Detail', 'pattern': 'error-detail class',
                                            'matches': 1, 'sample': clean_detail[:200]})

        categories = list(set(e['category'] for e in detected_errors))
        return {'has_errors': bool(detected_errors), 'errors': detected_errors,
                'total_errors': len(detected_errors), 'categories': categories}

    def extract_links(self, url, soup):
        """Extracts all links from the page (only within scope)"""
        links = set()
        # Use the directory of the current URL as base (not the full URL with query string)
        parsed_url = urlparse(url)
        base_for_relative = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path.rsplit('/', 1)[0]}/"

        for link in soup.find_all('a', href=True):
            if (href := link['href'].strip()) and not any(x in href.lower() for x in ['#', 'javascript:', 'mailto:']):
                # For relative links without scheme/host, use directory-based resolution
                if not href.startswith(('http://', 'https://', '//')):
                    abs_url = urljoin(base_for_relative, href)
                else:
                    abs_url = urljoin(url, href)
                abs_url = self._normalize_scheme(abs_url)

                if self.is_in_scope(abs_url):
                    parsed = urlparse(abs_url)
                    normalized = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, parsed.query, ''))
                    links.add(normalized)
                    if self.is_admin_path(parsed.path) and (admin_entry := {'path': normalized, 'source': f'link on {url}'}) not in self.admin_paths:
                        self.admin_paths.append(admin_entry)
        return links

    def _extract_links_with_render(self, url):
        """Extracts links from JS-rendered page using Playwright"""
        if not self.use_render or not self.context:
            return set()

        links = set()
        page = None
        try:
            page = self.context.new_page()

            # Navigate to URL with timeout
            page.goto(url, wait_until='networkidle', timeout=30000)

            # Get the REAL final URL after all redirects
            final_url = page.url

            # If this is the start_url and it was redirected, update base_path
            if url == self.start_url and final_url != url:
                final_parsed = urlparse(final_url)
                if final_parsed.netloc == self.base_netloc:
                    # Get the directory path (remove filename)
                    final_path = final_parsed.path.rstrip('/')
                    if '/' in final_path:
                        new_base_path = '/'.join(final_path.split('/')[:-1])
                        if new_base_path != self.base_path:
                            print(f"  🔄 Redirect: {url} → {final_url}")
                            print(f"  📂 Base path: '{self.base_path or '/'}' → '{new_base_path}'")
                            self.base_path = new_base_path

            # Wait for dynamic content to load
            page.wait_for_timeout(4000)  # Wait 4 seconds for fetch() requests

            # Extract HTML after all JS execution
            rendered_html = page.content()

            # Parse rendered HTML with BeautifulSoup to find all links
            soup = BeautifulSoup(rendered_html, 'html.parser')

            # Debug: print how many links found
            all_links = soup.find_all('a', href=True)
            print(f"  🔍 Debug: {len(all_links)} <a> links found in rendered HTML")

            # Use directory of final_url as base for relative links
            parsed_final = urlparse(final_url)
            base_for_relative = f"{parsed_final.scheme}://{parsed_final.netloc}{parsed_final.path.rsplit('/', 1)[0]}/"

            for link in all_links:
                href = link.get('href', '').strip()
                if not href or any(x in href.lower() for x in ['#', 'javascript:', 'mailto:']):
                    continue

                # For relative links without scheme/host, use directory-based resolution
                if not href.startswith(('http://', 'https://', '//')):
                    abs_url = urljoin(base_for_relative, href)
                else:
                    abs_url = urljoin(final_url, href)

                if not self.is_in_scope(abs_url):
                    continue

                parsed = urlparse(abs_url)
                normalized = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, parsed.query, ''))
                links.add(normalized)

                if self.is_admin_path(parsed.path):
                    admin_entry = {'path': normalized, 'source': f'JS-rendered link on {url}'}
                    if admin_entry not in self.admin_paths:
                        self.admin_paths.append(admin_entry)

            if links:
                print(f"  🎭 JS Rendering: {len(links)} in-scope links discovered")
                for link in sorted(links)[:15]:
                    print(f"      • {link}")
            else:
                print(f"  ⚠️  JS Rendering: 0 in-scope links (check if the base URL is correct)")
        except Exception as e:
            print(f"  ⚠️  Error in JS rendering: {e}")
            traceback.print_exc()
        finally:
            # Close the page
            if page:
                try:
                    page.close()
                except:
                    pass

        return links

    def extract_url_parameters(self, url):
        query = urlparse(url).query
        return [{'name': k, 'value': v, 'location': 'URL'} for k, vals in parse_qs(query).items() for v in vals] if query else []

    def _compare_errors(self, baseline_errors, payload_errors):
        """Helper to compare baseline vs payload errors and return new errors"""
        if not baseline_errors['has_errors'] and payload_errors['has_errors']:
            return payload_errors['errors']
        if baseline_errors['has_errors'] and payload_errors['has_errors']:
            baseline_samples = {e['sample'] for e in baseline_errors['errors']}
            payload_samples = {e['sample'] for e in payload_errors['errors']}
            if new_errors := payload_samples - baseline_samples:
                return [e for e in payload_errors['errors'] if e['sample'] in new_errors]
        return []

    def test_url_parameters_for_errors(self, url):
        """Tests URL GET parameters for SQL injection errors (optimized with caching)"""
        parsed = urlparse(url)
        if not (params := parse_qs(parsed.query)):
            return {'tested': False, 'vulnerable_params': [], 'total_vulnerable': 0}

        url_base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        # Check cache
        if url_base in self.tested_url_bases:
            cached = self.tested_url_bases[url_base]
            if all(p in cached for p in params):
                vuln = [cached[p] for p in params if cached[p]]
                return {'tested': True, 'vulnerable_params': vuln, 'total_vulnerable': len(vuln)}
        else:
            self.tested_url_bases[url_base] = {}

        # Get baseline once
        session = self._session_for(url)
        try:
            baseline_errors = self.detect_error_messages(session.get(url, timeout=10, verify=False, allow_redirects=True).text)
        except:
            return {'tested': False, 'vulnerable_params': [], 'total_vulnerable': 0}

        vulnerable_params = []
        for param_name, param_values in params.items():
            if param_name in self.tested_url_bases[url_base]:
                if result := self.tested_url_bases[url_base][param_name]:
                    vulnerable_params.append(result)
                continue

            try:
                modified_params = params.copy()
                modified_params[param_name] = ["'"]
                query_string = '&'.join(f"{k}={v[0]}" for k, v in modified_params.items())
                payload_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, query_string, ''))
                payload_errors = self.detect_error_messages(session.get(payload_url, timeout=10, verify=False, allow_redirects=True).text)

                if new_errors := self._compare_errors(baseline_errors, payload_errors):
                    result = {
                        'param': param_name,
                        'original_value': param_values[0] if param_values else '',
                        'errors': new_errors,
                        'categories': list(set(e['category'] for e in new_errors))
                    }
                    vulnerable_params.append(result)
                    self.tested_url_bases[url_base][param_name] = result
                else:
                    self.tested_url_bases[url_base][param_name] = None
            except:
                self.tested_url_bases[url_base][param_name] = None

        return {'tested': True, 'vulnerable_params': vulnerable_params, 'total_vulnerable': len(vulnerable_params)}

    def identify_form_type(self, form, form_data):
        combined = f"{form.get_text().lower()} {' '.join(f['name'].lower() for f in form_data if f['name'])} {form.get('action', '').lower()}"
        for form_type, keywords in self.FORM_PATTERNS.items():
            if any(kw in combined for kw in keywords):
                return form_type
        return 'LOGIN' if any('password' in f['type'].lower() or 'password' in f['name'].lower() for f in form_data) else 'GENERIC'

    def test_form_for_errors(self, form_data, base_url):
        """Tests form fields for SQL injection errors by comparing baseline vs payload response"""
        testable = [f for f in form_data['fields'] if f['name'] and f['type'] not in ['hidden', 'submit', 'button', 'file', 'reset', 'image']]
        if not testable:
            return {'tested': False, 'has_errors': False, 'errors': []}

        field_vals = {'text': 'test', 'email': 'test', 'search': 'test', 'password': 'test123', 'number': '123', 'checkbox': 'on', 'radio': 'on'}
        session = self._session_for(form_data['action'])
        method = session.post if form_data['method'] == 'post' else session.get
        data_key = 'data' if form_data['method'] == 'post' else 'params'

        for test_field in testable:
            normal_data = {f['name']: (f.get('value', '') if f['type'] == 'hidden' else field_vals.get(f['type'], 'test'))
                           for f in form_data['fields'] if f['name']}

            try:
                baseline_errors = self.detect_error_messages(method(form_data['action'], **{data_key: normal_data}, timeout=10, verify=False, allow_redirects=True).text)
                payload_data = {**normal_data, test_field['name']: "'"}
                payload_errors = self.detect_error_messages(method(form_data['action'], **{data_key: payload_data}, timeout=10, verify=False, allow_redirects=True).text)

                if new_errors := self._compare_errors(baseline_errors, payload_errors):
                    for e in new_errors:
                        e['tested_field'] = test_field['name']
                    categories = list(set(e['category'] for e in new_errors))
                    return {'tested': True, 'has_errors': True, 'errors': new_errors, 'categories': categories, 'total_errors': len(new_errors)}
            except:
                continue

        return {'tested': True, 'has_errors': False, 'errors': [], 'categories': [], 'total_errors': 0}

    def analyze_form(self, form, base_url):
        """Analyzes a form and extracts all its information"""
        action = form.get('action', '')
        parsed_base = urlparse(base_url)
        target_url = action if action.startswith(('http://', 'https://')) else (f"{parsed_base.scheme}://{parsed_base.netloc}{action}" if action.startswith('/') else urljoin(base_url, action))

        fields, has_csrf_token, csrf_field_name = [], False, None
        for field in form.find_all(['input', 'textarea', 'select']):
            name = field.get('name', '')
            field_type = field.get('type', 'text').lower() if field.name == 'input' else field.name

            if not has_csrf_token and field.name == 'input' and field_type == 'hidden' and name and any(p in name.lower() for p in self.CSRF_PATTERNS):
                has_csrf_token, csrf_field_name = True, name

            fields.append({
                'name': name,
                'type': 'select' if field.name == 'select' else field_type,
                'options': [opt.get('value', opt.text.strip()) for opt in field.find_all('option')] if field.name == 'select' else None,
                'value': field.get('value', ''),
                'required': field.has_attr('required'),
                'placeholder': field.get('placeholder', '')
            })

        method = form.get('method', 'get').lower()
        return {
            'method': method, 'action': target_url, 'id': form.get('id', ''), 'name': form.get('name', ''),
            'type': self.identify_form_type(form, fields), 'fields': fields, 'total_fields': len(fields),
            'required_fields': sum(1 for f in fields if f.get('required')),
            'password_fields': sum(1 for f in fields if 'password' in f.get('type', '').lower()),
            'file_fields': sum(1 for f in fields if f.get('type') == 'file'),
            'has_csrf_token': has_csrf_token, 'csrf_field_name': csrf_field_name,
            'error_test': self.test_form_for_errors({'method': method, 'action': target_url, 'fields': fields}, base_url)
        }

    def analyze_standalone_inputs(self, soup, base_url):
        """Detects standalone inputs (outside forms) with possible backend processing"""
        form_inputs = {inp for form in soup.find_all('form') for inp in form.find_all(['input', 'textarea', 'select'])}
        standalone_inputs = []

        for inp in soup.find_all(['input', 'textarea', 'select']):
            if inp in form_inputs:
                continue

            has_id, has_name = inp.get('id'), inp.get('name')
            has_onchange = inp.get('onchange') or inp.get('oninput') or inp.get('onkeyup')
            has_data_attrs = any(attr.startswith('data-') for attr in inp.attrs.keys())

            ajax_patterns, parent = [], inp.parent
            for _ in range(3):
                if parent:
                    for script in parent.find_all('script', limit=2):
                        script_text = script.string or ''
                        for pattern, name in self.AJAX_PATTERNS.items():
                            if pattern in script_text and name not in ajax_patterns:
                                ajax_patterns.append(name)
                    parent = parent.parent

            if has_id or has_name or has_onchange or ajax_patterns or has_data_attrs:
                has_class = inp.get('class')
                is_backend_processing = bool(ajax_patterns or has_onchange or has_data_attrs)
                standalone_inputs.append({
                    'tag': inp.name, 'type': inp.get('type', 'text').lower() if inp.name == 'input' else inp.name,
                    'id': has_id or '', 'name': has_name or '', 'class': ' '.join(has_class) if has_class else '',
                    'placeholder': inp.get('placeholder', ''), 'has_event_handlers': bool(has_onchange),
                    'event_handlers': has_onchange or '', 'has_ajax': bool(ajax_patterns),
                    'ajax_methods': ajax_patterns, 'has_data_attributes': has_data_attrs,
                    'data_attributes': {k: v for k, v in inp.attrs.items() if k.startswith('data-')},
                    'likely_backend_processing': is_backend_processing
                })
        return standalone_inputs

    def analyze_page(self, url, response):
        """Analyzes a complete page"""
        soup = BeautifulSoup(response.text, 'html.parser')
        all_forms_data = [self.analyze_form(form, url) for form in soup.find_all('form')]

        # Deduplicate forms by (action, method, field_names) — avoids saving
        # one entry per product when a page has a catalog with N identical forms
        seen_form_sigs = set()
        forms_data = []
        for form in all_forms_data:
            field_names = frozenset(
                f['name'] for f in form.get('fields', []) if f.get('name')
            )
            sig = (form.get('action', ''), form.get('method', '').lower(), field_names)
            if sig in seen_form_sigs:
                continue
            seen_form_sigs.add(sig)
            forms_data.append(form)

        if len(forms_data) < len(all_forms_data):
            print(f"  ♻️  Deduplicated {len(all_forms_data)} → {len(forms_data)} forms on {url}")
        standalone_inputs = self.analyze_standalone_inputs(soup, url)
        url_params = self.extract_url_parameters(url)
        links = self.extract_links(url, soup)

        # Add JS-rendered links if enabled
        if self.use_render:
            rendered_links = self._extract_links_with_render(url)
            links = links.union(rendered_links)

        title = soup.title.string.strip() if soup.title else 'No title'

        # Test URL parameters for SQL injection
        url_params_test = self.test_url_parameters_for_errors(url) if url_params else {
            'tested': False, 'vulnerable_params': [], 'total_vulnerable': 0
        }

        # Only detect errors on pages with forms
        has_forms = len(forms_data) > 0
        error_detection = self.detect_error_messages(response.text) if has_forms else {
            'has_errors': False, 'errors': [], 'total_errors': 0, 'categories': []
        }

        page_data = {
            'url': url, 'title': title, 'forms': forms_data, 'total_forms': len(forms_data),
            'standalone_inputs': standalone_inputs, 'total_standalone_inputs': len(standalone_inputs),
            'url_parameters': url_params, 'total_url_params': len(url_params),
            'url_params_test': url_params_test, 'links_found': len(links),
            'has_login': any(f['type'] == 'LOGIN' for f in forms_data),
            'has_register': any(f['type'] == 'REGISTER' for f in forms_data),
            'has_search': any(f['type'] == 'SEARCH' for f in forms_data),
            'has_upload': any(f['type'] == 'UPLOAD' for f in forms_data),
            'security_headers': self.check_security_headers(response),
            'error_detection': error_detection
        }

        # Save to database if web_app_id is available
        if self.web_app_id:
            self._save_page_to_db(page_data)

        return page_data, links

    def _save_error_page(self, url, depth, reason):
        """Records a page that failed to fetch/parse as an error crawl_page row,
        so it surfaces (with its URL) instead of silently vanishing from the pipeline."""
        if not self.web_app_id:
            return
        try:
            DatabaseManager.insert_crawl_page(
                web_app_id=self.web_app_id,
                url=url,
                base_url=self.base_url,
                depth=depth,
                state='error',
                error_message=reason,
            )
        except Exception as e:
            print(f"  ⚠️  Error saving error page to database: {e}")

    def _save_page_to_db(self, page_data):
        """Saves the crawled page to the database"""
        try:
            # Never save pages from outside the target host
            if urlparse(page_data['url']).netloc != self.base_netloc:
                print(f"  ⚠️  Blocked external page from DB: {page_data['url']}")
                return

            # Check if this is an admin path
            is_admin = any(admin['path'] == page_data['url'] for admin in self.admin_paths)

            # Check if URL is from robots.txt
            is_robots = False
            if self.robots_paths:
                for path in self.robots_paths.get('disallow', []):
                    if path.rstrip('*') in page_data['url']:
                        is_robots = True
                        break

            # Check for forms without CSRF
            has_form_without_csrf = any(not f['has_csrf_token'] for f in page_data['forms'])

            # Check for GET and POST params
            has_get_params = any(f['method'] == 'get' for f in page_data['forms'])
            has_post_params = any(f['method'] == 'post' for f in page_data['forms'])

            # Collect all errors (from page content and forms)
            all_errors = []
            has_any_errors = False

            # Add page-level errors
            if page_data['error_detection']['has_errors']:
                all_errors.extend(page_data['error_detection']['errors'])
                has_any_errors = True

            # Add form-level errors (SQL injection)
            for form in page_data['forms']:
                if form.get('error_test', {}).get('has_errors', False):
                    all_errors.extend(form['error_test']['errors'])
                    has_any_errors = True

            # Add URL parameter errors
            if page_data.get('url_params_test', {}).get('total_vulnerable', 0) > 0:
                for vuln_param in page_data['url_params_test']['vulnerable_params']:
                    all_errors.extend(vuln_param['errors'])
                    has_any_errors = True

            # Determine if the page is interesting for testing
            is_interesting = self.is_page_interesting(page_data)
            if is_interesting:
                page_state = 'pending_score'
            else:
                page_state = 'done'

            # Insert crawl_page
            crawl_page_id = DatabaseManager.insert_crawl_page(
                web_app_id=self.web_app_id,
                url=page_data['url'],
                base_url=self.base_url,
                depth=self.current_depth,
                is_admin_path=1 if is_admin else 0,
                has_login_form=1 if page_data['has_login'] else 0,
                has_register_form=1 if page_data['has_register'] else 0,
                has_search_form=1 if page_data['has_search'] else 0,
                has_upload_form=1 if page_data['has_upload'] else 0,
                has_form_without_csrf=1 if has_form_without_csrf else 0,
                has_errors=1 if has_any_errors else 0,
                has_parametres_url=1 if page_data['total_url_params'] > 0 else 0,
                is_referred_robots=1 if is_robots else 0,
                has_get_params=1 if has_get_params else 0,
                has_post_params=1 if has_post_params else 0,
                state=page_state
            )

            if crawl_page_id:
                # Insert crawl_page_details with ALL collected errors (same state as crawl_page)
                details_id = DatabaseManager.insert_crawl_page_details(
                    crawl_page_id=crawl_page_id,
                    forms=page_data['forms'],
                    standalone_inputs=page_data['standalone_inputs'],
                    url_params=page_data['url_parameters'],
                    error_details=all_errors if all_errors else None,
                    state='done'
                )
                if details_id:
                    state_emoji = '🔍' if page_state in ('pending', 'pending_score') else '✅'
                    print(f"  💾 Saved: crawl_page_id={crawl_page_id}, details_id={details_id}, state={page_state} {state_emoji}")
                else:
                    print(f"  ⚠️  Failed to save details for crawl_page_id={crawl_page_id}")
        except Exception as e:
            print(f"  ⚠️  Error saving to database: {e}")
            traceback.print_exc()

    def crawl(self):
        """Executes complete crawling (PHASE 2)"""
        print(f"\n{'='*80}\n🕷️  PHASE 2: CRAWLER - Complete analysis of discovered URLs\n{'='*80}")
        print(f"📊 Configuration:\n   • Initial URL: {self.start_url}\n   • Nikto URLs: {len(self.nikto_discovered)}")
        print(f"   • Maximum depth: {self.max_depth}\n   • Delay between requests: {self.delay}s\n{'='*80}\n")

        self.check_robots_txt()
        print(f"\n{'='*80}\nSTARTING CRAWLING\n{'='*80}\n")

        queue = deque([(self.start_url, 0)])
        for url in self.nikto_discovered:
            if url not in self.visited:
                queue.append((url, 0))

        while queue:
            url, depth = queue.popleft()
            if not self.is_in_scope(url) or url in self.visited or depth > self.max_depth:
                continue

            # Skip once a path+param-name pattern has racked up
            # MAX_URL_PATTERN_VARIANTS *unproductive* variants — different
            # param values (e.g. ?bID=1 vs ?bID=2) are distinct pages/vulns,
            # not duplicates, so a variant only counts against the budget if
            # it turns out to lead nowhere new (see _record_pattern_attempt).
            # A parameter that keeps unlocking genuinely new content keeps
            # getting crawled past the cap instead of being marked seen.
            pattern = self._url_pattern(url)
            if self.visited_url_patterns.get(pattern, 0) >= self.MAX_URL_PATTERN_VARIANTS:
                continue

            # Skip one-shot action links (e.g. Mutillidae's do=toggle-security)
            # repeated verbatim across pages — see _repeats_known_action.
            if self._repeats_known_action(url):
                print(f"  🔁 Skipping repeated action link: {url}")
                self.visited.add(url)
                continue

            self.visited.add(url)
            self._record_param_values(url)
            if self.is_admin_path(urlparse(url).path):
                admin_entry = {'path': url, 'source': 'crawling'}
                if admin_entry not in self.admin_paths:
                    self.admin_paths.append(admin_entry)
                    print(f"🔐 ADMIN PATH DETECTED: {url}")

            self.current_depth = depth
            print(f"[{len(self.pages_data)+1}] Analyzing (depth {depth}): {url}")

            # Set timeout alarm for 40 seconds
            signal.signal(signal.SIGALRM, timeout_handler)
            signal.alarm(40)

            try:
                response = self.fetch_page(url)
                if not response:
                    signal.alarm(0)  # Cancel alarm
                    print("  ❌ Error fetching page")
                    self._save_error_page(url, depth, "Error fetching page")
                    self._record_pattern_attempt(pattern, found_new_links=False)
                    continue

                # Skip pages that redirected outside the target host
                if urlparse(response.url).netloc != self.base_netloc:
                    signal.alarm(0)
                    print(f"  ⏭️  External redirect, skipping: {url} → {response.url}")
                    self._record_pattern_attempt(pattern, found_new_links=False)
                    continue

                # Detect redirect on first page and update base_path
                if url == self.start_url and response.url != url:
                    final_parsed = urlparse(response.url)
                    if final_parsed.netloc == self.base_netloc:
                        # Update base_path to the directory of the redirected URL
                        final_path = final_parsed.path.rstrip('/')
                        if '/' in final_path:
                            new_base_path = '/'.join(final_path.split('/')[:-1])
                            if new_base_path != self.base_path:
                                print(f"  🔄 Redirect detected: {url} → {response.url}")
                                print(f"  📂 Updating base_path: '{self.base_path or '/'}' → '{new_base_path}'")
                                self.base_path = new_base_path
                                # Update start_url to the final URL
                                self.start_url = response.url

                page_data, links = self.analyze_page(response.url, response)
                signal.alarm(0)  # Cancel alarm
                self.pages_data.append(page_data)
                self._record_pattern_attempt(
                    pattern,
                    found_new_links=any(link not in self.visited and self.is_in_scope(link) for link in links)
                )
            except TimeoutError:
                signal.alarm(0)  # Cancel alarm
                print(f"  ⏱️  Timeout after 30 seconds - Skipping page")
                self._save_error_page(url, depth, "Timeout after 30 seconds")
                self._record_pattern_attempt(pattern, found_new_links=False)
                continue
            except Exception as e:
                signal.alarm(0)  # Cancel alarm
                print(f"  ❌ Error processing page: {e}")
                self._save_error_page(url, depth, f"Error processing page: {e}")
                self._record_pattern_attempt(pattern, found_new_links=False)
                continue

            if page_data['total_forms'] > 0:
                print(f"  📋 {page_data['total_forms']} form(s) found")
                for form in page_data['forms']:
                    csrf_status = "✅ CSRF" if form['has_csrf_token'] else "⚠️  No CSRF"
                    error_status = ""
                    if form['error_test']['tested']:
                        if form['error_test']['has_errors']:
                            error_status = f" - 🚨 SQL ERROR DETECTED ({', '.join(form['error_test']['categories'])})"
                        else:
                            error_status = " - ✅ No errors"
                    print(f"     • {form['type']} ({form['method'].upper()}) - {form['total_fields']} fields - {csrf_status}{error_status}")
                    if form['has_csrf_token']:
                        print(f"       Token: {form['csrf_field_name']}")

            if page_data['total_standalone_inputs'] > 0:
                backend_count = sum(1 for i in page_data['standalone_inputs'] if i['likely_backend_processing'])
                print(f"  🎛️  {page_data['total_standalone_inputs']} standalone input(s) ({backend_count} with backend processing)")

            if page_data['total_url_params'] > 0:
                url_test = page_data['url_params_test']
                if url_test['tested'] and url_test['total_vulnerable'] > 0:
                    print(f"  🔗 {page_data['total_url_params']} URL parameter(s) - 🚨 {url_test['total_vulnerable']} with SQL errors")
                    for vuln_param in url_test['vulnerable_params']:
                        print(f"     ⚠️  Parameter '{vuln_param['param']}' generates error: {', '.join(vuln_param['categories'])}")
                else:
                    status = " - ✅ No errors" if url_test['tested'] else ""
                    print(f"  🔗 {page_data['total_url_params']} URL parameter(s){status}")

            if page_data['security_headers']['total_missing'] > 0:
                print(f"  ⚠️  {page_data['security_headers']['total_missing']} missing security header(s)")
            if page_data['error_detection']['has_errors']:
                print(f"  🚨 {page_data['error_detection']['total_errors']} error message(s) detected: {', '.join(page_data['error_detection']['categories'])}")

            if depth < self.max_depth:
                # Sorted (not `for link in links` over the set directly): set
                # iteration order depends on Python's per-process string hash
                # randomization, so leaving it unsorted made the crawl queue
                # order — and therefore which URL "wins" duplicate-pattern
                # bounding above — non-deterministic across runs.
                for link in sorted(links):
                    if link not in self.visited and self.is_in_scope(link):
                        queue.append((link, depth + 1))
            time.sleep(self.delay)

        print(f"\n{'='*80}\n✅ Crawling completed: {len(self.pages_data)} pages analyzed\n{'='*80}\n")

        # Close Playwright if used
        if self.use_render:
            try:
                if self.context:
                    self.context.close()
                if self.browser:
                    self.browser.close()
                if self.playwright:
                    self.playwright.stop()
            except Exception:
                pass

    def print_summary(self):
        """Prints complete summary (Nikto + Crawler)"""
        stats = {
            'total_forms': sum(p['total_forms'] for p in self.pages_data),
            'total_params': sum(p['total_url_params'] for p in self.pages_data),
            'total_standalone': sum(p['total_standalone_inputs'] for p in self.pages_data),
            'pages_with_forms': sum(1 for p in self.pages_data if p['total_forms'] > 0),
            'pages_with_params': sum(1 for p in self.pages_data if p['total_url_params'] > 0),
            'pages_with_standalone': sum(1 for p in self.pages_data if p['total_standalone_inputs'] > 0),
            'pages_with_errors': sum(1 for p in self.pages_data if p['error_detection']['has_errors']),
            'pages_with_missing_headers': sum(1 for p in self.pages_data if p['security_headers']['total_missing'] > 0),
            'standalone_with_backend': sum(sum(1 for i in p['standalone_inputs'] if i['likely_backend_processing']) for p in self.pages_data),
            'forms_with_csrf': sum(sum(1 for f in p['forms'] if f['has_csrf_token']) for p in self.pages_data),
            'forms_without_csrf': sum(sum(1 for f in p['forms'] if not f['has_csrf_token']) for p in self.pages_data),
            'forms_with_sql_errors': sum(sum(1 for f in p['forms'] if f.get('error_test', {}).get('has_errors', False)) for p in self.pages_data),
            'forms_tested': sum(sum(1 for f in p['forms'] if f.get('error_test', {}).get('tested', False)) for p in self.pages_data),
            'url_params_tested': sum(1 for p in self.pages_data if p.get('url_params_test', {}).get('tested', False)),
            'url_params_vulnerable': sum(1 for p in self.pages_data if p.get('url_params_test', {}).get('total_vulnerable', 0) > 0),
            'total_vulnerable_params': sum(p.get('url_params_test', {}).get('total_vulnerable', 0) for p in self.pages_data)
        }

        form_types, missing_headers_count, error_categories = {}, {}, {}
        for page in self.pages_data:
            for form in page['forms']:
                form_types[form['type']] = form_types.get(form['type'], 0) + 1
            for header in page['security_headers']['missing']:
                missing_headers_count[header] = missing_headers_count.get(header, 0) + 1
            for category in page['error_detection'].get('categories', []):
                error_categories[category] = error_categories.get(category, 0) + 1

        print(f"{'='*80}\n📊 GENERAL SUMMARY\n{'='*80}")
        print(f"🔍 Nikto discovered: {len(self.nikto_discovered)} URLs\n🌐 Pages analyzed: {len(self.pages_data)}")
        print(f"📋 Total forms: {stats['total_forms']} (in {stats['pages_with_forms']} pages)")
        if stats['total_forms'] > 0:
            print(f"   🔒 With CSRF: {stats['forms_with_csrf']} | ⚠️  Without CSRF: {stats['forms_without_csrf']}")
            print(f"   🧪 Forms tested for SQLi: {stats['forms_tested']}")
            print(f"   🚨 Forms with SQL errors: {stats['forms_with_sql_errors']}")
        print(f"🎛️  Total standalone inputs: {stats['total_standalone']} ({stats['standalone_with_backend']} with backend, in {stats['pages_with_standalone']} pages)")
        print(f"🔗 Total URL parameters: {stats['total_params']} (in {stats['pages_with_params']} pages)")
        if stats['url_params_tested'] > 0:
            print(f"   🧪 URL params tested for SQLi: {stats['url_params_tested']}")
            print(f"   🚨 Pages with URL params that generate errors: {stats['url_params_vulnerable']} ({stats['total_vulnerable_params']} parameter(s) with errors)")
        print(f"🚨 Pages with errors: {stats['pages_with_errors']}\n⚠️  Pages with missing headers: {stats['pages_with_missing_headers']}")

        if self.robots_paths:
            print(f"\n🤖 robots.txt:\n   • Blocked paths: {len(self.robots_paths.get('disallow', []))}")
            print(f"   • Allowed paths: {len(self.robots_paths.get('allow', []))}\n   • Sitemaps: {len(self.robots_paths.get('sitemaps', []))}")

        if self.admin_paths:
            print(f"\n🔐 Admin paths detected: {len(self.admin_paths)}")
            for admin in self.admin_paths[:10]:
                print(f"   • {admin['path']} (detected in: {admin['source']})")

        if form_types:
            print("\n📝 Form types found:")
            for form_type, count in sorted(form_types.items(), key=lambda x: x[1], reverse=True):
                print(f"   • {form_type}: {count}")

        if missing_headers_count:
            print("\n🔒 Missing security headers (most common):")
            for header, count in sorted(missing_headers_count.items(), key=lambda x: x[1], reverse=True)[:5]:
                print(f"   • {header}: missing in {count}/{len(self.pages_data)} pages")

        if error_categories:
            print("\n🚨 Error types detected:")
            for category, count in sorted(error_categories.items(), key=lambda x: x[1], reverse=True):
                print(f"   • {category}: {count} page(s)")

        if self.nikto_discovered:
            print(f"\n{'='*80}\n🔍 NIKTO DISCOVERY DETAILS\n{'='*80}\n📊 URLs discovered by Nikto ({len(self.nikto_discovered)}):")
            for url in self.nikto_discovered[:30]:
                print(f"   • {url}")
            if len(self.nikto_discovered) > 30:
                print(f"   ... and {len(self.nikto_discovered) - 30} more")

        if self.robots_paths:
            print(f"\n{'='*80}\n🤖 ROBOTS.TXT DETAILS\n{'='*80}")
            if self.robots_paths.get('disallow'):
                print("\n📍 Blocked paths (Disallow):")
                for path in self.robots_paths['disallow'][:20]:
                    print(f"   • {path}{' [ADMIN]' if self.is_admin_path(path) else ''}")
            if self.robots_paths.get('allow'):
                print("\n✓ Allowed paths (Allow):")
                for path in self.robots_paths['allow'][:20]:
                    print(f"   • {path}")
            if self.robots_paths.get('sitemaps'):
                print("\n🗺️  Sitemaps:")
                for sitemap in self.robots_paths['sitemaps']:
                    print(f"   • {sitemap}")

        print(f"\n{'='*80}\n🔍 PAGE DETAILS\n{'='*80}\n")
        for idx, page in enumerate(self.pages_data, 1):
            is_admin = any(admin['path'] == page['url'] for admin in self.admin_paths)
            is_nikto = page['url'] in self.nikto_discovered
            tags = []
            if is_admin:
                tags.append('🔐 [ADMIN PATH]')
            if is_nikto:
                tags.append('🔍 [NIKTO]')
            tag_str = ' '.join(tags) if tags else ''

            print(f"[{idx}] {page['url']} {tag_str}\n    📄 Title: {page['title']}")
            sec = page['security_headers']
            if sec['total_missing'] > 0:
                print(f"    ⚠️  Security: {sec['security_score']}% - Missing {sec['total_missing']} header(s):")
                for header in sec['missing'][:3]:
                    print(f"       ✗ {header}")
            else:
                print("    ✅ Security: 100% - All headers present")

            if page['total_forms'] > 0:
                print(f"    📋 Forms: {page['total_forms']}")
                for form_idx, form in enumerate(page['forms'], 1):
                    csrf_indicator = "🔒 [CSRF]" if form['has_csrf_token'] else "⚠️  [NO CSRF]"
                    error_indicator = ""
                    if form['error_test']['tested'] and form['error_test']['has_errors']:
                        error_indicator = f" 🚨 [SQL ERROR: {', '.join(form['error_test']['categories'])}]"
                    print(f"       [{form_idx}] {form['type']} - {form['method'].upper()} → {form['action']} {csrf_indicator}{error_indicator}")
                    if form['has_csrf_token']:
                        print(f"           CSRF Token: {form['csrf_field_name']}")
                    if form['error_test']['tested'] and form['error_test']['has_errors']:
                        print(f"           ⚠️  SQL Injection vulnerable - {form['error_test']['total_errors']} error(s) detected")
                        for error in form['error_test']['errors'][:2]:
                            print(f"              • {error['category']}: {error['sample'][:80]}...")
                    print(f"           Fields: {form['total_fields']} (required: {form['required_fields']})")
                    for field in form['fields'][:5]:
                        if field['name']:
                            print(f"           • {field['name']} ({field['type']}){'*' if field.get('required') else ''}")

            if page['total_standalone_inputs'] > 0:
                print(f"    🎛️  Standalone Inputs: {page['total_standalone_inputs']}")
                for inp_idx, inp in enumerate(page['standalone_inputs'][:5], 1):
                    backend = " [BACKEND]" if inp['likely_backend_processing'] else ""
                    print(f"       [{inp_idx}] {inp['tag']}.{inp['type']}{backend}")
                    if inp['id']:
                        print(f"           ID: {inp['id']}")
                    if inp['name']:
                        print(f"           Name: {inp['name']}")
                    if inp['has_ajax']:
                        print(f"           AJAX: {', '.join(inp['ajax_methods'])}")
                    if inp['has_event_handlers']:
                        print(f"           Events: {inp['event_handlers'][:50]}...")
                    if inp['data_attributes']:
                        print(f"           Data attrs: {len(inp['data_attributes'])} found")

            if page['total_url_params'] > 0:
                url_test = page.get('url_params_test', {})
                error_indicator = ""
                if url_test.get('tested') and url_test.get('total_vulnerable', 0) > 0:
                    error_indicator = f" 🚨 [{url_test['total_vulnerable']} WITH ERRORS]"
                print(f"    🔗 URL Parameters: {page['total_url_params']}{error_indicator}")
                for param in page['url_parameters'][:5]:
                    print(f"       • {param['name']} = {param['value']}")

                # Show parameters that generate errors
                if url_test.get('vulnerable_params'):
                    for vuln_param in url_test['vulnerable_params']:
                        print(f"       ⚠️  ERROR DETECTED: {vuln_param['param']} - {', '.join(vuln_param['categories'])}")
                        for error in vuln_param['errors'][:1]:
                            print(f"          Error: {error['sample'][:80]}...")
            print()

    # ------------------------------------------------------------------
    # Lifecycle (BaseModule pattern)
    # ------------------------------------------------------------------

    def validate(self) -> bool:
        assert_in_scope(self.start_url)
        # Nikto is optional (skip_nikto). There is no hard precondition.
        return True

    def load(self) -> bool:
        # The crawler works live; it does not preload context from the DB.
        return True

    def run(self) -> "ModuleResult":
        if not self.skip_nikto:
            # Nikto is best-effort discovery, not a hard dependency: a crash here
            # (binary missing, a timeout not caught by ExternalTool, or a
            # non-UTF8 byte in some scanned response tripping subprocess's
            # text=True decoding) must not abort the crawl before it even starts.
            try:
                self.run_nikto()
            except Exception as exc:
                print(f"⚠️  Nikto failed, continuing without its findings: {exc}")
        else:
            print(f"\n{'='*80}\n⏭️  NIKTO SKIPPED - Direct crawler\n{'='*80}\n")
        self.crawl()
        return ModuleResult.ok(
            self.slug, f"Crawling completed: {len(self.pages_data)} pages",
            findings=len(self.pages_data),
            pages=len(self.pages_data), admin_paths=len(self.admin_paths),
            nikto=len(self.nikto_discovered),
        )

    def report(self, result: "ModuleResult") -> None:
        self.print_summary()

    def on_failure(self, result: "ModuleResult") -> None:
        if self.web_app_id:
            self.db.update_web_app_state(self.web_app_id, "error", error_message=result.message)

    def on_log(self, result: "ModuleResult", log_text: str) -> None:
        if self.web_app_id:
            self.db.update_web_app_log(self.web_app_id, log_text)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Crawls a site (+ Nikto) looking for pages, forms and parameters")
    parser.add_argument("start_url", help="Initial crawling URL")
    parser.add_argument("--web-app-id", type=int, default=None, help="host_web_app ID to associate the found pages with")
    parser.add_argument("--depth", type=int, default=3, help="Maximum crawling depth (default: 3)")
    parser.add_argument("--delay", type=float, default=0.5, help="Seconds to wait between requests (default: 0.5)")
    parser.add_argument("--max-pages", type=int, default=None, help="Limit of pages to crawl (default: no limit)")
    parser.add_argument("--use-render", action="store_true", help="Render JS with Playwright before parsing")
    args = parser.parse_args()

    result = WebCrawler(
        args.start_url, max_depth=args.depth, delay=args.delay, use_render=args.use_render,
        web_app_id=args.web_app_id, max_pages=args.max_pages,
    ).execute()
    sys.exit(result.exit_code())

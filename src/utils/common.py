#!/usr/bin/env python3
"""
common.py - Shared utilities for detector.py and exploiter.py

Provides:
  - FormParser   : HTML form extractor
  - SKIP_PARAMS  : parameter names to exclude from injection testing
  - fetch_page   : download HTML from a URL
  - get_url_params: extract GET parameters from a URL
  - build_form_data: URL-encode a list of form fields
  - check_sqlmap : verify sqlmap is installed
  - pick         : interactive console menu
"""

import re
import sys
import subprocess
from urllib.parse import urlparse, urljoin, quote_plus, parse_qs, urlunparse
try:
    from html.parser import HTMLParser
    import urllib.request as urllib_request
except ImportError:
    print("❌ Python 3 required")
    sys.exit(1)


# ============================================================================
# CONSTANTS
# ============================================================================

# Parameters that should never be tested for injection (skip in sqlmap)
SKIP_PARAMS = {
    'page', 'file', 'include', 'template', 'view',
    'module', 'action', 'lang', 'language'
}


# ============================================================================
# HTML FORM PARSER
# ============================================================================

class FormParser(HTMLParser):
    """
    Parses an HTML page and extracts all <form> elements with their fields.

    Each form is a dict:
        {
            'action':  str,   # absolute URL
            'method':  str,   # 'GET' or 'POST'
            'fields':  list of {'name', 'type', 'value'}
        }

    Field types kept:
        text, password, hidden, checkbox, radio, select, textarea, submit, button
    Field types discarded:
        image, reset, file  (irrelevant for SQLi)

    Submit / button fields are retained so they can be included in --data,
    but callers should add them to sqlmap's --skip list.
    """

    def __init__(self, base_url):
        super().__init__()
        self.base_url = base_url
        self.forms = []
        self._current_form = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        tag = tag.lower()

        if tag == 'form':
            action = attrs.get('action', '')
            action = urljoin(self.base_url, action) if action else self.base_url
            self._current_form = {
                'action': action,
                'method': attrs.get('method', 'GET').upper(),
                'fields': []
            }
            self.forms.append(self._current_form)

        elif tag == 'input' and self._current_form is not None:
            name = attrs.get('name', '').strip()
            if not name:
                return
            itype = attrs.get('type', 'text').lower()
            if itype in ('image', 'reset', 'file'):
                return
            self._current_form['fields'].append({
                'name': name,
                'type': itype,
                'value': attrs.get('value', '')
            })

        elif tag == 'select' and self._current_form is not None:
            name = attrs.get('name', '').strip()
            if name:
                self._current_form['fields'].append({
                    'name': name, 'type': 'select', 'value': '1'
                })

        elif tag == 'textarea' and self._current_form is not None:
            name = attrs.get('name', '').strip()
            if name:
                self._current_form['fields'].append({
                    'name': name, 'type': 'textarea', 'value': 'test'
                })

    def handle_endtag(self, tag):
        if tag.lower() == 'form':
            self._current_form = None


# ============================================================================
# HELPERS
# ============================================================================

def fetch_page(url):
    """Downloads and returns the HTML content of *url*, or None on error."""
    try:
        req = urllib_request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib_request.urlopen(req, timeout=10) as resp:
            charset = resp.headers.get_content_charset() or 'utf-8'
            return resp.read().decode(charset, errors='replace')
    except Exception as e:
        print(f"⚠️  Could not fetch {url}: {e}")
        return None


# Params dropped from url_pattern() as pure pagination noise, unless their
# value looks like a routing target (e.g. page=document-viewer.php), in
# which case they're kept — that's not pagination, it's page selection.
_PATTERN_PAGINATION_PARAMS = {'page', 'pagina', 'p', 'offset', 'start'}
_PATTERN_ROUTING_VALUE_RE = re.compile(r'\.(php|html?|asp|aspx|jsp)$', re.IGNORECASE)


def url_pattern(url):
    """Canonical (scheme+host+path + sorted param NAMES, no values) key for
    a URL: two URLs differing only in query *values* (?id=1 vs ?id=2, or a
    blank vs a filled-in value) collapse to the same pattern. Scheme is
    normalized to http so an http/https pair of the same page also match.

    Used to bound how many value-variants of a page the crawler visits
    (modules/recon/WebCrawler.py._url_pattern delegates here), and to group
    SQLi findings that only differ by parameter value into a single
    reported vulnerability instead of counting each value separately.
    """
    p = urlparse(url)
    if not p.query:
        return urlunparse(('http', p.netloc, p.path, p.params, '', ''))

    parts = []
    for k, vals in sorted(parse_qs(p.query).items()):
        v = vals[0] if vals else ''
        if k.lower() in _PATTERN_PAGINATION_PARAMS and not _PATTERN_ROUTING_VALUE_RE.search(v):
            continue
        elif k.lower() in _PATTERN_PAGINATION_PARAMS and _PATTERN_ROUTING_VALUE_RE.search(v):
            parts.append(f"{k}={v}")
        else:
            parts.append(k)
    return urlunparse(('http', p.netloc, p.path, p.params, '&'.join(parts), ''))


def get_url_params(url):
    """Returns a list of {'name', 'value'} dicts for every GET parameter in *url*."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    return [{'name': k, 'value': v[0]} for k, v in params.items()]


def build_form_data(fields):
    """
    URL-encodes *fields* (list of {'name', 'value', ...}) into a query string.
    Falls back to '1' when a field has no value.
    """
    parts = []
    for f in fields:
        val = f.get('value') or '1'
        parts.append(f"{quote_plus(f['name'])}={quote_plus(str(val))}")
    return '&'.join(parts)


def check_sqlmap():
    """Returns True if sqlmap is installed and reachable."""
    try:
        return subprocess.run(
            ['sqlmap', '--version'], capture_output=True, timeout=5
        ).returncode == 0
    except Exception:
        return False


def pick(items, title):
    """
    Displays a numbered console menu and returns the chosen item.
    Returns None if the user selects 0 (cancel).
    """
    if not items:
        return None

    print(f"\n{'─'*60}")
    print(f"  {title}")
    print(f"{'─'*60}")
    for i, item in enumerate(items, 1):
        print(f"  {i:>3}. {item}")
    print(f"    0. Cancel / exit")
    print(f"{'─'*60}")

    while True:
        try:
            raw = input(f"  Select (0-{len(items)}): ").strip()
            n = int(raw)
            if n == 0:
                return None
            if 1 <= n <= len(items):
                return items[n - 1]
            print(f"  ❌ Enter a number between 0 and {len(items)}")
        except (ValueError, EOFError):
            print("  ❌ Enter a valid number")


def collect_form_targets(url, html=None):
    """
    Fetches *url* (or uses *html* if provided), parses its forms, and returns
    a list of (sqlmap_base_cmd, label) tuples ready to pass to sqlmap.

    Each tuple's cmd already includes:
      - --data  for POST forms
      - GET params appended to the URL for GET forms
      - --skip  for SKIP_PARAMS + submit/button fields
    """
    if html is None:
        print(f"\n📥 Fetching page to detect forms…")
        html = fetch_page(url)
        if not html:
            print("   ⚠️  Could not fetch the page, skipping form detection")
            return []

    parser = FormParser(url)
    parser.feed(html)

    if not parser.forms:
        print("   ℹ️  No forms detected on the page")
        return []

    print(f"📋 {len(parser.forms)} form(s) found:\n")
    candidates = []

    for i, form in enumerate(parser.forms, 1):
        submit_fields = [f for f in form['fields'] if f.get('type') in ('submit', 'button')]
        testable      = [f for f in form['fields']
                         if f.get('type') not in ('submit', 'button')
                         and f['name'].lower() not in SKIP_PARAMS]
        skip          = ([f['name'] for f in form['fields'] if f['name'].lower() in SKIP_PARAMS]
                         + [f['name'] for f in submit_fields])

        method = form['method']
        action = form['action']

        print(f"  [{i}] {method} → {action}")
        if not testable:
            print(f"       ⚠️  No testable fields")
            continue

        for f in testable:
            print(f"       • {f['name']} ({f['type']})")
        for f in submit_fields:
            print(f"       · {f['name']} (submit — included in data, not tested)")

        # Include ALL fields (testable + submit) in --data / URL
        form_data = build_form_data(form['fields'])

        if method == 'GET':
            sep    = '&' if '?' in action else '?'
            target = f"{action}{sep}{form_data}"
            cmd    = ['sqlmap', '-u', target, '--batch', '--threads=5',
                      '--timeout=30', '--retries=1', '--union-cols=1-15']
        else:
            cmd = ['sqlmap', '-u', action, '--batch', '--threads=5',
                   '--timeout=30', '--retries=1', '--union-cols=1-15',
                   '--data', form_data]

        if skip:
            cmd += ['--skip', ','.join(skip)]

        candidates.append((cmd, f"Form {i}: {method} → {action}"))

    return candidates


def dedup_targets(candidates):
    """
    Remove duplicate (cmd, label) pairs that point to the same base URL.
    When a URL-params target and a form target share the same endpoint,
    only the first one encountered is kept.
    Returns a deduplicated list preserving original order.
    """
    from urllib.parse import urlparse

    seen_bases = set()
    result = []
    for cmd, label in candidates:
        # Extract the -u argument from the cmd list
        try:
            u_idx = cmd.index('-u')
            target_url = cmd[u_idx + 1]
        except (ValueError, IndexError):
            result.append((cmd, label))
            continue

        parsed = urlparse(target_url)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        if base in seen_bases:
            print(f"   ⏭️  Skipping duplicate target (same endpoint): {label}")
            continue
        seen_bases.add(base)
        result.append((cmd, label))

    return result

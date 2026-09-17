#!/usr/bin/env python3
"""
detector.py - SQL Injection Detector 

Usage:
    python3 detector.py <URL>

Examples:
    python3 detector.py "http://192.168.1.179/mutillidae/index.php?page=login.php"
    python3 detector.py "http://192.168.1.179/dvwa/login.php"
"""

import sys
import re
import subprocess
import shlex
from common import (
    SKIP_PARAMS, get_url_params,check_sqlmap, collect_form_targets, dedup_targets,
)


# ============================================================================
# SQLMAP RUNNER
# ============================================================================

def run_sqlmap(cmd, label):
    """Runs sqlmap and parses output for vulnerability info"""
    print(f"\n🚀 Running sqlmap on {label}")
    print(f"   Command: {' '.join(shlex.quote(a) for a in cmd)}\n")
    print("─" * 70)

    vulnerable = False
    injection_points = []
    injection_types = []
    dbms = None

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
            bufsize=1
        )

        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue
            print(f"  {line}")

            if 'all tested parameters do not appear to be injectable' in line.lower():
                vulnerable = False

            if any(x in line.lower() for x in ['is vulnerable', 'resumed the following injection point']):
                vulnerable = True

            param_match = re.search(r'Parameter:\s*([^\s(]+)', line)
            if param_match:
                p = param_match.group(1)
                if p not in injection_points:
                    injection_points.append(p)
                    vulnerable = True

            type_match = re.search(r'Type:\s*(.+)', line)
            if type_match and 'testing' not in line.lower():
                t = type_match.group(1).strip()
                if t not in injection_types:
                    injection_types.append(t)

            if 'back-end dbms:' in line.lower():
                m = re.search(r'back-end DBMS:\s*(.+)', line, re.IGNORECASE)
                if m:
                    dbms = m.group(1).strip()

        proc.wait(timeout=15)

    except subprocess.TimeoutExpired:
        proc.kill()
        print("⚠️  sqlmap process timed out")
    except KeyboardInterrupt:
        proc.terminate()
        print("\n⚠️  Interrupted by user")
        sys.exit(0)

    print("─" * 70)
    return {
        'label': label,
        'vulnerable': vulnerable,
        'injection_points': injection_points,
        'injection_types': injection_types,
        'dbms': dbms
    }


def build_sqlmap_cmd_url(url, skip_params=None):
    """Builds sqlmap command for a URL with GET params"""
    cmd = ['sqlmap', '-u', url, '--batch', '--threads=5',
           '--timeout=30', '--retries=1', '--union-cols=1-15']
    if skip_params:
        cmd += ['--skip', ','.join(skip_params)]
    return cmd


def build_sqlmap_cmd_form(action, method, form_data, skip_params=None):
    """Builds sqlmap command for a form"""
    if method == 'GET':
        sep = '&' if '?' in action else '?'
        target = f"{action}{sep}{form_data}"
        cmd = ['sqlmap', '-u', target, '--batch', '--threads=5',
               '--timeout=30', '--retries=1', '--union-cols=1-15']
    else:
        cmd = ['sqlmap', '-u', action, '--batch', '--threads=5',
               '--timeout=30', '--retries=1', '--union-cols=1-15',
               '--data', form_data]
    if skip_params:
        cmd += ['--skip', ','.join(skip_params)]
    return cmd


# ============================================================================
# MAIN LOGIC
# ============================================================================

def print_result(result):
    """Prints a single result"""
    print(f"\n{'='*70}")
    print(f"🎯 Target: {result['label']}")
    if result['vulnerable']:
        print(f"🚨 VULNERABLE TO SQL INJECTION")
        if result['injection_points']:
            print(f"   • Parameter(s): {', '.join(result['injection_points'])}")
        if result['injection_types']:
            print(f"   • Type(s):")
            for t in result['injection_types']:
                print(f"       - {t}")
        if result['dbms']:
            print(f"   • DBMS: {result['dbms']}")
    else:
        print(f"✅ Not vulnerable")
    print(f"{'='*70}")


def main():
    if len(sys.argv) < 2 or sys.argv[1] in ('-h', '--help'):
        print(__doc__)
        sys.exit(0)

    url = sys.argv[1].strip()
    if not url.startswith(('http://', 'https://')):
        print("❌ URL must start with http:// or https://")
        sys.exit(1)

    if not check_sqlmap():
        print("❌ sqlmap not found. Install with: sudo apt-get install sqlmap")
        sys.exit(1)

    print(f"\n{'='*70}")
    print(f"🔍 DETECTOR - Simple SQL Injection Scanner")
    print(f"{'='*70}")
    print(f"🌐 Target URL: {url}")
    print(f"{'='*70}\n")

    targets = []  # list of (cmd, label)

    # ── 1. GET parameters in URL ─────────────────────────────────────────────
    url_params = get_url_params(url)
    if url_params:
        print(f"🔗 GET parameters detected in URL:")
        for p in url_params:
            print(f"   • {p['name']} = {p['value']!r}")

        testable = [p for p in url_params if p['name'].lower() not in SKIP_PARAMS]
        skip = [p['name'] for p in url_params if p['name'].lower() in SKIP_PARAMS]

        if testable:
            cmd = build_sqlmap_cmd_url(url, skip_params=skip if skip else None)
            targets.append((cmd, f"GET {url}"))
        else:
            print("   ⏭️  All parameters are in skip list, ignoring URL params")

    # ── 2. Fetch page and extract forms ──────────────────────────────────────
    for cmd, label in collect_form_targets(url):
        targets.append((cmd, label))

    # ── 3. Deduplicate (same base URL → keep first) ───────────────────────────
    targets = dedup_targets(targets)

    # ── 4. If nothing to test ─────────────────────────────────────────────────
    if not targets:
        print("\n❌ No testable targets found (no GET params, no forms with fields)")
        sys.exit(0)

    print(f"\n{'='*70}")
    print(f"📊 {len(targets)} target(s) to test with sqlmap")
    print(f"{'='*70}")

    # ── 5. Run sqlmap on each target ──────────────────────────────────────────
    results = []
    for cmd, label in targets:
        result = run_sqlmap(cmd, label)
        results.append(result)
        print_result(result)

    # ── 6. Final summary ──────────────────────────────────────────────────────
    print(f"\n{'='*70}")
    print(f"📊 FINAL SUMMARY")
    print(f"{'='*70}")

    vulnerable = [r for r in results if r['vulnerable']]
    safe       = [r for r in results if not r['vulnerable']]

    print(f"   Vulnerable   : {len(vulnerable)}")
    print(f"   Safe         : {len(safe)}")

    if vulnerable:
        print(f"\n⚠️  VULNERABLE TARGETS:")
        for r in vulnerable:
            print(f"\n   🎯 {r['label']}")
            if r['injection_points']:
                print(f"      Parameter(s): {', '.join(r['injection_points'])}")
            if r['injection_types']:
                for t in r['injection_types']:
                    print(f"      Type: {t}")
            if r['dbms']:
                print(f"      DBMS : {r['dbms']}")
    else:
        print(f"\n✅ No SQL injection vulnerabilities found")

    print(f"\n{'='*70}\n")


if __name__ == '__main__':
    main()

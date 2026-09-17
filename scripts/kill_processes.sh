#!/usr/bin/env bash
# Kills every process belonging to this project: the FastAPI server
# (Web/app.py), any pipeline module it spawned (modules/recon, modules/sqli,
# modules/reports, modules/sqli_ai_attack...), and the external scan tools
# those modules shell out to (nmap, whatweb, nikto, sqlmap).
set -uo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

PATTERNS=(
  "Web/app\.py"
  "${PROJECT_ROOT}/src/modules/"
  "\bnmap\b"
  "\bwhatweb\b"
  "\bnikto\b"
  "\bsqlmap\b"
)

found_any=0
for pattern in "${PATTERNS[@]}"; do
  pids=$(pgrep -f "$pattern" || true)
  [ -z "$pids" ] && continue
  found_any=1
  echo "--- matching '$pattern' ---"
  ps -o pid,ppid,etime,cmd -p $pids
  kill $pids 2>/dev/null
done

if [ "$found_any" -eq 0 ]; then
  echo "No matching processes found."
  exit 0
fi

sleep 2

# Force-kill anything that ignored SIGTERM
still_alive=0
for pattern in "${PATTERNS[@]}"; do
  pids=$(pgrep -f "$pattern" || true)
  [ -z "$pids" ] && continue
  still_alive=1
  echo "Still alive, sending SIGKILL: $pids"
  kill -9 $pids 2>/dev/null
done

[ "$still_alive" -eq 0 ] && echo "All matched processes terminated."

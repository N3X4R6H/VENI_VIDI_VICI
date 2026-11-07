
#!/usr/bin/env bash
set -euo pipefail

BASE="https://localhost:8443"

https_get() {
    curl --silent --show-error --fail --insecure "$1"
}

echo "[1/8] HTTP redirects to HTTPS"
status=$(curl -sS -o /dev/null -w '%{http_code}' \
    http://localhost:8080/)
test "$status" = "301"

echo "[2/8] Main portal is reachable"
response=$(https_get "$BASE/")
grep -q "Research Operations Portal" <<< "$response"

echo "[3/8] robots.txt reveals the backup path"
response=$(https_get "$BASE/robots.txt")
grep -q "/backup/" <<< "$response"

echo "[4/8] Backup index is reachable"
response=$(https_get "$BASE/backup/")
grep -q "2026-09-28/" <<< "$response"

echo "[5/8] Deployment artifact contains Flag 1"
response=$(https_get "$BASE/backup/2026-09-28/deployment.json")
grep -Fq "VVVFLAG{cf45a1382453e2f7c25acc0927ff24ecd7b394ace85b7434a0f6e7c30f2daa57}" <<< "$response"

echo "[6/8] Diagnostics are reachable through the gateway"
response=$(https_get "$BASE/api/diagnostics/")
grep -q "2.7.14-dev" <<< "$response"

echo "[7/8] Final endpoint contains Flag 2"
response=$(https_get "$BASE/api/diagnostics/artifacts/latest")
grep -Fq "VVVFLAG{2af20e1c0eedbdc1f829fc1cef86f30881038189896d4bdcf67ee545a81bf7cf}" <<< "$response"

echo "[8/8] Research API has no host-published port"
published_ports=$(docker port n1-research-api 2>/dev/null || true)

if [[ -n "$published_ports" ]]; then
    echo "FAIL: Research API has a published host port."
    printf '%s\n' "$published_ports"
    exit 1
fi

echo "PASS: Research API has no published host port."
echo
echo "All smoke tests passed."

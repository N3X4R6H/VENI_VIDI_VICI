#!/usr/bin/env bash
#
# N2 - GHOST IN THE WIRE
# Smoke + acceptance test pipeline.
#
# Runs the full chain from a clean evidence directory and verifies everything:
#   1. Regenerate all evidence + pcap deterministically
#   2. Run official_solve.py against the freshly generated evidence
#   3. Run all three python test suites
#
# Exits non-zero on any failure. Safe to re-run; it overwrites evidence/.
#
# Usage:
#   ./tests/smoke.sh
#   NO_DOCKER=1 ./tests/smoke.sh          # default; docker not required
#
# Requirements: python3 with scapy installed (pip install scapy).

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PY="${PYTHON:-python3}"
# No PYTHONPATH needed: generate_capture.py / official_solve.py / tests read
# the generated organizer/flag_config.json + _manifest.json directly.

echo "### N2 smoke test"
echo "### root: $ROOT"
echo "### python: $($PY --version)"
echo

echo "==> [1/5] clean evidence + organizer artifacts"
rm -rf evidence/*.pcap evidence/*.log evidence/*.csv
rm -f organizer/_manifest.json organizer/_artifact_envelope.bin organizer/flag_config.json
mkdir -p evidence

echo "==> [2/5] generate_evidence.py"
$PY organizer/generate_evidence.py

echo "==> [3/5] generate_capture.py"
$PY organizer/generate_capture.py

echo "==> [4/5] official_solve.py (must recover both flags + integrity PASS)"
$PY organizer/official_solve.py --quiet
echo "--- full solve trace ---"
$PY organizer/official_solve.py | tail -n +1 | sed 's/^/    /'

echo "==> [5/5] acceptance test suites"
rc=0
for t in evidence_consistency payload_reconstruction flag_validation; do
  echo
  echo "### $t"
  $PY tests/$t.py || rc=1
done

echo
if [ "$rc" -eq 0 ]; then
  echo "=== N2 smoke: ALL CHECKS PASSED ==="
else
  echo "=== N2 smoke: FAILURES PRESENT ==="
fi
exit $rc

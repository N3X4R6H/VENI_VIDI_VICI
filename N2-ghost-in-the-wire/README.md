# N2 — Ghost in the Wire

**PARSEC — IIT Dharwad · Veni Vidi Vici (VVV)**
Network Security · Intermediate · 2 flags · ~35–50 min

A forensic CTF challenge about a DNS-tunneling data-exfiltration incident at the
fictional organization *Asterion Research Systems*. Participants correlate a
packet capture, DNS resolver logs, DHCP lease records, and a repository audit
log to attribute the activity to a workstation MAC, then reconstruct the
exfiltrated payload and recover the embedded flag.

---

## Quick start

### Generate evidence and verify the solve (organizer side)

```bash
cd N2-ghost-in-the-wire
pip install scapy                      # only build dependency

# Full clean pipeline: regenerate evidence + pcap, run official solve,
# run all acceptance tests.
./tests/smoke.sh
```

Expected outcome: `=== N2 smoke: ALL CHECKS PASSED ===`

To regenerate just the evidence (without tests):

```bash
python3 organizer/generate_evidence.py
python3 organizer/generate_capture.py
python3 organizer/official_solve.py    # prints both flags + integrity check
```

### Run the participant portal locally

```bash
cp .env.example .env                   # optional: set CTFD_URL
python3 portal/app.py                  # serves http://0.0.0.0:8080
```

### Run via Docker Compose

```bash
docker compose build
docker compose up                       # portal only (no published port)
docker compose --profile gateway up     # portal + nginx gateway on :8080
```

---

## Layout

```
N2-ghost-in-the-wire/
├── README.md                  this file
├── context.md                 full design specification (organizer reference)
├── docker-compose.yml         portal (+ optional gateway), resource-limited
├── .env.example
│
├── evidence/                  PARTICIPANT-FACING (4 files)
│   ├── network_capture.pcap
│   ├── dns_resolver.log
│   ├── dhcp_leases.csv
│   └── repository_audit.log
│
├── portal/                    PARTICIPANT-FACING
│   ├── Dockerfile
│   ├── app.py                 stdlib http.server, allowlist-only downloads
│   ├── templates/index.html   briefing, objectives, evidence links, hints
│   └── static/style.css
│
├── gateway/                   OPTIONAL reverse proxy
│   ├── Dockerfile
│   └── nginx.conf
│
├── organizer/                 ORGANIZER-ONLY (never in the portal image)
│   ├── generate_evidence.py   single source of truth; builds logs + manifest
│   │                          + flag_config + artifact
│   ├── generate_capture.py    builds the pcap from _manifest.json
│   ├── official_solve.py      recovers both flags from evidence/ only
│   ├── flag_config.json       authoritative flag values (generated)
│   ├── _manifest.json         internal ground-truth (generated)
│   ├── _artifact_envelope.bin raw exfiltrated blob (generated)
│   ├── flag_config.example    documents the flag_config.json schema
│   └── solution.md             detailed solution write-up
│
├── tests/
│   ├── smoke.sh                full clean pipeline
│   ├── evidence_consistency.py pcap↔logs↔dhcp↔audit agreement
│   ├── payload_reconstruction.py  base64url round-trip + ordering
│   └── flag_validation.py      independent flag derivation + leak scan
│
└── docs/
    ├── challenge.md           participant-facing challenge write-up
    ├── hints.md               the five progressive hints
    ├── solution.md            solution path (organizer reference)
    └── deployment.md          deployment, reset, security notes
```

---

## Flags

| # | Objective | How recovered |
|---|-----------|--------------|
| 1 | Source attribution — the compromised workstation's MAC | Correlate the suspicious DNS queries' Ethernet source MAC in the pcap with the DHCP lease active during the incident window. |
| 2 | Payload recovery — the exfiltrated artifact | Order the `segNNN.<chunk>` DNS query labels by sequence, concatenate the chunks, restore Base64URL padding, decode, and read the envelope (whose SHA-256 self-check validates). |

Both flag values live only in `organizer/flag_config.json` (generated). The
official solve and the test suite both independently derive the flags from the
participant evidence and assert equality with `flag_config.json`.

---

## Security posture

- Organizer files (`generate_evidence.py`, `flag_config.json`, `_manifest.json`,
  `_artifact_envelope.bin`, `official_solve.py`, `solution.md`) are **never**
  copied into the portal image (`portal/Dockerfile` copies only `portal/` and
  `evidence/`).
- The portal serves evidence files from a **hard allowlist**; any other path
  (including `../` and `%2e%2e` traversal) returns 404.
- No flags appear in any participant-facing file (verified by
  `tests/flag_validation.py`).
- Container runs non-root, read-only filesystem, `no-new-privileges`, with CPU
  and memory limits.
- No real DNS queries, no external API dependency, no database.

See `docs/deployment.md` for the full security review.

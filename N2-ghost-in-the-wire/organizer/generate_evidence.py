#!/usr/bin/env python3
"""
N2 - GHOST IN THE WIRE
Evidence generator (ORGANIZER-ONLY).

This module is the single source of truth for every deterministic constant in
the challenge: fictional network identities, MAC addresses, the timeline, the
exfiltrated artifact, the Base64URL payload encoding, and the two flags.

It produces the participant-facing evidence files:
  evidence/dns_resolver.log
  evidence/dhcp_leases.csv
  evidence/repository_audit.log

And the organizer-only ground-truth artifacts consumed by generate_capture.py,
official_solve.py and the tests:
  organizer/_manifest.json          (all DNS events + background traffic + MAC map)
  organizer/_artifact_envelope.bin  (raw exfiltrated blob, ground truth)
  organizer/flag_config.json         (authoritative flags + integrity digests)

Deterministic: no randomness beyond a fixed seed, no network access, no real
DNS queries.

Usage:
  python3 organizer/generate_evidence.py
"""

from __future__ import annotations

import base64
import csv
import hashlib
import json
import os
import random
import sys
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

CHALLENGE_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EVIDENCE_DIR = os.path.join(CHALLENGE_ROOT, "evidence")
ORGANIZER_DIR = os.path.join(CHALLENGE_ROOT, "organizer")

# ===========================================================================
# Reproducibility
# ===========================================================================

SEED = 20261028  # fixed; do not change without regenerating all evidence

# ===========================================================================
# Timezone
#
# All human-readable timestamps in the evidence files are expressed in IST
# (Asia/Kolkata, UTC+05:30). The PCAP stores absolute Unix epoch seconds
# (timezone-neutral); generate_capture.py derives them from the same IST
# datetimes used here, so PCAP time == log time.
# ===========================================================================

TZ = ZoneInfo("Asia/Kolkata")
INCIDENT_DATE = "2026-10-28"  # Wednesday


def ist(year: int, month: int, day: int, hour: int, minute: int, second: int = 0) -> datetime:
    """Construct an IST-aware datetime."""
    return datetime(year, month, day, hour, minute, second, tzinfo=TZ)


# ===========================================================================
# Fictional organization & incident
# ===========================================================================

ORG_NAME = "Asterion Research Systems"
INCIDENT_REF = "ARS-2026-041"
EXFIL_DOMAIN = "sync.ghostwire.test"   # simulated exfiltration destination

# ===========================================================================
# Network identities
# All MAC addresses are locally-administered unicast (2nd bit of 1st octet set,
# multicast bit clear) so they are clearly fictional and never collide with a
# real vendor OUI.
# ===========================================================================

# Compromised research workstation (the target of the investigation)
COMPROMISED_IP = "10.40.2.17"
COMPROMISED_MAC = "6a:8c:47:2d:91:b3"
COMPROMISED_HOST = "ARS-WS-RES-07"
COMPROMISED_USER = "res07"          # repository account on this workstation

# Benign finance workstation
FINANCE_IP = "10.40.2.21"
FINANCE_MAC = "3e:f1:a9:74:0c:5a"
FINANCE_HOST = "ARS-WS-FIN-03"

# Other internal hosts (benign background traffic / lease noise)
OTHER_HOSTS = [
    ("10.40.2.34", "8a:11:5f:2c:e0:93", "ARS-WS-RES-12"),
    ("10.40.2.55", "0e:7d:a2:91:44:b6", "ARS-WS-OPS-04"),
    ("10.40.2.41", "1e:b4:a0:d7:6e:22", "ARS-WS-RES-09"),
    ("10.40.2.62", "4e:90:cc:8b:1f:ad", "ARS-WS-DEV-02"),
]

# Infrastructure
DNS_RESOLVER_IP = "10.40.0.53"
DNS_RESOLVER_MAC = "5a:2d:e8:11:6f:90"
DNS_RESOLVER_HOST = "ars-dns-01"

REPO_IP = "10.40.1.20"
REPO_MAC = "0a:9b:c3:7e:42:d1"
REPO_HOST = "ars-repo-01"

GATEWAY_IP = "10.40.0.1"
GATEWAY_MAC = "22:9a:f0:c4:18:77"

# A *prior* MAC that held the compromised IP on an earlier day. This forces
# participants to pick the lease that was ACTIVE during the incident window
# rather than blindly trusting any lease that mentions the IP.
COMPROMISED_PRIOR_MAC = "12:7e:c4:88:0a:1f"


def ip_mac_map() -> dict[str, str]:
    """Return IP -> MAC for every host that appears on the wire."""
    m = {
        COMPROMISED_IP: COMPROMISED_MAC,
        FINANCE_IP: FINANCE_MAC,
        DNS_RESOLVER_IP: DNS_RESOLVER_MAC,
        REPO_IP: REPO_MAC,
        GATEWAY_IP: GATEWAY_MAC,
    }
    for ip, mac, _ in OTHER_HOSTS:
        m[ip] = mac
    return m


IP_MAC = ip_mac_map()

# ===========================================================================
# Flags (authoritative values)
#
# Flag 1 is derived from the compromised workstation's MAC address.
# Flag 2 is a unique token embedded INSIDE the exfiltrated artifact. It is NOT
# equal to the repository resource name (which is visible in the audit log),
# so the audit log alone cannot reveal Flag 2 -- the DNS payload must actually
# be reconstructed and decoded.
# ===========================================================================

# MAC representation: lowercase hex, colon-separated (scapy's Ether.src form).
MAC_FORMAT_DOC = "lowercase hexadecimal, colon-separated (e.g. 6a:8c:47:2d:91:b3)"
FLAG1 = f"VVVFLAG{{{COMPROMISED_MAC}}}"

FLAG2 = "VVVFLAG{gh0st-in-dns-w1r3-4rs041}"
# The artifact's repository resource name (visible in audit log) is intentionally
# different from FLAG2 so the audit log is not a shortcut to Flag 2.
ARTIFACT_REPO_PATH = "research/chimera/chimera_phase2_briefing.md"
ARTIFACT_ID = "chimera_phase2_briefing"

# ===========================================================================
# Exfiltrated artifact
#
# A confidential research briefing. When participants reconstruct and decode
# the DNS payload they recover this envelope. The envelope carries an explicit
# SHA-256 of its content section so reconstruction integrity can be validated
# without any external service.
# ===========================================================================

ARTIFACT_CONTENT = """# Project CHIMERA - Phase 2 Research Briefing
Classification: CONFIDENTIAL // ARS INTERNAL ONLY
Document ID: ARS-CHM-2026-P2-017
Date: 2026-10-26
Author: Dr. M. Hegde, Principal Investigator

## 1. Summary
Phase 2 of Project CHIMERA validates the hybrid neural-material classifier
across three signal corpora. Initial results exceed the Phase 1 baseline by
14.2 percent under noisy-channel conditions.

## 2. Key Findings
- Classifier accuracy: 0.978 (+0.018 vs Phase 1)
- Inference latency: 9.3 ms on the ARS-Edge-7 accelerator
- Material stability index: 0.864 under thermal cycling 0-80C

## 3. Restricted Asset
The trained model weights and the proprietary CHIMERA feature extractor
remain restricted to the Asterion core research network. External disclosure
requires signed authorization from the Information Security Committee.

Recovery token for incident ARS-2026-041:
VVVFLAG{gh0st-in-dns-w1r3-4rs041}

## 4. Next Steps
Proceed to Phase 3 field trials pending committee review.
"""


def build_envelope(content: str = ARTIFACT_CONTENT) -> bytes:
    """Build the exfiltrated envelope bytes (UTF-8).

    The envelope is a small, human-readable manifest wrapping the artifact
    content with an explicit SHA-256 integrity tag.
    """
    content_bytes = content.encode("utf-8")
    digest = hashlib.sha256(content_bytes).hexdigest()
    header = (
        "ARS-EXFIL/1\n"
        f"artifact_id: {ARTIFACT_ID}\n"
        f"filename: {ARTIFACT_REPO_PATH.split('/')[-1]}\n"
        f"content_sha256: {digest}\n"
        "---BEGIN CONTENT---\n"
    )
    footer = "\n---END CONTENT---\n"
    return (header + content + footer).encode("utf-8")


def envelope_sha256(envelope: bytes | None = None) -> str:
    """SHA-256 of the full envelope bytes (used as the artifact-level digest)."""
    if envelope is None:
        envelope = build_envelope()
    return hashlib.sha256(envelope).hexdigest()


ENVELOPE_BYTES = build_envelope()
ENVELOPE_B64URL = base64.urlsafe_b64encode(ENVELOPE_BYTES).decode("ascii").rstrip("=")
ENVELOPE_SHA256 = envelope_sha256(ENVELOPE_BYTES)
CONTENT_SHA256 = hashlib.sha256(ARTIFACT_CONTENT.encode("utf-8")).hexdigest()
ENVELOPE_SIZE = len(ENVELOPE_BYTES)

# ===========================================================================
# DNS payload encoding parameters
# ===========================================================================

# Each Base64URL chunk is embedded as its own DNS label. 48 chars keeps every
# label well under the 63-byte DNS label limit and keeps total qname length far
# under the 253-byte limit.
CHUNK_SIZE = 48
SEQ_WIDTH = 3  # zero-padded segment index: seg000 .. segNNN
SEQ_PREFIX = "seg"  # leftmost label of a data-bearing query: segNNN
DATA_DOMAIN = EXFIL_DOMAIN  # segNNN.<chunk>.sync.ghostwire.test

# Control (non-data) queries to the exfil domain, used as tunnel handshake /
# keepalive / close markers. They do NOT match the segNNN.<chunk> pattern, so
# participants must filter to data-bearing queries only.
CONTROL_QUERIES = ["init", "ping", "done"]


def encode_segments(envelope: bytes = ENVELOPE_BYTES,
                    chunk_size: int = CHUNK_SIZE) -> list[tuple[int, str]]:
    """Return [(seq, chunk), ...] for the envelope, Base64URL, unpadded."""
    b64 = base64.urlsafe_b64encode(envelope).decode("ascii").rstrip("=")
    chunks = [b64[i:i + chunk_size] for i in range(0, len(b64), chunk_size)]
    return [(i, chunk) for i, chunk in enumerate(chunks)]


def seg_label(seq: int) -> str:
    return f"{SEQ_PREFIX}{seq:0{SEQ_WIDTH}d}"


def data_qname(seq: int, chunk: str) -> str:
    """Full DNS query name for one data segment."""
    return f"{seg_label(seq)}.{chunk}.{EXFIL_DOMAIN}"


def control_qname(kind: str) -> str:
    return f"{kind}.{EXFIL_DOMAIN}"


def is_data_qname(qname: str) -> bool:
    """True if qname matches the data-bearing pattern segNNN.<chunk>.<domain>."""
    qname = qname.rstrip(".").lower()
    parts = qname.split(".")
    if len(parts) < 3:
        return False
    if not parts[0].startswith(SEQ_PREFIX):
        return False
    num = parts[0][len(SEQ_PREFIX):]
    return num.isdigit() and len(num) == SEQ_WIDTH


# ===========================================================================
# Timeline (IST)
# ===========================================================================

# DHCP leases ---------------------------------------------------------------
LEASE_COMPROMISED_START = ist(2026, 10, 28, 8, 14, 23)
LEASE_COMPROMISED_DURATION = timedelta(hours=8)

# Prior (expired) lease for the SAME ip but a DIFFERENT mac, days earlier.
LEASE_PRIOR_START = ist(2026, 10, 20, 9, 3, 11)
LEASE_PRIOR_DURATION = timedelta(hours=8)

LEASE_FINANCE_START = ist(2026, 10, 28, 8, 15, 2)
LEASE_FINANCE_DURATION = timedelta(hours=8)

# Repository audit event (the trigger) -------------------------------------
REPO_AUDIT_AT = ist(2026, 10, 28, 14, 2, 17)

# Suspicious DNS exfiltration window ----------------------------------------
EXFIL_START = ist(2026, 10, 28, 14, 5, 0)     # init query
EXFIL_DATA_START = ist(2026, 10, 28, 14, 5, 3)
EXFIL_DATA_INTERVAL = timedelta(seconds=2)     # one segment every 2s
EXFIL_KEEPALIVE_AT = ist(2026, 10, 28, 14, 5, 40)
EXFIL_DONE_AT = ist(2026, 10, 28, 14, 6, 32)

# Benign background traffic window (morning) -------------------------------
BENIGN_WINDOW_START = ist(2026, 10, 28, 9, 0, 0)
BENIGN_WINDOW_END = ist(2026, 10, 28, 14, 30, 0)


def iso(dt: datetime) -> str:
    """ISO-8601 with +05:30 offset, second precision (matches log format)."""
    return dt.strftime("%Y-%m-%dT%H:%M:%S%z")[:-2] + ":" + dt.strftime("%z")[-2:]


# ===========================================================================
# Authoritative flag configuration (written to organizer/flag_config.json)
# ===========================================================================

def flag_config() -> dict:
    return {
        "challenge": "N2",
        "name": "GHOST IN THE WIRE",
        "incident_ref": INCIDENT_REF,
        "flag1": {
            "objective": "Source attribution (compromised workstation MAC)",
            "mac": COMPROMISED_MAC,
            "mac_format": MAC_FORMAT_DOC,
            "value": FLAG1,
        },
        "flag2": {
            "objective": "Payload recovery (exfiltrated artifact)",
            "artifact_id": ARTIFACT_ID,
            "artifact_repo_path": ARTIFACT_REPO_PATH,
            "artifact_envelope_sha256": ENVELOPE_SHA256,
            "content_sha256": CONTENT_SHA256,
            "envelope_size": ENVELOPE_SIZE,
            "value": FLAG2,
        },
        "encoding": {
            "scheme": "Base64URL (RFC 4648 URL-safe), padding stripped",
            "chunk_label_size": CHUNK_SIZE,
            "sequence_label": f"{SEQ_PREFIX}NNN ({SEQ_WIDTH}-digit, zero-padded)",
            "qname_template": f"{SEQ_PREFIX}NNN.<chunk>.{EXFIL_DOMAIN}",
            "control_queries": CONTROL_QUERIES,
            "num_segments": len(encode_segments()),
            "b64url_len": len(ENVELOPE_B64URL),
        },
        "network": {
            "compromised_ip": COMPROMISED_IP,
            "compromised_mac": COMPROMISED_MAC,
            "compromised_prior_mac": COMPROMISED_PRIOR_MAC,
            "compromised_host": COMPROMISED_HOST,
            "dns_resolver_ip": DNS_RESOLVER_IP,
            "repo_ip": REPO_IP,
            "exfil_domain": EXFIL_DOMAIN,
        },
        "timezone": "Asia/Kolkata (UTC+05:30); PCAP stores Unix epoch seconds",
        "seed": SEED,
    }


def flag_config_json() -> str:
    return json.dumps(flag_config(), indent=2, sort_keys=True) + "\n"


# ===========================================================================
# Benign background DNS lookups (ordinary hostnames). These are simulated and
# never sent to a real resolver. A/AAAA/PTR/TXT mix makes the resolver log look
# realistic.
# ===========================================================================

BENIGN_DOMAINS = [
    "updates.asterion.test",
    "repo.asterion.test",
    "wiki.asterion.test",
    "cdn.asterion.test",
    "mail.asterion.test",
    "ntp.asterion.test",
    "packages.ubuntu.com",
    "api.github.com",
    "registry.npmjs.org",
    "pypi.org",
    "dl.fedoraproject.org",
    "security.cloudflareinsights.com",
    "ocsp.digicert.com",
    "fonts.googleapis.com",
    "avatars.githubusercontent.com",
]

BENIGN_QTYPES = ["A", "AAAA", "PTR", "TXT", "MX"]

RCODE_NAMES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 5: "REFUSED"}


def _dns_event(ts, src_ip, qname, qtype="A", rcode=0, answer=None):
    """One DNS transaction record (query + resolver response)."""
    return {
        "ts": ts,                 # IST-aware datetime
        "src_ip": src_ip,
        "src_mac": IP_MAC.get(src_ip, "00:00:00:00:00:00"),
        "qname": qname,
        "qtype": qtype,
        "rcode": rcode,           # numeric rcode
        "rcode_name": RCODE_NAMES.get(rcode, "UNKNOWN"),
        "answer": answer,         # e.g. resolved A record, or None
        "suspicious": qname.lower().endswith(EXFIL_DOMAIN),
    }


def _fake_answer(qname: str) -> str | None:
    """A plausible resolved address for internal asterion.test hostnames."""
    q = qname.lower()
    if q == "repo.asterion.test":
        return REPO_IP
    if q == "updates.asterion.test":
        return "10.40.1.30"
    if q == "wiki.asterion.test":
        return "10.40.1.40"
    if q == "mail.asterion.test":
        return "10.40.1.50"
    if q == "ntp.asterion.test":
        return "10.40.0.12"
    if q == "cdn.asterion.test":
        return "10.40.1.60"
    if q.endswith(".in-addr.arpa"):
        return COMPROMISED_IP  # a PTR we can answer
    # external simulated hosts -> pretend resolved by upstream cache
    return None


# ===========================================================================
# Build the full DNS event list (shared by resolver log and PCAP)
# ===========================================================================

def build_dns_events() -> list[dict]:
    rng = random.Random(SEED)
    events: list[dict] = []

    # --- Benign morning background traffic from several workstations -------
    benign_hosts = [COMPROMISED_IP, FINANCE_IP] + [h[0] for h in OTHER_HOSTS]
    # Spread ~46 benign queries across the benign window.
    n_benign = 46
    span = int((BENIGN_WINDOW_END - BENIGN_WINDOW_START).total_seconds())
    for i in range(n_benign):
        offset = int(span * (i + 1) / (n_benign + 1))
        # jitter so they aren't perfectly even
        offset += rng.randint(-40, 40)
        ts = BENIGN_WINDOW_START + timedelta(seconds=offset)
        src_ip = rng.choice(benign_hosts)
        qname = rng.choice(BENIGN_DOMAINS)
        qtype = rng.choice(BENIGN_QTYPES)
        # Internal asterion.test lookups resolve; external ones sometimes NOERROR
        # with a cached answer, sometimes NXDOMAIN (transient upstream failure).
        rcode = 0
        answer = _fake_answer(qname)
        if answer is None and rng.random() < 0.18:
            rcode = 3  # NXDOMAIN for some external lookups (realistic noise)
        events.append(_dns_event(ts, src_ip, qname, qtype, rcode, answer))

    # A couple of benign PTR lookups from the resolver's perspective
    ptr_ts = BENIGN_WINDOW_START + timedelta(minutes=37)
    events.append(_dns_event(ptr_ts, FINANCE_IP,
                             "17.2.40.10.in-addr.arpa", "PTR", 0, COMPROMISED_HOST))
    events.append(_dns_event(ptr_ts + timedelta(seconds=4), COMPROMISED_IP,
                             "21.2.40.10.in-addr.arpa", "PTR", 0, FINANCE_HOST))

    # --- Benign DNS right before the incident from the compromised host -----
    events.append(_dns_event(REPO_AUDIT_AT - timedelta(seconds=8),
                             COMPROMISED_IP, "repo.asterion.test", "A", 0, REPO_IP))
    events.append(_dns_event(REPO_AUDIT_AT - timedelta(seconds=3),
                             COMPROMISED_IP, "api.github.com", "A", 0, "140.82.121.6"))

    # --- Suspicious exfiltration sequence (from the compromised host) ------
    # 1. tunnel init
    events.append(_dns_event(EXFIL_START, COMPROMISED_IP,
                             control_qname("init"), "A", 3, None))
    # 2. data segments
    for seq, chunk in encode_segments():
        ts = EXFIL_DATA_START + EXFIL_DATA_INTERVAL * seq
        events.append(_dns_event(ts, COMPROMISED_IP,
                                 data_qname(seq, chunk), "A", 3, None))
    # 3. keepalive
    events.append(_dns_event(EXFIL_KEEPALIVE_AT, COMPROMISED_IP,
                             control_qname("ping"), "A", 3, None))
    # 4. tunnel close
    events.append(_dns_event(EXFIL_DONE_AT, COMPROMISED_IP,
                             control_qname("done"), "A", 3, None))

    # --- A benign lookup from the finance host during the incident window --
    events.append(_dns_event(EXFIL_START + timedelta(seconds=11),
                             FINANCE_IP, "mail.asterion.test", "A", 0, "10.40.1.50"))
    events.append(_dns_event(EXFIL_DONE_AT + timedelta(seconds=6),
                             OTHER_HOSTS[0][0], "cdn.asterion.test", "A", 0, "10.40.1.60"))

    # Sort by time for a tidy log
    events.sort(key=lambda e: e["ts"])
    return events


# ===========================================================================
# Background (non-DNS) traffic for the PCAP: ARP + HTTP to the repo.
# These are described at the packet level so generate_capture.py can realize
# them without re-deriving timing.
# ===========================================================================

def build_background_packets() -> list[dict]:
    pkts: list[dict] = []

    # Gratuitous / who-has ARP for the resolver and gateway at boot-ish times.
    for ts, who, frm in [
        (BENIGN_WINDOW_START + timedelta(seconds=12), DNS_RESOLVER_IP, COMPROMISED_IP),
        (BENIGN_WINDOW_START + timedelta(seconds=13), GATEWAY_IP, COMPROMISED_IP),
        (BENIGN_WINDOW_START + timedelta(seconds=40), REPO_IP, COMPROMISED_IP),
        (BENIGN_WINDOW_START + timedelta(minutes=8, seconds=5), DNS_RESOLVER_IP, FINANCE_IP),
        (REPO_AUDIT_AT - timedelta(seconds=1), REPO_IP, COMPROMISED_IP),
    ]:
        pkts.append({
            "kind": "arp",
            "ts": ts,
            "sender_ip": frm,
            "sender_mac": IP_MAC[frm],
            "target_ip": who,
        })

    # A benign HTTP GET to the internal repo from the finance host (morning).
    http_ts = BENIGN_WINDOW_START + timedelta(minutes=22)
    pkts.append({
        "kind": "tcp_syn",
        "ts": http_ts,
        "src_ip": FINANCE_IP,
        "src_mac": IP_MAC[FINANCE_IP],
        "dst_ip": REPO_IP,
        "dst_mac": IP_MAC[REPO_IP],
        "sport": 51122,
        "dport": 80,
    })
    pkts.append({
        "kind": "tcp_synack",
        "ts": http_ts + timedelta(milliseconds=4),
        "src_ip": REPO_IP,
        "src_mac": IP_MAC[REPO_IP],
        "dst_ip": FINANCE_IP,
        "dst_mac": IP_MAC[FINANCE_IP],
        "sport": 80,
        "dport": 51122,
    })

    # The compromised host fetches the artifact via HTTP right after the audit
    # event (this is the in-network counterpart to the audit log entry).
    fetch_ts = REPO_AUDIT_AT + timedelta(seconds=2)
    pkts.append({
        "kind": "tcp_syn",
        "ts": fetch_ts,
        "src_ip": COMPROMISED_IP,
        "src_mac": IP_MAC[COMPROMISED_IP],
        "dst_ip": REPO_IP,
        "dst_mac": IP_MAC[REPO_IP],
        "sport": 49154,
        "dport": 80,
    })
    pkts.append({
        "kind": "tcp_synack",
        "ts": fetch_ts + timedelta(milliseconds=3),
        "src_ip": REPO_IP,
        "src_mac": IP_MAC[REPO_IP],
        "dst_ip": COMPROMISED_IP,
        "dst_mac": IP_MAC[COMPROMISED_IP],
        "sport": 80,
        "dport": 49154,
    })

    pkts.sort(key=lambda p: p["ts"])
    return pkts


# ===========================================================================
# dns_resolver.log
# ===========================================================================

def write_resolver_log(events: list[dict], path: str) -> None:
    header = (
        f"# Asterion Research Systems - Internal DNS Resolver Log\n"
        f"# Host: {DNS_RESOLVER_HOST} ({DNS_RESOLVER_IP})\n"
        f"# Incident reference: {INCIDENT_REF}\n"
        f"# All timestamps in IST (Asia/Kolkata, UTC+05:30)\n"
        f"# Fields: timestamp src_ip qname qtype rcode answer\n"
    )
    with open(path, "w", encoding="utf-8") as f:
        f.write(header)
        for e in events:
            ts = iso(e["ts"])
            answer = e["answer"] if e["answer"] is not None else "-"
            f.write(f"{ts} {e['src_ip']} {e['qname']} {e['qtype']} "
                    f"{e['rcode']}({e['rcode_name']}) {answer}\n")


# ===========================================================================
# dhcp_leases.csv
# ===========================================================================

def write_dhcp_leases(path: str) -> None:
    rows = [
        # (lease_start, lease_end, ip, mac, hostname, note)
        # Prior, EXPIRED lease for the compromised IP -- different MAC.
        (LEASE_PRIOR_START,
         LEASE_PRIOR_START + LEASE_PRIOR_DURATION,
         COMPROMISED_IP, COMPROMISED_PRIOR_MAC, COMPROMISED_HOST, "renewed"),
        # Active lease during the incident for the compromised IP -- the real MAC.
        (LEASE_COMPROMISED_START,
         LEASE_COMPROMISED_START + LEASE_COMPROMISED_DURATION,
         COMPROMISED_IP, COMPROMISED_MAC, COMPROMISED_HOST, "active"),
        # Finance host
        (LEASE_FINANCE_START,
         LEASE_FINANCE_START + LEASE_FINANCE_DURATION,
         FINANCE_IP, FINANCE_MAC, FINANCE_HOST, "active"),
        # Other hosts (benign noise)
    ]
    # add the other hosts as currently-active leases issued earlier today
    for i, (ip, mac, host) in enumerate(OTHER_HOSTS):
        start = BENIGN_WINDOW_START + timedelta(minutes=3 + i * 2)
        rows.append((start, start + LEASE_COMPROMISED_DURATION, ip, mac, host, "active"))

    # A stale expired lease for an unrelated host (more noise)
    rows.append((LEASE_PRIOR_START - timedelta(days=1),
                 LEASE_PRIOR_START - timedelta(days=1) + timedelta(hours=8),
                 OTHER_HOSTS[1][0], OTHER_HOSTS[1][1], OTHER_HOSTS[1][2], "expired"))

    rows.sort(key=lambda r: r[0])
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["lease_start", "lease_end", "ip", "mac", "hostname", "state"])
        for start, end, ip, mac, host, state in rows:
            w.writerow([iso(start), iso(end), ip, mac, host, state])


# ===========================================================================
# repository_audit.log
# ===========================================================================

def write_audit_log(path: str) -> None:
    rng = random.Random(SEED + 7)
    events: list[dict] = []

    def add(ts, client_ip, user, resource, op, status, size=None):
        events.append({
            "ts": ts, "client_ip": client_ip, "user": user,
            "resource": resource, "op": op, "status": status, "size": size,
        })

    # Benign repository activity across the morning
    users = [
        (FINANCE_IP, "fin03", "ARS-WS-FIN-03"),
        (OTHER_HOSTS[0][0], "res12", "ARS-WS-RES-12"),
        (OTHER_HOSTS[2][0], "res09", "ARS-WS-RES-09"),
        (OTHER_HOSTS[3][0], "dev02", "ARS-WS-DEV-02"),
    ]
    resources = [
        "research/public/weekly-status.md",
        "research/public/roadmap-2026.md",
        "ops/runbooks/deploy-repo.md",
        "research/public/chimera-overview.md",
        "finance/budget-2026q4.csv",
    ]
    for i in range(14):
        offset = int((BENIGN_WINDOW_END - BENIGN_WINDOW_START).total_seconds()
                     * (i + 1) / 15)
        ts = BENIGN_WINDOW_START + timedelta(seconds=offset) + timedelta(seconds=rng.randint(-20, 20))
        ip, user, host = rng.choice(users)
        add(ts, ip, user, rng.choice(resources),
            rng.choice(["read", "list", "clone"]), "200", rng.randint(1200, 90000))

    # The incident event: compromised host exports the confidential artifact.
    add(REPO_AUDIT_AT, COMPROMISED_IP, COMPROMISED_USER,
        ARTIFACT_REPO_PATH, "export", "200", ENVELOPE_SIZE)

    # A follow-up benign access shortly after, from another host
    add(REPO_AUDIT_AT + timedelta(seconds=45), OTHER_HOSTS[0][0], "res12",
        "research/public/roadmap-2026.md", "read", "200", 4321)

    events.sort(key=lambda e: e["ts"])
    header = (
        f"# Asterion Research Systems - Research Repository Audit Log\n"
        f"# Host: {REPO_HOST} ({REPO_IP})\n"
        f"# Incident reference: {INCIDENT_REF}\n"
        f"# All timestamps in IST (Asia/Kolkata, UTC+05:30)\n"
        f"# Fields: timestamp client_ip user resource operation status size_bytes\n"
    )
    with open(path, "w", encoding="utf-8") as f:
        f.write(header)
        for e in events:
            f.write(f"{iso(e['ts'])} {e['client_ip']} {e['user']} "
                    f"{e['resource']} {e['op']} {e['status']} {e['size']}\n")


# ===========================================================================
# Manifest (organizer-only, consumed by generate_capture.py + tests)
# ===========================================================================

def write_manifest(events: list[dict], bg: list[dict], path: str) -> None:
    manifest = {
        "challenge": "N2",
        "incident_ref": INCIDENT_REF,
        "timezone": "Asia/Kolkata (UTC+05:30); PCAP epoch derived from these IST datetimes",
        "dns_resolver_ip": DNS_RESOLVER_IP,
        "seed": SEED,
        "mac_map": IP_MAC,
        "dns_events": [
            {**{k: v for k, v in e.items() if k != "ts"},
             "ts_iso": iso(e["ts"]),
             "ts_epoch": e["ts"].timestamp()}
            for e in events
        ],
        "background_packets": [
            {**{k: v for k, v in p.items() if k != "ts"},
             "ts_iso": iso(p["ts"]),
             "ts_epoch": p["ts"].timestamp()}
            for p in bg
        ],
        "payload": {
            "envelope_sha256": ENVELOPE_SHA256,
            "content_sha256": CONTENT_SHA256,
            "envelope_size": ENVELOPE_SIZE,
            "b64url_len": len(ENVELOPE_B64URL),
            "num_segments": len(encode_segments()),
            "chunk_size": CHUNK_SIZE,
        },
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, sort_keys=True)


# ===========================================================================
# main
# ===========================================================================

def main() -> int:
    os.makedirs(EVIDENCE_DIR, exist_ok=True)
    os.makedirs(ORGANIZER_DIR, exist_ok=True)

    events = build_dns_events()
    bg = build_background_packets()

    write_resolver_log(events, os.path.join(EVIDENCE_DIR, "dns_resolver.log"))
    write_dhcp_leases(os.path.join(EVIDENCE_DIR, "dhcp_leases.csv"))
    write_audit_log(os.path.join(EVIDENCE_DIR, "repository_audit.log"))

    write_manifest(events, bg, os.path.join(ORGANIZER_DIR, "_manifest.json"))
    with open(os.path.join(ORGANIZER_DIR, "_artifact_envelope.bin"), "wb") as f:
        f.write(ENVELOPE_BYTES)
    with open(os.path.join(ORGANIZER_DIR, "flag_config.json"), "w", encoding="utf-8") as f:
        f.write(flag_config_json())

    susp = [e for e in events if e["suspicious"]]
    data = [e for e in events if is_data_qname(e["qname"])]
    print(f"[generate_evidence] wrote 3 evidence files to {EVIDENCE_DIR}")
    print(f"  dns_resolver.log   : {len(events)} DNS events ({len(susp)} suspicious, "
          f"{len(data)} data segments)")
    print(f"  dhcp_leases.csv    : written")
    print(f"  repository_audit.log: written")
    print(f"[generate_evidence] wrote organizer/flag_config.json, _manifest.json, "
          f"_artifact_envelope.bin")
    print(f"[generate_evidence] envelope={ENVELOPE_SIZE}B  "
          f"b64url={len(ENVELOPE_B64URL)}  segments={len(encode_segments())}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

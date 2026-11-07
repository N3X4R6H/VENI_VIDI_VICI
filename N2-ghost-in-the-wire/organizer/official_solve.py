#!/usr/bin/env python3
"""
N2 - GHOST IN THE WIRE
Official solve (ORGANIZER-ONLY).

This script performs the INTENDED investigation path from the participant
side: it reads ONLY the four evidence files under evidence/ and reconstructs
both flags. It does not import any organizer module for the solution logic;
organizer/flag_config.json is read solely to compare the recovered flags
against the authoritative values for verification.

Solve path:
  Stage 1  Establish the incident window      (dns_resolver.log)
  Stage 2  Identify suspicious DNS behavior    (sync.ghostwire.test)
  Stage 3  Attribute the source workstation    (pcap + dns_resolver.log + dhcp)
  Stage 4  Correlate repository activity      (repository_audit.log)
  Stage 5  Reconstruct the DNS payload         (pcap data labels)
  Stage 6  Decode and validate the artifact    (Base64URL + SHA-256)

Usage:
  python3 organizer/official_solve.py
  python3 organizer/official_solve.py --evidence evidence/
"""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

CHALLENGE_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_EVIDENCE = os.path.join(CHALLENGE_ROOT, "evidence")

IST = ZoneInfo("Asia/Kolkata")

EXFIL_SUFFIX = "sync.ghostwire.test"
SEQ_RE = re.compile(r"^seg(\d{3})$")

# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------

def parse_resolver_log(path: str):
    rows = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # timestamp src_ip qname qtype rcode(num) answer
            parts = line.split()
            ts = datetime.fromisoformat(parts[0])
            src_ip = parts[1]
            qname = parts[2]
            qtype = parts[3]
            rcode_field = parts[4]            # e.g. 3(NXDOMAIN)
            rcode = int(rcode_field.split("(")[0])
            rcode_name = rcode_field.split("(")[1].rstrip(")") if "(" in rcode_field else ""
            answer = parts[5] if len(parts) > 5 else "-"
            rows.append({"ts": ts, "src_ip": src_ip, "qname": qname,
                         "qtype": qtype, "rcode": rcode, "rcode_name": rcode_name,
                         "answer": answer if answer != "-" else None})
    return rows


def parse_dhcp_leases(path: str):
    rows = []
    with open(path, "r", encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            row["lease_start"] = datetime.fromisoformat(row["lease_start"])
            row["lease_end"] = datetime.fromisoformat(row["lease_end"])
            rows.append(row)
    return rows


def parse_audit_log(path: str):
    rows = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            ts = datetime.fromisoformat(parts[0])
            rows.append({"ts": ts, "client_ip": parts[1], "user": parts[2],
                         "resource": parts[3], "op": parts[4], "status": parts[5],
                         "size": int(parts[6]) if len(parts) > 6 else 0})
    return rows


def iter_pcap(path: str):
    """Yield DNS query frames from the PCAP (scapy)."""
    from scapy.all import rdpcap, DNS, Ether, IP  # local import; scapy optional
    pkts = rdpcap(path)
    for p in pkts:
        if p.haslayer(DNS) and p[DNS].qr == 0 and p.haslayer(Ether) and p.haslayer(IP):
            yield p, DNS, Ether, IP


# ---------------------------------------------------------------------------
# Stages
# ---------------------------------------------------------------------------

def stage1_window(resolver_rows):
    """Find the densest suspicious-to domain window. Returns (domain, count, lo, hi)."""
    by_domain = {}
    for r in resolver_rows:
        qn = r["qname"].lower()
        # treat the rightmost two labels as the 'destination domain'
        parts = qn.split(".")
        domain = ".".join(parts[-2:]) if len(parts) >= 2 else qn
        by_domain.setdefault(domain, []).append(r["ts"])
    # rank by count, then by longest-label signature (suspicious = long labels)
    ranked = sorted(by_domain.items(), key=lambda kv: (-len(kv[1]), kv[0]))
    dom, times = ranked[0]
    return dom, len(times), min(times), max(times)


def stage2_suspicious(resolver_rows):
    """Return suspicious resolver rows: qname ends with exfil domain AND has long labels."""
    sus = []
    for r in resolver_rows:
        qn = r["qname"].lower()
        if not qn.endswith(EXFIL_SUFFIX):
            continue
        # suspicious if it has a long (>20 char) subdomain label OR matches seg pattern
        labels = qn.split(".")
        long_label = any(len(lbl) > 20 for lbl in labels)
        if long_label or SEQ_RE.match(labels[0]):
            sus.append(r)
    return sus


def stage3_attribute(sus_rows, leases, pcap_path):
    """Attribute suspicious traffic to a MAC via pcap + DHCP correlation."""
    src_ips = {r["src_ip"] for r in sus_rows}
    if len(src_ips) != 1:
        raise SystemExit(f"[stage3] expected single suspicious src IP, got {src_ips}")
    src_ip = next(iter(src_ips))

    # MAC from the PCAP (Ethernet source of the suspicious DNS queries)
    pcap_macs = set()
    pcap_qnames = []
    for p, DNS, Ether, IP in iter_pcap(pcap_path):
        qname = p[DNS].qd.qname.decode(errors="replace").rstrip(".")
        if qname.lower().endswith(EXFIL_SUFFIX):
            pcap_macs.add(p[Ether].src)
            pcap_qnames.append((p[Ether].src, p[IP].src, qname))
    if len(pcap_macs) != 1:
        raise SystemExit(f"[stage3] expected single suspicious src MAC in pcap, got {pcap_macs}")
    pcap_mac = next(iter(pcap_macs))

    # DHCP: pick the lease ACTIVE during the incident window for src_ip
    incident_ts = min(r["ts"] for r in sus_rows)
    matching = [l for l in leases if l["ip"] == src_ip
                and l["lease_start"] <= incident_ts <= l["lease_end"]]
    if not matching:
        raise SystemExit(f"[stage3] no active DHCP lease covers {src_ip} at {incident_ts}")
    # there may be >1 (e.g. renewed) -> pick the active one whose mac matches pcap
    dhcp_mac = None
    for l in matching:
        if l["mac"].lower() == pcap_mac.lower() and l["state"] == "active":
            dhcp_mac = l["mac"]
            break
    if dhcp_mac is None:
        # fall back: any active lease whose mac matches
        for l in matching:
            if l["state"] == "active" and l["mac"].lower() == pcap_mac.lower():
                dhcp_mac = l["mac"]
                break
    if dhcp_mac is None:
        raise SystemExit(f"[stage3] DHCP/PCAP MAC mismatch: pcap={pcap_mac} "
                         f"leases={[l['mac'] for l in matching]}")
    return src_ip, pcap_mac, dhcp_mac, incident_ts, pcap_qnames


def stage4_repo(audit_rows, src_ip):
    """Find the repository access from the compromised host near the incident."""
    # any audit row from src_ip
    hits = [a for a in audit_rows if a["client_ip"] == src_ip]
    return hits


def stage5_reconstruct(pcap_path):
    """Extract data-bearing qnames, order by seq, concatenate chunks."""
    segs = {}
    for p, DNS, Ether, IP in iter_pcap(pcap_path):
        qname = p[DNS].qd.qname.decode(errors="replace").rstrip(".")
        labels = qname.split(".")
        if len(labels) < 2:
            continue
        m = SEQ_RE.match(labels[0])
        if not m:
            continue
        seq = int(m.group(1))
        chunk = labels[1]
        if seq in segs and segs[seq] != chunk:
            raise SystemExit(f"[stage5] conflicting chunk for seq {seq}")
        segs[seq] = chunk
    expected = list(range(max(segs) + 1)) if segs else []
    missing = [s for s in expected if s not in segs]
    if missing:
        raise SystemExit(f"[stage5] missing segments: {missing}")
    ordered = [segs[s] for s in sorted(segs)]
    return "".join(ordered), sorted(segs)


def restore_padding(b64url: str) -> str:
    return b64url + "=" * ((-len(b64url)) % 4)


def stage6_decode(b64url: str):
    raw = base64.urlsafe_b64decode(restore_padding(b64url))
    text = raw.decode("utf-8", errors="replace")
    return raw, text


def extract_flag2(text: str) -> str | None:
    m = re.search(r"VVVFLAG\{[^}]+\}", text)
    return m.group(0) if m else None


def parse_envelope(raw: bytes):
    """Return (header_dict, content_str, ok). Validates ARS-EXFIL/1 envelope."""
    text = raw.decode("utf-8", errors="replace")
    if not text.startswith("ARS-EXFIL/1"):
        return None, None, False
    try:
        header_block, body = text.split("---BEGIN CONTENT---\n", 1)
        content, _ = body.split("\n---END CONTENT---", 1)
    except ValueError:
        return None, None, False
    header = {}
    for line in header_block.strip().splitlines()[1:]:
        if ": " in line:
            k, v = line.split(": ", 1)
            header[k] = v
    expected = header.get("content_sha256")
    actual = hashlib.sha256(content.encode("utf-8")).hexdigest()
    return header, content, (expected == actual)


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--evidence", default=DEFAULT_EVIDENCE)
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    ev = args.evidence.rstrip("/")
    resolver_log = os.path.join(ev, "dns_resolver.log")
    dhcp_csv = os.path.join(ev, "dhcp_leases.csv")
    audit_log = os.path.join(ev, "repository_audit.log")
    pcap = os.path.join(ev, "network_capture.pcap")
    for p in (resolver_log, dhcp_csv, audit_log, pcap):
        if not os.path.exists(p):
            print(f"[solve] missing evidence file: {p}", file=sys.stderr)
            return 2

    resolver_rows = parse_resolver_log(resolver_log)
    leases = parse_dhcp_leases(dhcp_csv)
    audit_rows = parse_audit_log(audit_log)

    # Stage 1 -- window
    dom, n, lo, hi = stage1_window(resolver_rows)
    # Stage 2 -- suspicious
    sus = stage2_suspicious(resolver_rows)

    # Stage 3 -- attribute
    src_ip, pcap_mac, dhcp_mac, incident_ts, pcap_qnames = stage3_attribute(sus, leases, pcap)

    # Stage 4 -- repo
    repo_hits = stage4_repo(audit_rows, src_ip)

    # Stage 5 -- reconstruct
    b64url, seqs = stage5_reconstruct(pcap)

    # Stage 6 -- decode
    raw, text = stage6_decode(b64url)
    header, content, integ_ok = parse_envelope(raw)
    flag2 = extract_flag2(text)
    flag1 = f"VVVFLAG{{{pcap_mac}}}"

    # Report
    out = []
    out.append("=" * 72)
    out.append("N2 - GHOST IN THE WIRE -- official solve")
    out.append("=" * 72)
    out.append("")
    out.append(f"[Stage 1] Most-querered destination domain: {dom} ({n} queries)")
    out.append(f"          window: {lo.isoformat()} .. {hi.isoformat()}")
    out.append("")
    out.append(f"[Stage 2] Suspicious (exfil-domain) DNS queries: {len(sus)}")
    out.append("          examples:")
    for r in sus[:3]:
        out.append(f"            {r['ts'].isoformat()} {r['src_ip']} {r['qname']}")
    out.append(f"            ... ({len([x for x in sus if SEQ_RE.match(x['qname'].split('.')[0])])} data segments)")
    out.append("")
    out.append(f"[Stage 3] Suspicious source IP : {src_ip}")
    out.append(f"          Source MAC (from PCAP Ethernet header): {pcap_mac}")
    out.append(f"          DHCP lease active at {incident_ts.isoformat()} for {src_ip}:")
    out.append(f"            mac={dhcp_mac}  (corroborates PCAP)")
    out.append(f"          >>> Flag 1 = {flag1}")
    out.append("")
    out.append(f"[Stage 4] Repository access from {src_ip}:")
    for h in repo_hits:
        out.append(f"            {h['ts'].isoformat()} user={h['user']} "
                   f"{h['resource']} {h['op']} status={h['status']} size={h['size']}")
    out.append("")
    out.append(f"[Stage 5] Reconstructed {len(seqs)} data segments (seq {seqs[0]}..{seqs[-1]})")
    out.append(f"          Base64URL length: {len(b64url)}")
    out.append("")
    out.append(f"[Stage 6] Decoded envelope: {len(raw)} bytes")
    if header:
        out.append(f"          artifact_id: {header.get('artifact_id')}")
        out.append(f"          content_sha256 (in envelope): {header.get('content_sha256')}")
        out.append(f"          content_sha256 (recomputed) : {hashlib.sha256(content.encode()).hexdigest()}")
        out.append(f"          integrity check: {'PASS' if integ_ok else 'FAIL'}")
    out.append(f"          >>> Flag 2 = {flag2}")
    out.append("")
    out.append("=" * 72)
    print("\n".join(out) if not args.quiet else f"{flag1}\n{flag2}")

    # Compare against authoritative flag_config.json (verification only)
    cfg_path = os.path.join(CHALLENGE_ROOT, "organizer", "flag_config.json")
    try:
        with open(cfg_path, encoding="utf-8") as f:
            cfg = json.load(f)
        ok = (flag1 == cfg["flag1"]["value"] and flag2 == cfg["flag2"]["value"])
        if integ_ok and ok:
            print("\n[verify] recovered flags MATCH flag_config.json AND "
                  "envelope integrity check PASSED.")
            return 0
        print(f"\n[verify] MISMATCH: flag1_ok={flag1==cfg['flag1']['value']} "
              f"flag2_ok={flag2==cfg['flag2']['value']} integ={integ_ok}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"[verify] could not read flag_config.json for comparison: {e}",
              file=sys.stderr)
        return 0 if (flag1 and flag2 and integ_ok) else 1


if __name__ == "__main__":
    raise SystemExit(main())

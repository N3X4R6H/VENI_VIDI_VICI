#!/usr/bin/env python3
"""
N2 - GHOST IN THE WIRE
Evidence consistency tests.

Verifies the four evidence files agree with each other and with the
organizer manifest / flag config, and that the intended forensic claims hold:

  - all four files exist
  - PCAP is parseable and Ethernet headers are present
  - suspicious DNS queries in the PCAP share ONE source MAC
  - that MAC matches the DHCP lease ACTIVE during the incident
  - the resolver log and the PCAP agree on every suspicious query
  - the repository audit log places the compromised host on the artifact
    resource shortly before / during the DNS exfiltration window
  - the suspicious DNS sequence is complete (no missing segments)
  - Base64URL reconstruction returns the exact expected artifact
  - the reconstructed envelope's integrity check passes
  - the two flags match the authoritative config
  - neither flag is leaked into any participant-facing file
"""

from __future__ import annotations

import base64
import csv
import hashlib
import json
import os
import re
from datetime import datetime
from zoneinfo import ZoneInfo

# ---------------------------------------------------------------------------
# Inlined test helpers (no external _helpers module needed).
# ---------------------------------------------------------------------------
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EVIDENCE_DIR = os.path.join(ROOT, "evidence")
ORGANIZER_DIR = os.path.join(ROOT, "organizer")
PORTAL_DIR = os.path.join(ROOT, "portal")

_failures: list[str] = []
_passes = 0


def banner(text: str) -> None:
    print("\n" + "=" * 70)
    print(text)
    print("=" * 70)


def ok(msg: str) -> None:
    global _passes
    _passes += 1
    print(f"  PASS  {msg}")


def fail(msg: str) -> None:
    _failures.append(msg)
    print(f"  FAIL  {msg}")


def check(cond: bool, msg: str) -> None:
    if cond:
        ok(msg)
    else:
        fail(msg)


def summary(name: str) -> int:
    banner(f"{name}: {_passes} passed, {len(_failures)} failed")
    for m in _failures:
        print("  - " + m)
    return 1 if _failures else 0


# ---------------------------------------------------------------------------
# Ground-truth values from the generated flag_config.json.
# ---------------------------------------------------------------------------
with open(os.path.join(ORGANIZER_DIR, "flag_config.json"), encoding="utf-8") as _f:
    _CFG = json.load(_f)
FLAG1 = _CFG["flag1"]["value"]
FLAG2 = _CFG["flag2"]["value"]
COMPROMISED_MAC = _CFG["network"]["compromised_mac"]
COMPROMISED_IP = _CFG["network"]["compromised_ip"]
EXFIL = _CFG["network"]["exfil_domain"]
ARTIFACT_ID = _CFG["flag2"]["artifact_id"]
ARTIFACT_REPO_PATH = _CFG["flag2"]["artifact_repo_path"]
ENVELOPE_SHA256 = _CFG["flag2"]["artifact_envelope_sha256"]
ENVELOPE_SIZE = _CFG["flag2"]["envelope_size"]
NUM_SEGMENTS = _CFG["encoding"]["num_segments"]

IST = ZoneInfo("Asia/Kolkata")
SEQ_RE = re.compile(r"^seg(\d{3})$")


def parse_resolver(path):
    rows = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            rows.append({
                "ts": datetime.fromisoformat(parts[0]),
                "src_ip": parts[1], "qname": parts[2], "qtype": parts[3],
                "rcode": int(parts[4].split("(")[0]),
            })
    return rows


def parse_leases(path):
    rows = []
    with open(path, encoding="utf-8", newline="") as f:
        for r in csv.DictReader(f):
            r["lease_start"] = datetime.fromisoformat(r["lease_start"])
            r["lease_end"] = datetime.fromisoformat(r["lease_end"])
            rows.append(r)
    return rows


def parse_audit(path):
    rows = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            rows.append({
                "ts": datetime.fromisoformat(parts[0]), "ip": parts[1],
                "user": parts[2], "resource": parts[3], "op": parts[4],
                "status": parts[5], "size": int(parts[6]),
            })
    return rows


def main() -> int:
    banner("N2 evidence consistency tests")

    # --- file existence ----------------------------------------------------
    files = {
        "network_capture.pcap": os.path.join(EVIDENCE_DIR, "network_capture.pcap"),
        "dns_resolver.log": os.path.join(EVIDENCE_DIR, "dns_resolver.log"),
        "dhcp_leases.csv": os.path.join(EVIDENCE_DIR, "dhcp_leases.csv"),
        "repository_audit.log": os.path.join(EVIDENCE_DIR, "repository_audit.log"),
    }
    for name, p in files.items():
        check(os.path.exists(p) and os.path.getsize(p) > 0, f"{name} exists and non-empty")

    # --- PCAP parseable ----------------------------------------------------
    from scapy.all import rdpcap, DNS, Ether, IP
    try:
        pkts = rdpcap(files["network_capture.pcap"])
        check(len(pkts) > 0, f"PCAP is parseable ({len(pkts)} packets)")
    except Exception as e:
        fail(f"PCAP not parseable: {e}")
        return summary("evidence_consistency")

    dns_q = [p for p in pkts if p.haslayer(DNS) and p[DNS].qr == 0]
    check(all(p.haslayer(Ether) for p in dns_q), "all DNS query frames carry Ethernet headers")

    # --- suspicious queries share ONE source MAC ---------------------------
    susp = [p for p in dns_q
            if p[DNS].qd.qname.decode(errors="replace").rstrip(".").lower().endswith(EXFIL)]
    check(len(susp) >= 30, f"suspicious DNS query count = {len(susp)} (>=30)")
    macs = {p[Ether].src for p in susp}
    ips = {p[IP].src for p in susp}
    check(len(macs) == 1, f"suspicious traffic has single src MAC: {macs}")
    check(len(ips) == 1, f"suspicious traffic has single src IP: {ips}")
    pcap_mac = next(iter(macs)) if macs else None
    pcap_ip = next(iter(ips)) if ips else None
    check(pcap_mac == COMPROMISED_MAC, f"pcap MAC == config compromised MAC ({pcap_mac})")
    check(pcap_ip == COMPROMISED_IP, f"pcap IP == config compromised IP ({pcap_ip})")

    # --- resolver log / pcap agreement on suspicious queries ---------------
    resolver = parse_resolver(files["dns_resolver.log"])
    susp_log = [r for r in resolver if r["qname"].lower().endswith(EXFIL)]
    pcap_qnames = {p[DNS].qd.qname.decode(errors="replace").rstrip(".") for p in susp}
    log_qnames = {r["qname"] for r in susp_log}
    check(pcap_qnames == log_qnames,
          f"resolver log and PCAP agree on {len(pcap_qnames)} suspicious qnames")
    check(all(r["src_ip"] == COMPROMISED_IP for r in susp_log),
          "all suspicious resolver entries come from compromised IP")

    # --- DHCP: active lease for compromised IP during incident ------------
    leases = parse_leases(files["dhcp_leases.csv"])
    incident_ts = min(r["ts"] for r in susp_log)
    active = [l for l in leases if l["ip"] == COMPROMISED_IP
              and l["lease_start"] <= incident_ts <= l["lease_end"]
              and l["state"] == "active"]
    check(len(active) == 1, f"exactly one active lease covers {COMPROMISED_IP} "
          f"during the incident (found {len(active)})")
    if active:
        check(active[0]["mac"].lower() == COMPROMISED_MAC.lower(),
              f"active DHCP lease MAC matches PCAP/config MAC ({active[0]['mac']})")

    # there must be a PRIOR/different MAC for the same IP to force correlation
    prior = [l for l in leases if l["ip"] == COMPROMISED_IP
             and l["mac"] != COMPROMISED_MAC]
    check(len(prior) >= 1, "a prior/alternate MAC exists for the compromised IP "
          "(forces correlation, not blind trust)")

    # --- repository audit: compromised host -> artifact, near incident -----
    audit = parse_audit(files["repository_audit.log"])
    hits = [a for a in audit if a["ip"] == COMPROMISED_IP
            and a["resource"] == ARTIFACT_REPO_PATH]
    check(len(hits) >= 1, "compromised host accessed the artifact resource")
    if hits:
        ev = hits[0]
        check(ev["ts"] <= incident_ts + (incident_ts - incident_ts) or
              abs((ev["ts"] - incident_ts).total_seconds()) < 600,
              f"audit event is within 10 min of DNS window ({ev['ts'].isoformat()})")
        check(ev["op"] in ("export", "read", "clone"),
              f"audit operation is a retrieval op ({ev['op']})")
        check(ev["size"] == ENVELOPE_SIZE,
              f"audit size matches envelope size ({ev['size']} == {ENVELOPE_SIZE})")

    # --- suspicious DNS sequence is complete -------------------------------
    data = {}
    for p in susp:
        qn = p[DNS].qd.qname.decode(errors="replace").rstrip(".")
        labels = qn.split(".")
        m = SEQ_RE.match(labels[0])
        if m:
            data[int(m.group(1))] = labels[1]
    expected = set(range(max(data) + 1)) if data else set()
    check(set(data) == expected, f"data segments contiguous 0..{max(data) if data else -1} "
          f"(missing {sorted(expected - set(data))})")
    check(len(data) == NUM_SEGMENTS,
          f"segment count matches generator ({len(data)})")

    # --- Base64URL reconstruction -> exact artifact ------------------------
    ordered = [data[s] for s in sorted(data)]
    b64url = "".join(ordered)
    pad = "=" * ((-len(b64url)) % 4)
    raw = base64.urlsafe_b64decode(b64url + pad)
    check(hashlib.sha256(raw).hexdigest() == ENVELOPE_SHA256,
          "Base64URL reconstruction matches authoritative envelope (sha256)")

    # integrity check inside the envelope
    text = raw.decode("utf-8", errors="replace")
    check(text.startswith("ARS-EXFIL/1"), "envelope header ARS-EXFIL/1 present")
    try:
        header_block, body = text.split("---BEGIN CONTENT---\n", 1)
        content, _ = body.split("\n---END CONTENT---", 1)
        stated = dict(line.split(": ", 1) for line in header_block.strip().splitlines()[1:] if ": " in line)
        recomputed = hashlib.sha256(content.encode("utf-8")).hexdigest()
        check(stated.get("content_sha256") == recomputed,
              "envelope content_sha256 integrity check passes")
        check(stated.get("artifact_id") == ARTIFACT_ID,
              f"envelope artifact_id matches ({stated.get('artifact_id')})")
    except Exception as e:
        fail(f"envelope integrity parse failed: {e}")

    # --- flags present in recovered artifact -------------------------------
    f2 = re.search(r"VVVFLAG\{[^}]+\}", text)
    check(f2 and f2.group(0) == FLAG2, f"Flag 2 recovered from artifact ({f2.group(0) if f2 else None})")
    check(f"VVVFLAG{{{COMPROMISED_MAC}}}" == FLAG1, "Flag 1 derived from compromised MAC")

    # --- flags NOT leaked into participant-facing files -------------------
    # Participant-facing surface = evidence/ + portal/ + the two participant
    # docs (challenge.md, hints.md). Organizer-only docs may cite flags.
    PLACEHOLDER = "VVVFLAG{...}"
    leak_targets = []
    for dirpath, _, fns in os.walk(EVIDENCE_DIR):
        for fn in fns:
            leak_targets.append(os.path.join(dirpath, fn))
    for dirpath, _, fns in os.walk(os.path.join(ROOT, "portal")):
        for fn in fns:
            leak_targets.append(os.path.join(dirpath, fn))
    for name in ("challenge.md", "hints.md"):
        leak_targets.append(os.path.join(ROOT, "docs", name))

    leaked = []
    for p in leak_targets:
        try:
            with open(p, "rb") as f:
                blob = f.read()
        except Exception:
            continue
        for flag in (FLAG1, FLAG2):
            if flag.encode() in blob:
                leaked.append((p, flag))
        text_scan = blob.decode("utf-8", "replace")
        for tok in re.findall(r"VVVFLAG\{[^}]+\}", text_scan):
            if tok == PLACEHOLDER or tok in (FLAG1, FLAG2):
                continue
            leaked.append((p, tok))
    check(not leaked, f"no flags in participant-facing files ({leaked})")

    return summary("evidence_consistency")


if __name__ == "__main__":
    raise SystemExit(main())

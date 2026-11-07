#!/usr/bin/env python3
"""
N2 - GHOST IN THE WIRE
Flag validation tests.

Independently derives Flag 1 (MAC attribution) and Flag 2 (payload recovery)
from the evidence files and asserts they match organizer/flag_config.json.
Also scans for accidental flag exposure across the whole challenge tree.
"""

from __future__ import annotations

import base64
import json
import os
import re

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
CFG_PATH = os.path.join(ORGANIZER_DIR, "flag_config.json")
with open(CFG_PATH, encoding="utf-8") as _f:
    _CFG = json.load(_f)
FLAG1 = _CFG["flag1"]["value"]
FLAG2 = _CFG["flag2"]["value"]
COMPROMISED_MAC = _CFG["flag1"]["mac"]
EXFIL_DOMAIN = _CFG["network"]["exfil_domain"]
ARTIFACT_ID = _CFG["flag2"]["artifact_id"]

FLAG_RE = re.compile(r"VVVFLAG\{[^}]+\}")


def derive_flag1():
    """From PCAP: suspicious DNS query source MAC."""
    from scapy.all import rdpcap, DNS, Ether
    macs = set()
    for p in rdpcap(os.path.join(EVIDENCE_DIR, "network_capture.pcap")):
        if p.haslayer(DNS) and p[DNS].qr == 0:
            qn = p[DNS].qd.qname.decode(errors="replace").rstrip(".").lower()
            if qn.endswith(EXFIL_DOMAIN):
                macs.add(p[Ether].src)
    if len(macs) != 1:
        return None
    return f"VVVFLAG{{{next(iter(macs))}}}"


def derive_flag2():
    """Reconstruct payload, decode envelope, extract flag token."""
    from scapy.all import rdpcap, DNS
    segs = {}
    for p in rdpcap(os.path.join(EVIDENCE_DIR, "network_capture.pcap")):
        if not (p.haslayer(DNS) and p[DNS].qr == 0):
            continue
        labels = p[DNS].qd.qname.decode(errors="replace").rstrip(".").split(".")
        m = re.match(r"^seg(\d{3})$", labels[0])
        if m:
            segs[int(m.group(1))] = labels[1]
    b64 = "".join(segs[s] for s in sorted(segs))
    text = base64.urlsafe_b64decode(b64 + "=" * ((-len(b64)) % 4)).decode("utf-8", "replace")
    f = FLAG_RE.search(text)
    return f.group(0) if f else None


def main() -> int:
    banner("N2 flag validation tests")

    check(os.path.exists(CFG_PATH), "organizer/flag_config.json exists")
    with open(CFG_PATH, encoding="utf-8") as f:
        cfg = json.load(f)

    # authoritative config sanity
    check(cfg["flag1"]["value"] == FLAG1, "flag_config flag1 == expected")
    check(cfg["flag2"]["value"] == FLAG2, "flag_config flag2 == expected")
    check(cfg["flag1"]["mac"] == COMPROMISED_MAC, "flag_config mac == expected MAC")

    # derive from evidence
    f1 = derive_flag1()
    f2 = derive_flag2()
    check(f1 == FLAG1, f"Flag 1 independently derived from evidence ({f1})")
    check(f2 == FLAG2, f"Flag 2 independently derived from evidence ({f2})")
    check(f1 == cfg["flag1"]["value"], "derived Flag 1 == flag_config")
    check(f2 == cfg["flag2"]["value"], "derived Flag 2 == flag_config")

    # Flag 2 is NOT a shortcut from the audit log resource name
    audit_path = os.path.join(EVIDENCE_DIR, "repository_audit.log")
    with open(audit_path, encoding="utf-8") as f:
        audit_text = f.read()
    check(FLAG2 not in audit_text, "Flag 2 not present in repository audit log")
    check(ARTIFACT_ID not in FLAG2, "Flag 2 differs from artifact id (no audit-log shortcut)")

    # No flag string anywhere in PARTICIPANT-FACING files. The participant-
    # facing surface is: evidence/, portal/, and the two participant docs
    # (docs/challenge.md, docs/hints.md). Organizer-only docs (solution.md,
    # deployment.md) and context.md are NOT shipped to participants (the portal
    # Dockerfile copies only portal/ + evidence/) and may legitimately cite flags.
    PLACEHOLDER = "VVVFLAG{...}"   # the format example shown to participants
    participant_files = []
    for p in [os.path.join(EVIDENCE_DIR, n) for n in
              ("network_capture.pcap", "dns_resolver.log", "dhcp_leases.csv",
               "repository_audit.log")]:
        if os.path.exists(p):
            participant_files.append(p)
    for dirpath, _, fns in os.walk(os.path.join(ROOT, "portal")):
        for fn in fns:
            participant_files.append(os.path.join(dirpath, fn))
    for name in ("challenge.md", "hints.md"):
        p = os.path.join(ROOT, "docs", name)
        if os.path.exists(p):
            participant_files.append(p)

    leaked = []
    for p in participant_files:
        try:
            blob = open(p, "rb").read()
        except Exception:
            continue
        # real flag values must never appear
        for flag in (FLAG1, FLAG2):
            if flag.encode() in blob:
                leaked.append((p, flag))
        # any other concrete VVVFLAG{...} token (not the literal placeholder)
        # is suspicious: it could be a leaked flag
        text = blob.decode("utf-8", "replace")
        for tok in FLAG_RE.findall(text):
            if tok == PLACEHOLDER:
                continue
            if tok in (FLAG1, FLAG2):
                continue  # already recorded above
            leaked.append((p, tok))
    check(not leaked, f"no flags in participant-facing files ({leaked})")

    # flags must NOT appear in repo-root or top-level non-organizer docs either
    # (good hygiene; these are not the authoritative source for flags).
    for top in ("README.md", "context.md", ".env.example", "docker-compose.yml",
                "docs/challenge.md", "docs/hints.md"):
        p = os.path.join(ROOT, top)
        if os.path.exists(p):
            blob = open(p, "rb").read()
            check(FLAG1.encode() not in blob and FLAG2.encode() not in blob,
                  f"{top} does not contain real flag values")

    return summary("flag_validation")


if __name__ == "__main__":
    raise SystemExit(main())

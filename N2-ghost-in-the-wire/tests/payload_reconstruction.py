#!/usr/bin/env python3
"""
N2 - GHOST IN THE WIRE
Payload reconstruction tests.

Independently (re-)implements the decode logic and asserts the segments can be
ordered deterministically and that the decoded artifact matches the
authoritative envelope, even when the input is shuffled.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re

# ---------------------------------------------------------------------------
# Inlined test helpers (no external _helpers module needed).
# ---------------------------------------------------------------------------
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EVIDENCE_DIR = os.path.join(ROOT, "evidence")
ORGANIZER_DIR = os.path.join(ROOT, "organizer")

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
# Ground-truth values from the generated flag_config.json + _artifact_envelope.bin.
# ---------------------------------------------------------------------------
with open(os.path.join(ORGANIZER_DIR, "flag_config.json"), encoding="utf-8") as _f:
    _CFG = json.load(_f)
EXFIL_DOMAIN = _CFG["network"]["exfil_domain"]
ENVELOPE_SHA256 = _CFG["flag2"]["artifact_envelope_sha256"]
NUM_SEGMENTS = _CFG["encoding"]["num_segments"]
B64URL_LEN = _CFG["encoding"]["b64url_len"]
# Raw ground-truth envelope bytes (written by generate_evidence.py).
with open(os.path.join(ORGANIZER_DIR, "_artifact_envelope.bin"), "rb") as _f:
    ENVELOPE_BYTES = _f.read()
ENVELOPE_B64URL = base64.urlsafe_b64encode(ENVELOPE_BYTES).decode("ascii").rstrip("=")

SEQ_RE = re.compile(r"^seg(\d{3})$")


def segments_from_pcap(path):
    from scapy.all import rdpcap, DNS
    segs = {}
    for p in rdpcap(path):
        if not (p.haslayer(DNS) and p[DNS].qr == 0):
            continue
        qn = p[DNS].qd.qname.decode(errors="replace").rstrip(".")
        labels = qn.split(".")
        if len(labels) < 2:
            continue
        m = SEQ_RE.match(labels[0])
        if not m:
            continue
        segs[int(m.group(1))] = labels[1]
    return segs


def reconstruct(segs):
    ordered = [segs[s] for s in sorted(segs)]
    b64 = "".join(ordered)
    return base64.urlsafe_b64decode(b64 + "=" * ((-len(b64)) % 4))


def main() -> int:
    banner("N2 payload reconstruction tests")

    pcap = os.path.join(EVIDENCE_DIR, "network_capture.pcap")
    check(os.path.exists(pcap), "pcap exists")
    segs = segments_from_pcap(pcap)
    check(len(segs) == NUM_SEGMENTS,
          f"segment count == expected ({len(segs)})")

    # contiguous
    check(set(segs) == set(range(max(segs) + 1)), "segment indices contiguous")

    # ordering is deterministic: shuffle inputs, decode, compare
    import random
    items = list(segs.items())
    for trial in range(3):
        rng = random.Random(trial)
        rng.shuffle(items)
        decoded = reconstruct(dict(items))
        check(hashlib.sha256(decoded).hexdigest() == ENVELOPE_SHA256,
              f"shuffle-trial {trial}: decode matches authoritative envelope (sha256)")

    # restore padding works for trailing partial groups
    b64 = "".join(segs[s] for s in sorted(segs))
    check(len(b64) == B64URL_LEN,
          f"base64 length == expected ({len(b64)})")
    check(b64 == ENVELOPE_B64URL, "concatenated base64 == authoritative envelope base64")
    check(reconstruct(segs) == ENVELOPE_BYTES, "decoded envelope == authoritative envelope bytes")

    # label length safety
    max_label = max(len(s) for s in segs.values())
    max_qname = max(len(f"seg{s:03d}.{chunk}.{EXFIL_DOMAIN}") for s, chunk in segs.items())
    check(max_label <= 63, f"max data label <= 63 bytes ({max_label})")
    check(max_qname <= 253, f"max qname <= 253 bytes ({max_qname})")

    # integrity field inside decoded envelope
    text = reconstruct(segs).decode("utf-8", errors="replace")
    hb, body = text.split("---BEGIN CONTENT---\n", 1)
    content, _ = body.split("\n---END CONTENT---", 1)
    stated = dict(l.split(": ", 1) for l in hb.strip().splitlines()[1:] if ": " in l)
    check(stated["content_sha256"] == hashlib.sha256(content.encode()).hexdigest(),
          "envelope content_sha256 self-check")

    return summary("payload_reconstruction")


if __name__ == "__main__":
    raise SystemExit(main())

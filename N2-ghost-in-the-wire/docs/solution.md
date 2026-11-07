# N2 — Ghost in the Wire · Official Solution (ORGANIZER-ONLY)

> Do not expose this file to participants. The automated reproduction is
> `organizer/official_solve.py`; this document explains the reasoning.

## Overview

Asterion Research Systems workstation `ARS-WS-RES-07` (IP `10.40.2.17`) was
compromised. On 2026-10-28 at 14:02:17 IST, user `res07` exported the
confidential artifact `research/chimera/chimera_phase2_briefing.md` from the
internal repository (`10.40.1.20`). Roughly 3 minutes later the workstation
began exfiltrating that artifact via DNS tunneling to `sync.ghostwire.test`,
splitting a Base64URL encoding of an `ARS-EXFIL/1` envelope across 34 query
labels. The DNS queries returned NXDOMAIN (the exfil domain does not exist),
which is normal for DNS-tunneling clients that only need the request path.

## Stage 1 — Establish the incident window

In `dns_resolver.log`, group queries by their destination domain. The
overwhelming majority of queries to a single unfamiliar domain occur in a
tight ~90-second window starting `2026-10-28T14:05:00+05:30` and ending
`14:06:32`. Everything outside that window is benign background DNS.

## Stage 2 — Identify suspicious DNS behavior

The destination domain is `sync.ghostwire.test`. The queries to it have:

- abnormally long subdomain labels (`seg000.<48 chars>.sync.ghostwire.test`),
- a structured leftmost label (`segNNN`) that looks like a sequence id,
- encoded-looking content in the second label,
- NXDOMAIN responses.

These are not ordinary hostname lookups.

## Stage 3 — Attribute the source workstation (Flag 1)

Every suspicious query in `dns_resolver.log` comes from `10.40.2.17`. Open
`network_capture.pcap` and look at the **Ethernet source MAC** of those same
DNS query frames: it is `6a:8c:47:2d:91:b3`.

Now correlate with `dhcp_leases.csv`. The IP `10.40.2.17` has *two* lease
records:

- an expired/renewed lease on 2026-10-20 with MAC `12:7e:c4:88:0a:1f`,
- the **active** lease on 2026-10-28 08:14:23–16:14:23 with MAC
  `6a:8c:47:2d:91:b3`.

The incident (14:05 IST) falls inside the active lease, whose MAC matches the
pcap. The workstation is `ARS-WS-RES-07` and its MAC is `6a:8c:47:2d:91:b3`.

> **Flag 1:** `VVVFLAG{6a:8c:47:2d:91:b3}`

## Stage 4 — Correlate repository activity

In `repository_audit.log`, the only event from `10.40.2.17` is:

```
2026-10-28T14:02:17+05:30 10.40.2.17 res07 \
  research/chimera/chimera_phase2_briefing.md export 200 1194
```

This is the artifact that was exfiltrated: `chimera_phase2_briefing`, 1194
bytes (which matches the reconstructed envelope size exactly).

## Stage 5 — Reconstruct the DNS payload

Filter the pcap (or resolver log) for queries matching
`segNNN.<chunk>.sync.ghostwire.test`. There are 34 of them, `seg000`..`seg033`.

For each, take the second label as the data chunk. Order by `NNN` and
concatenate to get a 1592-character Base64URL string. No segments are missing
and the indices are contiguous, so ordering is unambiguous.

## Stage 6 — Decode and validate (Flag 2)

Restore Base64URL padding (`=` × `(4 - len % 4) % 4`) and decode. The result is
an `ARS-EXFIL/1` envelope:

```
ARS-EXFIL/1
artifact_id: chimera_phase2_briefing
filename: chimera_phase2_briefing.md
content_sha256: 6d9d85ea6ab437e3498a1d487821623f4136122f49e765e74f6ccc9f948239c0
---BEGIN CONTENT---
# Project CHIMERA - Phase 2 Research Briefing
...
Recovery token for incident ARS-2026-041:
VVVFLAG{gh0st-in-dns-w1r3-4rs041}
...
---END CONTENT---
```

Recompute `SHA-256` of the content between the BEGIN/END markers and confirm it
equals the `content_sha256` in the header (it does — integrity PASS).

> **Flag 2:** `VVVFLAG{gh0st-in-dns-w1r3-4rs041}`

## Why the audit log is not a shortcut to Flag 2

The audit log records the *resource path* (`chimera_phase2_briefing.md`) and
its *size* (1194), but the flag token itself
(`VVVFLAG{gh0st-in-dns-w1r3-4rs041}`) lives only inside the reconstructed
artifact. The flag string differs from the artifact id, so participants must
actually reconstruct and decode the DNS payload.

## Reproducing it

```bash
./tests/smoke.sh                                # regenerate + solve + test
python3 organizer/official_solve.py            # full trace
python3 organizer/official_solve.py --quiet     # just the two flags
```

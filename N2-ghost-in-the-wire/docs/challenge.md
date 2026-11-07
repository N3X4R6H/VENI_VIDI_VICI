# N2 — Ghost in the Wire · Challenge (participant-facing)

> This document mirrors the briefing shown on the evidence portal. It is safe
> for participants to read.

## Incident briefing

**Asterion Research Systems** recently detected unusual outbound network
activity originating from its internal research network. Its monitoring systems
recorded repeated DNS queries to an unfamiliar external domain. Around the same
time, an internal research repository registered an unexpected access event.

The security team suspects that a compromised workstation transferred
confidential research material outside the organization. Unfortunately, the
endpoint investigation was interrupted before the workstation could be
isolated. The team managed to preserve several pieces of evidence:

- A network packet capture.
- DNS resolver logs.
- DHCP lease records.
- Repository audit logs.

You have been assigned to reconstruct the incident.

**Incident reference:** `ARS-2026-041`
**Timezone:** all evidence timestamps are in IST (Asia/Kolkata, UTC+05:30).

## Objectives

1. Identify the workstation responsible for the suspicious activity.
2. Determine which network mechanism was abused.
3. Reconstruct the information transferred outside the organization.
4. Submit both recovered flags.

## Evidence

| File | Description |
|---|---|
| `network_capture.pcap` | Packet capture of the network segment during the incident. |
| `dns_resolver.log` | Internal DNS resolver query log for the incident window. |
| `dhcp_leases.csv` | DHCP lease history for the internal research subnet. |
| `repository_audit.log` | Research repository access audit log. |

## Submission

Submit each flag on the competition platform. Flags use the format
`VVVFLAG{...}`.

- **Flag 1** is recovered by attributing the suspicious traffic to a
  workstation's hardware address.
- **Flag 2** is embedded inside the recovered artifact — reconstruct the
  transferred data to reveal it.

## Tools you may find useful

A packet analyzer (Wireshark / `tshark` / `scapy`), a spreadsheet or `awk` for
the CSV, and any scripting language for parsing logs and decoding bytes.
Nothing in this challenge requires network access once you have the evidence.

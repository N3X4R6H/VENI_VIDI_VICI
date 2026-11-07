#!/usr/bin/env python3
"""
N2 - GHOST IN THE WIRE
PCAP generator (ORGANIZER-ONLY).

Reads organizer/_manifest.json (produced by generate_evidence.py) and writes
evidence/network_capture.pcap.

The PCAP is the primary forensic artifact. Design goals:

  * Preserve Ethernet headers on every frame so the source MAC of the
    suspicious DNS traffic is recoverable (Flag 1 attribution path).
  * Include the SAME DNS queries that appear in dns_resolver.log, with the
    SAME timestamps, so the resolver log and the capture agree.
  * Include benign background traffic (ARP, HTTP to the repo, ordinary DNS
    from several hosts) so the suspicious sequence is not the only traffic.
  * Deterministic: no network access, no real DNS queries, fixed seed for
    cosmetic fields (DNS transaction ids, UDP source ports).

This script reads ONLY the manifest (and the seed from flag_config.json); it
does not import generate_evidence.py or any other module, so the pcap build
is decoupled from the generator internals.

Usage:
  python3 organizer/generate_capture.py
"""

from __future__ import annotations

import json
import os
import random
import sys

from scapy.all import (  # noqa: E402
    ARP, DNS, DNSQR, DNSRR, Ether, IP, PcapWriter, TCP, UDP, conf,
)

CHALLENGE_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EVIDENCE_DIR = os.path.join(CHALLENGE_ROOT, "evidence")
ORGANIZER_DIR = os.path.join(CHALLENGE_ROOT, "organizer")
MANIFEST_PATH = os.path.join(ORGANIZER_DIR, "_manifest.json")
FLAG_CONFIG_PATH = os.path.join(ORGANIZER_DIR, "flag_config.json")
PCAP_PATH = os.path.join(EVIDENCE_DIR, "network_capture.pcap")

# DNS qtype name -> numeric (scapy accepts names too, but we pin the values so
# the wire bytes are deterministic regardless of scapy's internal table).
QTYPE_NUM = {"A": 1, "NS": 2, "CNAME": 5, "PTR": 12, "MX": 15, "TXT": 16,
             "AAAA": 28, "SRV": 33}

# Keep scapy quiet and force automatic checksum computation on serialization.
conf.verb = 0
conf.checkIPaddr = False


def _dns_id(rng: random.Random) -> int:
    return rng.randint(0x0001, 0xFFFF)


def _sport(rng: random.Random) -> int:
    # ephemeral port range, avoid 53
    return rng.randint(1024, 65535)


def build_dns_query_packet(ev: dict, rng: random.Random, dns_resolver_ip: str,
                           mac_map: dict) -> "object":
    src_ip, dst_ip = ev["src_ip"], dns_resolver_ip
    src_mac = ev["src_mac"]
    dst_mac = mac_map[dst_ip]
    sport = _sport(rng)
    qname = ev["qname"]
    qtype = QTYPE_NUM.get(ev["qtype"], 1)
    dnspkt = DNS(
        id=_dns_id(rng), qr=0, opcode=0,
        qd=DNSQR(qname=qname, qtype=qtype),
    )
    return (Ether(src=src_mac, dst=dst_mac)
            / IP(src=src_ip, dst=dst_ip)
            / UDP(sport=sport, dport=53)
            / dnspkt), sport


def build_dns_response_packet(ev: dict, sport: int, rng: random.Random,
                              dns_resolver_ip: str, mac_map: dict) -> "object":
    src_ip, dst_ip = dns_resolver_ip, ev["src_ip"]
    src_mac = mac_map[src_ip]
    dst_mac = ev["src_mac"]
    qname = ev["qname"]
    qtype = QTYPE_NUM.get(ev["qtype"], 1)
    rcode = ev["rcode"]
    dns_kwargs = dict(
        id=_dns_id(rng), qr=1, opcode=0, rcode=rcode,
        qd=DNSQR(qname=qname, qtype=qtype),
    )
    # Add an answer record only for successful A / PTR lookups. AAAA, TXT and MX
    # queries return NODATA (NOERROR, no answer) -- a real resolver does this
    # when the host only has an A record. This also avoids feeding an IPv4
    # literal into an AAAA RDATA field.
    an = []
    if rcode == 0 and ev.get("answer") not in (None, "-"):
        ans = ev["answer"]
        if qtype == 1:        # A
            an.append(DNSRR(rrname=qname, type="A", rdata=ans, ttl=60))
        elif qtype == 12:     # PTR
            an.append(DNSRR(rrname=qname, type="PTR", rdata=ans, ttl=60))
    if an:
        dns_kwargs["an"] = an
    dnspkt = DNS(**dns_kwargs)
    return (Ether(src=src_mac, dst=dst_mac)
            / IP(src=src_ip, dst=dst_ip)
            / UDP(sport=53, dport=sport)
            / dnspkt)


def build_arp_packet(p: dict) -> "object":
    sender_mac = p["sender_mac"]
    sender_ip = p["sender_ip"]
    target_ip = p["target_ip"]
    return (Ether(src=sender_mac, dst="ff:ff:ff:ff:ff:ff")
            / ARP(op="who-has", hwsrc=sender_mac, psrc=sender_ip, pdst=target_ip))


def build_tcp_packet(p: dict, flags: str) -> "object":
    return (Ether(src=p["src_mac"], dst=p["dst_mac"])
            / IP(src=p["src_ip"], dst=p["dst_ip"])
            / TCP(sport=p["sport"], dport=p["dport"], flags=flags, seq=1000))


def main() -> int:
    if not os.path.exists(MANIFEST_PATH):
        print(f"[generate_capture] manifest not found: {MANIFEST_PATH}\n"
              f"  run generate_evidence.py first.", file=sys.stderr)
        return 1
    if not os.path.exists(FLAG_CONFIG_PATH):
        print(f"[generate_capture] flag_config.json not found: {FLAG_CONFIG_PATH}\n"
              f"  run generate_evidence.py first.", file=sys.stderr)
        return 1
    os.makedirs(EVIDENCE_DIR, exist_ok=True)

    with open(MANIFEST_PATH, "r", encoding="utf-8") as f:
        manifest = json.load(f)
    with open(FLAG_CONFIG_PATH, "r", encoding="utf-8") as f:
        flag_config = json.load(f)

    dns_resolver_ip = manifest["dns_resolver_ip"]
    mac_map = manifest["mac_map"]
    seed = flag_config["seed"]

    rng = random.Random(seed + 1)

    frames: list[tuple[float, object]] = []  # (epoch, packet)

    # --- DNS query + response pairs ----------------------------------------
    for ev in manifest["dns_events"]:
        ts = float(ev["ts_epoch"])
        qpkt, sport = build_dns_query_packet(ev, rng, dns_resolver_ip, mac_map)
        qpkt.time = ts
        frames.append((ts, qpkt))
        # response ~8ms later (same transaction id is fine but we randomize)
        rpkt = build_dns_response_packet(ev, sport, rng, dns_resolver_ip, mac_map)
        rpkt.time = ts + 0.008
        frames.append((ts + 0.008, rpkt))

    # --- Background (non-DNS) frames ---------------------------------------
    for p in manifest["background_packets"]:
        ts = float(p["ts_epoch"])
        kind = p["kind"]
        if kind == "arp":
            pkt = build_arp_packet(p)
        elif kind == "tcp_syn":
            pkt = build_tcp_packet(p, "S")
        elif kind == "tcp_synack":
            pkt = build_tcp_packet(p, "SA")
        else:
            continue
        pkt.time = ts
        frames.append((ts, pkt))

    # Stable ordering by timestamp (queries before their responses by design).
    frames.sort(key=lambda fr: fr[0])

    with PcapWriter(PCAP_PATH, linktype=1, append=False, sync=False) as writer:
        for _, pkt in frames:
            writer.write(pkt)

    size = os.path.getsize(PCAP_PATH)
    print(f"[generate_capture] wrote {PCAP_PATH}")
    print(f"  frames: {len(frames)}   size: {size} bytes ({size/1024:.1f} KiB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

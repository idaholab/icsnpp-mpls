#!/usr/bin/env python3
"""
Build mpls_vlan_matrix.pcap: ICMP echo exchanges carried over MPLS with VLAN tags
on the provider side, the customer side, or both, to see how Zeek fills conn.log's
vlan and inner_vlan when a pseudowire's inner frame has its own tags, and to check
that icsnpp-mpls records only the provider-side tags.

Standard library only (no scapy). Usage:
    python3 make_mpls_vlan_matrix.py [output.pcap]

Every scenario uses its own customer subnet, so each one is a separate conn.log row.
Requests and replies use different label stacks, as a real pseudowire would.

  #  provider tags        stack      customer tags   customer subnet
  1  802.1Q 100           PW + CW    802.1Q 10       10.1.1.0/24
  2  802.1ad 200, Q 201   PW + CW    802.1Q 20       10.2.2.0/24
  3  802.1Q 300           PW + CW    untagged        10.3.3.0/24
  4  untagged             PW + CW    802.1Q 40       10.4.4.0/24
  5  802.1Q 500           PW + CW    802.1ad 50,Q 51 10.5.5.0/24
  6  802.1Q 600           IP/MPLS    (none)          10.6.6.0/24

mpls_header.log should show only the provider tags in vlan/inner_vlan for every
row (100, 200/201, 300, none, 500, 600), with payload ethernet+cw for 1-5 and ipv4
for 6. conn.log's vlan/inner_vlan for 1, 2 and 5 is the open question; 3, 4 and 6
are controls.
"""

import struct
import sys

LINKTYPE_ETHERNET = 1
TPID_8021Q = 0x8100
TPID_8021AD = 0x88A8
ETH_IPV4 = 0x0800
ETH_MPLS = 0x8847

# provider routers (PE/P) and customer hosts
PROV_A = bytes.fromhex("0200000000a1")
PROV_B = bytes.fromhex("0200000000b2")
CUST_A = bytes.fromhex("525400000001")
CUST_B = bytes.fromhex("525400000002")


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def ip_addr(s: str) -> bytes:
    return bytes(int(o) for o in s.split("."))


def icmp_echo(src: str, dst: str, reply: bool, ident: int, seq: int, ttl: int) -> bytes:
    payload = bytes(range(32))
    icmp = struct.pack("!BBHHH", 0 if reply else 8, 0, 0, ident, seq) + payload
    icmp = icmp[:2] + struct.pack("!H", checksum(icmp)) + icmp[4:]
    total_len = 20 + len(icmp)
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total_len, seq, 0, ttl, 1, 0, ip_addr(src), ip_addr(dst))
    hdr = hdr[:10] + struct.pack("!H", checksum(hdr)) + hdr[12:]
    return hdr + icmp


def ethernet(dst: bytes, src: bytes, tags, ethertype: int, payload: bytes) -> bytes:
    # tags: list of (tpid, vlan_id), outermost first
    frame = dst + src
    for tpid, vid in tags:
        frame += struct.pack("!HH", tpid, vid & 0x0FFF)
    return frame + struct.pack("!H", ethertype) + payload


def mpls_stack(entries) -> bytes:
    # entries: list of (label, traffic_class, ttl), outermost first
    out = b""
    for i, (label, tc, ttl) in enumerate(entries):
        bos = 1 if i == len(entries) - 1 else 0
        out += struct.pack("!I", (label << 12) | (tc << 9) | (bos << 8) | ttl)
    return out


CONTROL_WORD = b"\x00\x00\x00\x00"

# (number, provider tags, customer tags or None for IP over MPLS, subnet,
#  request stack, reply stack)
SCENARIOS = [
    (
        1,
        [(TPID_8021Q, 100)],
        [(TPID_8021Q, 10)],
        "10.1.1",
        [(16, 0, 254), (1001, 0, 255)],
        [(17, 0, 254), (2001, 0, 255)],
    ),
    (
        2,
        [(TPID_8021AD, 200), (TPID_8021Q, 201)],
        [(TPID_8021Q, 20)],
        "10.2.2",
        [(16, 0, 254), (1002, 0, 255)],
        [(17, 0, 254), (2002, 0, 255)],
    ),
    (3, [(TPID_8021Q, 300)], [], "10.3.3", [(16, 0, 254), (1003, 0, 255)], [(17, 0, 254), (2003, 0, 255)]),
    (4, [], [(TPID_8021Q, 40)], "10.4.4", [(16, 0, 254), (1004, 0, 255)], [(17, 0, 254), (2004, 0, 255)]),
    (
        5,
        [(TPID_8021Q, 500)],
        [(TPID_8021AD, 50), (TPID_8021Q, 51)],
        "10.5.5",
        [(16, 0, 254), (1005, 0, 255)],
        [(17, 0, 254), (2005, 0, 255)],
    ),
    (6, [(TPID_8021Q, 600)], None, "10.6.6", [(1006, 0, 254)], [(2006, 0, 254)]),
]

PINGS_PER_SCENARIO = 3
BASE_TS = 1700000000.0


def build_packets():
    packets = []
    for num, prov_tags, cust_tags, subnet, req_stack, rep_stack in SCENARIOS:
        host_a, host_b = f"{subnet}.1", f"{subnet}.2"
        start = BASE_TS + (num - 1) * 10
        for seq in range(1, PINGS_PER_SCENARIO + 1):
            for reply in (False, True):
                ip = icmp_echo(host_b if reply else host_a, host_a if reply else host_b, reply, 0x1000 + num, seq, 64)
                if cust_tags is None:
                    # IP directly under the label stack
                    inner = ip
                else:
                    inner_src, inner_dst = (CUST_B, CUST_A) if reply else (CUST_A, CUST_B)
                    inner = CONTROL_WORD + ethernet(inner_dst, inner_src, cust_tags, ETH_IPV4, ip)
                stack = mpls_stack(rep_stack if reply else req_stack)
                outer_src, outer_dst = (PROV_B, PROV_A) if reply else (PROV_A, PROV_B)
                frame = ethernet(outer_dst, outer_src, prov_tags, ETH_MPLS, stack + inner)
                ts = start + seq + (0.002 if reply else 0.0)
                packets.append((ts, frame))
    return packets


def write_pcap(path, packets):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, LINKTYPE_ETHERNET))
        for ts, frame in packets:
            sec = int(ts)
            usec = int(round((ts - sec) * 1_000_000))
            f.write(struct.pack("<IIII", sec, usec, len(frame), len(frame)))
            f.write(frame)


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "mpls_vlan_matrix.pcap"
    pkts = build_packets()
    write_pcap(out, pkts)
    print(f"wrote {len(pkts)} packets to {out}")

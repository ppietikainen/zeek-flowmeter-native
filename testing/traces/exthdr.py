"""IPv6 extension headers in front of TCP and UDP: is the header counted as payload?

Usage: exthdr.py OUT.pcap

Each case is one IPv6 connection with a 100-byte request and a 200-byte reply,
so every extractor should report 100 and 200 payload bytes whatever sits
between the IPv6 header and the transport header:
  1 no extension header (baseline)
  2 Destination Options (8 bytes) on every packet
  3 Hop-by-Hop Options (8 bytes) on every packet
  4 Hop-by-Hop + Destination Options (16 bytes) on every packet
  5 atomic Fragment header (8 bytes) on every packet
  6 UDP request/reply behind Destination Options
Case N: client 2001:db8:a:N::1 port 41000+N, server 2001:db8:a:N::2 port 50000.
"""
import sys

from scapy.all import (IPv6, IPv6ExtHdrDestOpt, IPv6ExtHdrFragment, IPv6ExtHdrHopByHop,
                       TCP, UDP, Ether, Raw, wrpcap)

T0 = 1776780000.0
pkts = []
EXT = {1: lambda: None, 2: lambda: IPv6ExtHdrDestOpt(), 3: lambda: IPv6ExtHdrHopByHop(),
       4: lambda: IPv6ExtHdrHopByHop() / IPv6ExtHdrDestOpt(), 5: lambda: IPv6ExtHdrFragment(),
       6: lambda: IPv6ExtHdrDestOpt()}


def put(t, n, from_client, l4, data=b""):
    c, s = f"2001:db8:a:{n}::1", f"2001:db8:a:{n}::2"
    ip = IPv6(src=c, dst=s) if from_client else IPv6(src=s, dst=c)
    e = EXT[n]()
    p = Ether() / ip / (e / l4 if e is not None else l4)
    if data:
        p = p / Raw(data)
    p.time = T0 + t
    pkts.append(p)


for n in range(1, 6):
    t, cp, sp, cs, ss = 10.0 * n, 41000 + n, 50000, 1000, 5000
    def tcp(fc, fl, d=b""):
        global cs, ss
        sq, ak = (cs, ss) if fc else (ss, cs)
        l4 = TCP(sport=cp if fc else sp, dport=sp if fc else cp, flags=fl, seq=sq, ack=ak if "A" in fl else 0)
        step = len(d) + (1 if ("S" in fl or "F" in fl) else 0)
        if fc: cs += step
        else: ss += step
        return l4, d
    for i, (fc, fl, d) in enumerate([(True, "S", b""), (False, "SA", b""), (True, "A", b""),
                                     (True, "PA", b"q" * 100), (False, "PA", b"r" * 200),
                                     (True, "FA", b""), (False, "FA", b""), (True, "A", b"")]):
        l4, d = tcp(fc, fl, d)
        put(t + 0.001 * i, n, fc, l4, d)
put(60.0, 6, True, UDP(sport=41006, dport=50000), b"q" * 100)
put(60.001, 6, False, UDP(sport=50000, dport=41006), b"r" * 200)
wrpcap(sys.argv[1], pkts)
print(len(pkts), "packets")

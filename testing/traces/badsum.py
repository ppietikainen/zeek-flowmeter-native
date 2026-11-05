"""One TCP connection with one bad-checksum packet per direction; Zeek (without -C) skips them.
Usage: badsum.py OUT.pcap"""
import sys
from scapy.all import Ether, IP, TCP, Raw, wrpcap
t = [1776780000.0]; p = []
def add(pk):
    pk.time = t[0]; t[0] += 0.01; p.append(pk)
def tcp(src, dst, sp, dp, flags, seq, ack, data=b"", bad=False):
    pk = Ether()/IP(src=src, dst=dst)/TCP(sport=sp, dport=dp, flags=flags, seq=seq, ack=ack)/Raw(data)
    if bad:
        pk = Ether(bytes(pk)); pk[TCP].chksum = (pk[TCP].chksum + 1) & 0xffff
    add(pk)
c, s = "10.6.1.1", "10.6.1.2"
tcp(c, s, 41001, 80, "S", 1000, 0)
tcp(s, c, 80, 41001, "SA", 5000, 1001)
tcp(c, s, 41001, 80, "A", 1001, 5001)
tcp(c, s, 41001, 80, "PA", 1001, 5001, b"q"*100)
tcp(c, s, 41001, 80, "PA", 1101, 5001, b"q"*50, bad=True)
tcp(s, c, 80, 41001, "PA", 5001, 1101, b"r"*200)
tcp(s, c, 80, 41001, "PA", 5201, 1101, b"r"*60, bad=True)
tcp(c, s, 41001, 80, "A", 1101, 5201)
wrpcap(sys.argv[1], p)

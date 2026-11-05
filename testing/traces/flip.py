"""Connections whose first packet is not the client's SYN (Zeek flips originator on SYN-ACK first).
Usage: flip.py OUT.pcap"""
import sys
from scapy.all import Ether, IP, TCP, Raw, wrpcap
t = [1776780000.0]
p = []
def add(pk):
    pk.time = t[0]; t[0] += 0.01; p.append(pk)
def tcp(src, dst, sp, dp, flags, seq, ack, data=b""):
    add(Ether()/IP(src=src, dst=dst)/TCP(sport=sp, dport=dp, flags=flags, seq=seq, ack=ack)/Raw(data))
# case 1: capture starts at the SYN-ACK (server first), then client ACK, data both ways
c, s = "10.8.1.1", "10.8.1.2"
tcp(s, c, 80, 41001, "SA", 5000, 1001)
tcp(c, s, 41001, 80, "A", 1001, 5001)
tcp(c, s, 41001, 80, "PA", 1001, 5001, b"q"*100)
tcp(s, c, 80, 41001, "PA", 5001, 1101, b"r"*200)
tcp(c, s, 41001, 80, "A", 1101, 5201)
# case 2: normal, for contrast
c, s = "10.8.2.1", "10.8.2.2"
tcp(c, s, 41002, 80, "S", 1000, 0)
tcp(s, c, 80, 41002, "SA", 5000, 1001)
tcp(c, s, 41002, 80, "A", 1001, 5001)
tcp(c, s, 41002, 80, "PA", 1001, 5001, b"q"*100)
tcp(s, c, 80, 41002, "PA", 5001, 1101, b"r"*200)
wrpcap(sys.argv[1], p)

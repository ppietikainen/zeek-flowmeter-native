"""Corner cases any flow tool should be measured by. Usage: corners.py DIR
 flip2.pcap  : a connection seen from one side only (SYN-ACK, ACK, ACK, FIN-ACK from the server);
               Zeek's originator is the unseen client, history starts with ^
 trunc.pcap  : ICMP echo request/reply truncated by the capture (IP length 32, 28 bytes kept) plus
               a TCP connection truncated after the TCP header (payload cut)"""
import struct, sys, os
from scapy.all import Ether, IP, TCP, ICMP, Raw, wrpcap

out = sys.argv[1]
t0 = 1776780000.0

# --- flip2
p = []
def add(pk, t):
    pk.time = t; p.append(pk)
s, c = "10.5.1.2", "10.5.1.1"
for i, fl in enumerate(["SA", "A", "A", "FA"]):
    add(Ether()/IP(src=s, dst=c)/TCP(sport=80, dport=41001, flags=fl, seq=5000 + i, ack=1001), t0 + i * 0.01)
wrpcap(os.path.join(out, "flip2.pcap"), p)

# --- trunc: raw pcap with caplen < len
def rec(pk, t, cap):
    b = bytes(pk)
    cap = min(cap, len(b))
    return struct.pack("<IIII", int(t), int((t % 1) * 1e6), cap, len(b)) + b[:cap]
recs = []
for i in range(3):
    req = Ether()/IP(src="10.5.2.1", dst="10.5.2.2")/ICMP(type=8, id=7, seq=i)/Raw(b"abcd")
    rep = Ether()/IP(src="10.5.2.2", dst="10.5.2.1")/ICMP(type=0, id=7, seq=i)/Raw(b"abcd")
    recs.append(rec(req, t0 + i * 0.1, 14 + 28))   # IP length 32, 28 kept
    recs.append(rec(rep, t0 + i * 0.1 + 0.01, 14 + 28))
c, sv = "10.5.3.1", "10.5.3.2"
def tcp(src, dst, sp, dp, fl, seq, ack, data=b"", cap=None):
    return Ether()/IP(src=src, dst=dst)/TCP(sport=sp, dport=dp, flags=fl, seq=seq, ack=ack)/Raw(data)
tt = t0 + 1
for i, (src, dst, sp, dp, fl, data) in enumerate([(c, sv, 41003, 80, "S", b""), (sv, c, 80, 41003, "SA", b""),
        (c, sv, 41003, 80, "A", b""), (c, sv, 41003, 80, "PA", b"q" * 100), (sv, c, 80, 41003, "PA", b"r" * 200)]):
    recs.append(rec(tcp(src, dst, sp, dp, fl, 1000 + i, 5000, data), tt + i * 0.01, 14 + 20 + 20))  # headers only
with open(os.path.join(out, "trunc.pcap"), "wb") as fh:
    fh.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
    for r in sorted(recs, key=lambda r: struct.unpack("<II", r[:8])):
        fh.write(r)

# --- knobs.pcap: out-of-order UDP (abs_gap, min header), two TCP bulk periods, IPv4 ICMP echo and unreachable
from scapy.all import UDP
k = []
def kadd(pk, t):
    pk.time = t; k.append(pk)
for tt_, n in ((0.0, 1), (0.010, 2), (0.005, 3)):   # third packet is older than the second
    kadd(Ether()/IP(src="10.4.1.1", dst="10.4.1.2")/UDP(sport=50000, dport=5000)/Raw(b"u" * (10 * n)), t0 + tt_)
cc, ss = "10.4.2.1", "10.4.2.2"
tb = t0 + 1.0
def tc(src, dst, sp, dp, fl, data=b""):
    global tb
    kadd(Ether()/IP(src=src, dst=dst)/TCP(sport=sp, dport=dp, flags=fl, seq=1, ack=1)/Raw(data), tb); tb += 0.01
tc(cc, ss, 41004, 80, "S"); tc(ss, cc, 80, 41004, "SA"); tc(cc, ss, 41004, 80, "A")
for _ in range(5): tc(cc, ss, 41004, 80, "PA", b"q" * 100)      # period 1: 5 packets
tc(ss, cc, 80, 41004, "PA", b"r" * 50)                          # other side ends the run
for _ in range(4): tc(cc, ss, 41004, 80, "PA", b"q" * 100)      # period 2: 4 packets
kadd(Ether()/IP(src="10.4.3.1", dst="10.4.3.2")/ICMP(type=8, id=1, seq=1)/Raw(b"abcd"), t0 + 3)
kadd(Ether()/IP(src="10.4.4.2", dst="10.4.4.1")/ICMP(type=3, code=1)/Raw(b"abcd"), t0 + 3.1)
for i in range(6):   # an echo train: payload packets in a row, but not bulk (not a stream protocol)
    kadd(Ether()/IP(src="10.4.5.1", dst="10.4.5.2")/ICMP(type=8, id=2, seq=i)/Raw(b"abcd"), t0 + 4 + i * 0.01)
# ECN handshake: SYN carries ECE+CWR ([SEW]), SYN-ACK carries ECE only ([S.E]): CWR 1, ECE 2 in total
kadd(Ether()/IP(src="10.4.6.1", dst="10.4.6.2")/TCP(sport=41006, dport=80, flags="SEC", seq=1), t0 + 5)
kadd(Ether()/IP(src="10.4.6.2", dst="10.4.6.1")/TCP(sport=80, dport=41006, flags="SAE", seq=1, ack=2), t0 + 5.01)
wrpcap(os.path.join(out, "knobs.pcap"), k)

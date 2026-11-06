from scapy.all import IP, IPv6, Ether, Raw, wrpcap, GRE
from scapy.layers.sctp import SCTP, SCTPChunkData, SCTPChunkInit
p=[]
t=1776780000.0
def add(pk):
    global t
    pk.time=t; t+=0.01; p.append(pk)
for proto,(a,b) in {47:("10.7.1.1","10.7.1.2"),50:("10.7.2.1","10.7.2.2"),89:("10.7.3.1","10.7.3.2")}.items():
    for i in range(3):
        add(Ether()/IP(src=a,dst=b,proto=proto)/Raw(b"x"*(20+i)))
        add(Ether()/IP(src=b,dst=a,proto=proto)/Raw(b"y"*10))
add(Ether()/IPv6(src="2001:db8:7::1",dst="2001:db8:7::2",nh=58)/Raw(b"\x80\x00\x00\x00"+b"z"*8))
# SCTP (IP protocol 132): ports exist on the wire, Zeek treats it as an unknown transport (ports 0)
for i in range(5):
    add(Ether()/IP(src="10.7.4.1",dst="10.7.4.2")/SCTP(sport=2905,dport=2905,tag=1)/SCTPChunkData(data=b"s"*(30+i),tsn=i,stream_id=0,stream_seq=i))
add(Ether()/IP(src="10.7.4.2",dst="10.7.4.1")/SCTP(sport=2905,dport=2905,tag=2)/SCTPChunkData(data=b"t"*20,tsn=0,stream_id=0,stream_seq=0))
add(Ether()/IP(src="10.7.5.1",dst="10.7.5.2")/SCTP(sport=2906,dport=2905,tag=3)/SCTPChunkData(data=b"u"*10,tsn=0,stream_id=0,stream_seq=0))
wrpcap("other.pcap",p)

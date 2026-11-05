from scapy.all import IP, IPv6, Ether, Raw, wrpcap, GRE
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
wrpcap("other.pcap",p)

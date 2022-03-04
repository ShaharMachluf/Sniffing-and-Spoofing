from scapy.all import * 
#sniff and then spoof
def spoof_pkt(pkt):
    print("got packet")
    if pkt.getlayer(ICMP).type == 8:
        a = IP()
        a.src = pkt[IP].dst
        a.dst = pkt[IP].src
        b = ICMP()
        b.type = 0
        p = a/b
        send(p)

pkt = sniff(iface="br-6b8f6941a504", filter="icmp",prn=spoof_pkt) 


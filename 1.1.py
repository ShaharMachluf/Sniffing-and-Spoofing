from scapy.all import * 
#sniffing packets
def print_pkt(pkt):
    pkt.show()

pkt = sniff(iface="br-6b8f6941a504", filter="icmp", prn=print_pkt) #icmp
pkt = sniff(iface="br-6b8f6941a504", filter="src net 10.9.0.5 and tcp port 23", prn=print_pkt) # tcp
pkt = sniff(iface="br-6b8f6941a504", filter="net 128.230", prn=print_pkt) # subnet

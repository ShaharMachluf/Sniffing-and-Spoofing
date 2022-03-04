from scapy.all import * 
#trace route
count = 1
r = ""
while r != "8.8.8.8":
    a = IP()
    a.dst = "8.8.8.8"
    a.ttl = count
    b = ICMP()
    n = sr1(a/b)
    r = n.src
    print("router number: ", count)
    print(r)
    count += 1
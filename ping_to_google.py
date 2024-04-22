from scapy.all import *

ping = IP(dst="www.google.com")/ICMP()
ans  = sr1(ping)
print(conf.iface)
ans.show()

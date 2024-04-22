from scapy.all import *

def packet_callback(packet):
    if packet.haslayer(TCP):
        print("TCP packet received:")
        packet.show()

# TCPパケットのみをキャプチャ
filter_protocol = "tcp"
sniff(filter=filter_protocol, prn=packet_callback)

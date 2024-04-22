from scapy.all import *

def handle_dns_packet(packet):
    if packet.haslayer(DNSQR):  # DNS query request
        query_name = packet[DNSQR].qname.decode()
        print(f"DNS Query Captured: {query_name}")

# DNSクエリのみをキャプチャ
sniff(filter="udp port 53", prn=handle_dns_packet, store=False)

from scapy.all import *
from scapy.layers.http import HTTPRequest  # HTTP support

def handle_http_packet(packet):
    if packet.haslayer(HTTPRequest):
        host = packet[HTTPRequest].Host.decode()
        path = packet[HTTPRequest].Path.decode()
        print(f"HTTP Request Captured: Host={host}, Path={path}")

# HTTPとHTTPS (port 80 and 443) トラフィックのみをキャプチャ
sniff(filter="tcp port 80 or tcp port 443", prn=handle_http_packet, store=False)

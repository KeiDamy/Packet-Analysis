from scapy.all import *

def handle_high_port_packet(packet):
    if TCP in packet and packet[TCP].dport >= 1024:
        port = packet[TCP].dport
        print(f"High port TCP packet detected: Port={port}")
        #packet.show()

# 特定の非標準ポートを使用するパケットのみをキャプチャ
sniff(filter="tcp and portrange 1024-65535", prn=handle_high_port_packet, store=False)

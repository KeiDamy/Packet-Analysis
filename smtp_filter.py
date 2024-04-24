from scapy.all import *

def handle_smtp_packet(packet):
    if packet.haslayer(TCP) and packet[TCP].dport == 25:
        src = packet[IP].src
        dst = packet[IP].dst
        print(f"SMTP packet detected: From={src} to {dst}")

# SMTPトラフィックのみをキャプチャ (ポート25)
sniff(filter="tcp port 25", prn=handle_smtp_packet, store=False)

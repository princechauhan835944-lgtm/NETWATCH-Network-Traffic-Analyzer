from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime
import sqlite3

DATABASE = "traffic.db"


def save_packet(timestamp, src_ip, dst_ip, protocol, src_port, dst_port, packet_size):
    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO packets (
            timestamp,
            source_ip,
            destination_ip,
            protocol,
            source_port,
            destination_port,
            packet_size
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        timestamp,
        src_ip,
        dst_ip,
        protocol,
        src_port,
        dst_port,
        packet_size
    ))

    connection.commit()
    connection.close()


def analyze_packet(packet):

    if IP not in packet:
        return

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    packet_size = len(packet)

    protocol = "Other"
    src_port = None
    dst_port = None

    if TCP in packet:
        protocol = "TCP"
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport

    elif UDP in packet:
        protocol = "UDP"
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

    elif ICMP in packet:
        protocol = "ICMP"

    save_packet(
        timestamp,
        src_ip,
        dst_ip,
        protocol,
        src_port,
        dst_port,
        packet_size
    )

    print(
        f"{timestamp} | "
        f"{src_ip} → {dst_ip} | "
        f"{protocol} | "
        f"{src_port} → {dst_port} | "
        f"{packet_size} bytes"
    )


print("=" * 60)
print("NETWORK TRAFFIC ANALYZER")
print("=" * 60)
print("Starting packet capture...")
print("Packets will be saved to traffic.db")
print("Press CTRL+C to stop.")
print()

sniff(
    iface="wlan0",
    prn=analyze_packet,
    store=False
)

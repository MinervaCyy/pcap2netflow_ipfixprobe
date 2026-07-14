#!/usr/bin/env python3

from pathlib import Path

from scapy.all import Ether, IP, TCP, UDP, Raw, wrpcap


OUTPUT = Path("tests/data/smoke.pcap")


def main() -> None:
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)

    packets = []

    # Flow 1: complete bidirectional TCP exchange.
    client_mac = "02:00:00:00:00:01"
    server_mac = "02:00:00:00:00:02"
    client_ip = "192.0.2.10"
    server_ip = "192.0.2.20"
    client_port = 40000
    server_port = 443

    packets.extend(
        [
            Ether(src=client_mac, dst=server_mac)
            / IP(src=client_ip, dst=server_ip)
            / TCP(sport=client_port, dport=server_port, flags="S", seq=1000),
            Ether(src=server_mac, dst=client_mac)
            / IP(src=server_ip, dst=client_ip)
            / TCP(sport=server_port, dport=client_port, flags="SA", seq=2000, ack=1001),
            Ether(src=client_mac, dst=server_mac)
            / IP(src=client_ip, dst=server_ip)
            / TCP(sport=client_port, dport=server_port, flags="A", seq=1001, ack=2001),
            Ether(src=client_mac, dst=server_mac)
            / IP(src=client_ip, dst=server_ip)
            / TCP(sport=client_port, dport=server_port, flags="PA", seq=1001, ack=2001)
            / Raw(b"hello"),
            Ether(src=server_mac, dst=client_mac)
            / IP(src=server_ip, dst=client_ip)
            / TCP(sport=server_port, dport=client_port, flags="PA", seq=2001, ack=1006)
            / Raw(b"world"),
            Ether(src=client_mac, dst=server_mac)
            / IP(src=client_ip, dst=server_ip)
            / TCP(sport=client_port, dport=server_port, flags="FA", seq=1006, ack=2006),
            Ether(src=server_mac, dst=client_mac)
            / IP(src=server_ip, dst=client_ip)
            / TCP(sport=server_port, dport=client_port, flags="FA", seq=2006, ack=1007),
            Ether(src=client_mac, dst=server_mac)
            / IP(src=client_ip, dst=server_ip)
            / TCP(sport=client_port, dport=server_port, flags="A", seq=1007, ack=2007),
        ]
    )

    # Flow 2: bidirectional UDP exchange.
    packets.extend(
        [
            Ether(src="02:00:00:00:00:03", dst="02:00:00:00:00:04")
            / IP(src="198.51.100.10", dst="198.51.100.20")
            / UDP(sport=53000, dport=53)
            / Raw(b"query"),
            Ether(src="02:00:00:00:00:04", dst="02:00:00:00:00:03")
            / IP(src="198.51.100.20", dst="198.51.100.10")
            / UDP(sport=53, dport=53000)
            / Raw(b"response"),
        ]
    )

    # Flow 3: one-way UDP packet.
    packets.append(
        Ether(src="02:00:00:00:00:05", dst="02:00:00:00:00:06")
        / IP(src="203.0.113.10", dst="203.0.113.20")
        / UDP(sport=60000, dport=9999)
        / Raw(b"one-way")
    )

    base_time = 1700000000.0
    for index, packet in enumerate(packets):
        packet.time = base_time + index * 0.001

    wrpcap(str(OUTPUT), packets)
    print(f"wrote {len(packets)} packets to {OUTPUT}")


if __name__ == "__main__":
    main()

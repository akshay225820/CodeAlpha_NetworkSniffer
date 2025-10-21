# CodeAlpha_NetworkSniffer

## Project Overview
This project is a simple **network packet sniffer** built using Python. It captures packets from your local network and displays information such as **Ethernet addresses, IP addresses, protocol type, and UDP/TCP ports**.

This tool is useful for learning how networks communicate and for **analyzing traffic in local networks**.

---

## Features
- Captures network packets in real-time.
- Displays **Ethernet (MAC) addresses**.
- Shows **source and destination IP addresses**.
- Detects **protocol type** (TCP/UDP/ICMP/etc.).
- Shows **port numbers** for TCP/UDP packets.
- Optional: Displays payload data (can be extended).

---

## Requirements
- Python 3.8+
- `scapy` library

Install `scapy` using pip:

```bash
pip install scapy

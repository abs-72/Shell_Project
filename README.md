# Shell_Project
Packet sniffer
A lightweight real-time packet sniffer written in Bash that captures and displays network traffic with live parsing, color-coded output, and automatic .pcap saving using tcpdump.

Features
Real-time packet capture and monitoring.

Supports TCP, UDP, ICMP, and ARP protocols.

Color-coded output for easy protocol identification.

Saves all captured traffic into a timestamped .pcap file.

Graceful shutdown with automatic capture saving.

Easily extendable to support more protocols.

Requirements
Linux environment

tcpdump installed

Root privileges to capture network traffic

Usage
bash
Copy
Edit
sudo ./packets_sniffer.sh [interface]
interface (optional): Network interface to sniff on (default: wlan0).

Example:

bash
Copy
Edit
sudo ./packets_sniffer.sh eth0
Output
Displays:

Timestamp

Protocol (TCP/UDP/ICMP/ARP)

Source IP and Port

Destination IP and Port

Packet Size

Additional Information (e.g., TCP Flags, ICMP Type)

Saves the full packet capture to a .pcap file with a filename format:
capture_YYYYMMDD_HHMMSS.pcap

Contribution
The script is designed to be modular — you can easily add support for more protocols by enhancing the parsing logic inside the AWK block. Feel free to fork and expand it!

License
This project is open for educational and personal use.


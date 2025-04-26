#!/bin/bash
# Real-Time Packet Sniffer with Improved Parsing and .pcap File Saving
# Usage: sudo ./sniffer.sh [interface]

# Set colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Check root
[ "$(id -u)" != "0" ] && echo -e "${RED}Error: Run as root${NC}" >&2 && exit 1

INTERFACE=${1:-wlan0}
ip link show "$INTERFACE" >/dev/null 2>&1 || { echo -e "${RED}Error: Interface $INTERFACE not found${NC}" >&2; exit 1; }

# Define file to save captured packets
PCAP_FILE="capture_$(date +%Y%m%d_%H%M%S).pcap"
echo -e "${CYAN}[*] Packets will be saved to ${PCAP_FILE}${NC}"

cleanup() { 
    echo -e "\n${YELLOW}[*] Capture stopped. Packets saved in ${PCAP_FILE}${NC}"
    kill "$TCPDUMP_PID" 2>/dev/null  # Ensure tcpdump is terminated
    exit 0
}
trap cleanup INT TERM

# Start tcpdump in the background to save packets to .pcap file
tcpdump -i "$INTERFACE" -w "$PCAP_FILE" >/dev/null 2>&1 &
TCPDUMP_PID=$!  # Capture PID of tcpdump

# Header
echo -e "${GREEN}Capturing on $INTERFACE...${NC}"
printf "%-12s %-8s %-25s %-25s %-6s %s\n" "Time" "Proto" "Source IP:Port" "Dest IP:Port" "Size" "Info"
echo "------------------------------------------------------------------------------------------"

# Enhanced AWK processing for real-time display
tcpdump -i "$INTERFACE" -l -n -tttt 2>/dev/null | awk -v GREEN="$GREEN" -v BLUE="$BLUE" -v RED="$RED" -v YELLOW="$YELLOW" -v NC="$NC" '
{
    # Extract time without date
    timestamp = substr($2, 1, 12)
    
    # Reset variables
    proto = "OTHER"; src_ip = ""; src_port = ""; dest_ip = ""; dest_port = ""
    pkt_length = 0; info = ""

    # Protocol detection
    if (/ARP/) {
        proto = "ARP"
        # ARP parsing
        if (match($0, /who-has ([0-9.]+)/, arp)) dest_ip = arp[1]
        if (match($0, /tell ([0-9.]+)/, arp)) src_ip = arp[1]
        info = /Request/ ? "Request" : "Reply"
    }
    else if (/ICMP/) {
        proto = "ICMP"
        # Extract source and destination IPs for ICMP
        if (match($0, /([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}) > ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})/, icmp)) {
            src_ip = icmp[1]
            dest_ip = icmp[2]
        }
        # ICMP type detection
        if (/echo request/) info = "Echo Request"
        else if (/echo reply/) info = "Echo Reply"
        else if (/destination unreachable/) info = "Destination Unreachable"
        else if (/time exceeded/) info = "Time Exceeded"
        else info = "Other ICMP"
    }
    else if (match($0, /([0-9]{1,3}\.){3}[0-9]{1,3}([.:][0-9]+)? > ([0-9]{1,3}\.){3}[0-9]{1,3}([.:][0-9]+)?/)) {
        # IP packet parsing
        proto = "IP"
        if (match($0, /([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})([.:]([0-9]+))? > ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})([.:]([0-9]+))?/, ip)) {
            src_ip = ip[1]
            src_port = ip[3]
            dest_ip = ip[4]
            dest_port = ip[6]
        }
        
        # Enhanced protocol detection
        if (match($0, /(TCP|UDP)/, prot)) proto = prot[1]
        if (proto == "IP") {
            if (/Flags \[/) proto = "TCP"
            else if (/: UDP,/) proto = "UDP"
        }

        # Packet length extraction
        if (match($0, /(length|len) ([0-9]+)/, len)) pkt_length = len[2]

        # TCP specific info
        if (proto == "TCP" && match($0, /Flags \[([^\]]+)\]/, flags)) {
            info = "Flags: " flags[1]
            if (match($0, /seq ([0-9:]+)/, seq)) info = info ", Seq: " seq[1]
        }
        else if (proto == "UDP") info = "UDP Payload"
    }

    # Format output
    output = sprintf("%-12s %-8s %-25s %-25s %-6s %s", 
        timestamp, 
        proto,
        (src_port ? src_ip ":" src_port : src_ip),
        (dest_port ? dest_ip ":" dest_port : dest_ip),
        pkt_length,
        info)

    # Apply colors
    switch (proto) {
        case "TCP": print GREEN output NC; break
        case "UDP": print BLUE output NC; break
        case "ICMP": print RED output NC; break
        case "ARP": print YELLOW output NC; break
        default: print output
    }
    fflush("")  # Ensure real-time output
}'
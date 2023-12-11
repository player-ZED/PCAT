from scapy.arch import get_if_list, get_windows_if_list
from scapy.all import sniff, wrpcap, IP, TCP, UDP, ICMP
from scapy.layers.http import HTTP
from collections import Counter
from datetime import datetime
from scapy_http import http
import time
import os

def list_interfaces():
    # Determine the operating system
    is_windows = os.name == 'nt'
    
    # Get a list of network interfaces
    interfaces = get_windows_if_list() if is_windows else get_if_list()
    
    print("Available interfaces:")
    
    # Display available interfaces with their indices
    for i, iface in enumerate(interfaces):
        ifname = iface["name"] if is_windows else iface
        print(f"{i}. {ifname}")
    
    selected = -1
    # Prompt the user to select an interface
    while selected < 0 or selected >= len(interfaces):
        try:
            selected = int(input("Select an interface (0-based index): "))
        except ValueError:
            pass
    return interfaces[selected]["name"] if is_windows else interfaces[selected]


def packet_handler(packet):
    # Display packet details
    packet.show()

def save_and_analyze_packets(device, output_file):
    try:
        print(f"Capturing packets on {device}. Press Ctrl+C to stop.")
        # Sniff packets on the specified interface, calling packet_handler for each packet
        packets = sniff(iface=device, prn=packet_handler, store=True)
    except KeyboardInterrupt:
        print("Packet capture interrupted by user.")
        packets = []

    # Generate a timestamp for the output file
    timestamp = time.strftime("%Y%m%d%H%M%S")
    output_file_with_timestamp = f"{output_file}_{timestamp}.pcap"
    
    # write captured packets to a pcap file
    wrpcap(output_file_with_timestamp, packets, linktype=0)

    print(f"Packets saved to {output_file_with_timestamp}")

    # Analyze the captured packet data
    analyze_packet_data(packets, output_file_with_timestamp)


def analyze_packet_data(packets, output_file_with_timestamp):
    # Initialize counters and lists
    total_packets = len(packets)
    unique_src_ips = set()
    unique_dst_ips = set()
    protocols = Counter()
    port_usage = Counter()
    packet_sizes = []
    timestamps = []

    for packet in packets:
        # checks if packet has IP layer
        if IP in packet:
            # Collect source and destination IP addresses
            unique_src_ips.add(packet[IP].src)
            unique_dst_ips.add(packet[IP].dst)
            # Count protocols
            protocols[type(packet[IP].payload)] += 1

        if TCP in packet:
            # Count usage of destinatin ports
            port_usage[packet[TCP].dport] += 1
            # Collect packet sizes and timestamps
            packet_sizes.append(len(packet))
            timestamps.append(packet.time)

    # Convert timestamps to formatted strings
    formatted_timestamps = [datetime.utcfromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S') for ts in timestamps]

    # Export important data to a text file
    info_file_path = f"{output_file_with_timestamp}.txt"
    with open(info_file_path, 'w') as info_file:
        info_file.write("Important Information Summary:\n")
        info_file.write(f"Total Packets: {total_packets}\n")
        info_file.write(f"Unique Source IPs: {', '.join(unique_src_ips)}\n")
        info_file.write(f"Unique Destination IPs: {', '.join(unique_dst_ips)}\n\n")

        info_file.write("Protocol Distribution:\n")
        for protocol, count in protocols.items():
            info_file.write(f"{protocol.__name__}: {count} packets\n")

        info_file.write("\nPort Numbers:\n")
        for port, count in port_usage.items():
            info_file.write(f"Port {port}: {count} packets\n")

        info_file.write("\nPacket Size and Timing:\n")
        info_file.write(f"Average Packet Size: {sum(packet_sizes) / len(packet_sizes) if packet_sizes else 0}\n")
        info_file.write(f"Formatted Timestamps (first 5):\n")
        for ts in formatted_timestamps[:5]:
            info_file.write(f"  {ts}\n")

    print(f"Information summary saved to {info_file_path}")


if __name__ == "__main__":
    # Prompt the user to select a network interface
    DEVICE = list_interfaces()
    OUTPUT_FILE = "captured_packets"

    # Start capturing and analyzing packets
    save_and_analyze_packets(DEVICE, OUTPUT_FILE)

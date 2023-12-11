# PCAT - Network Packet Capture and Analysis Tool

PCAT (Packet Capture and Analysis Tool) is a Python script that allows users to capture and analyze network packets on a specified interface. The tool uses the Scapy library for packet manipulation and analysis.

( **Perfect for non-technical users who need a quick overview of network traffic without delving into individual packets using Wireshark.**
 )
## Features

- **Packet Capture:** Capture network packets in real-time on a selected network interface.
- **packet saved:** Saves the captured packets in PCAP file for latter use.
- **Packet Analysis:** Analyze captured packets, including source and destination IP addresses, protocol distribution, port numbers, packet sizes, and timing information.

## Prerequisites

Before using PCAT, make sure you have the following installed:

- Python
- Scapy library
- Scapy-HTTP library

```bash
  python -m pip install --upgrade pip
  pip install scapy
  pip install scapy_http
```

Clone the Repository:
   ```bash
   git clone https://github.com/player-ZED/PCAT.git
   cd PCAT
  ```


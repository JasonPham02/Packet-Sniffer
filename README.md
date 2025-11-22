# Python Network Packet Sniffer

## Overview
This is a cybersecurity project that analyzes network traffic in real-time. I built this tool using **Python** and **Scapy** to demonstrate how network protocols work and how to detect suspicious activity programmatically.

## Features
*   **Traffic Analysis:** Captures and logs Source and Destination IP addresses.
*   **Protocol Sorting:** Distinguishes between TCP and UDP packets.
*   **Intrusion Detection:** Automatically alerts when insecure ports (like Port 80/HTTP or 23/Telnet) are used.
*   **Logging:** Saves all activity to `packet_log.txt` for review.

## How to Run (Mac/Linux)
Since this script interacts with the network card, it requires root privileges.


1. **Install the dependency:**
  ```bash
  pip3 install -r requirements.txt
  ```

2. **Run the script:**
  ```bash
  sudo python3 sniffer.py
  ```

## How to Run (Windows)
Windows users need a specific driver to capture network packets.

1. **Install Npcap:**
   * Download and install [Npcap](https://npcap.com/#download).
   * *Important:* During installation, check the box that says **"Install Npcap in WinPcap API-compatible Mode"**.

2. **Install Dependencies:**
  ```bash
  pip install -r requirements.txt
  ```
   
3. **Run the script:**
  ```bash
  python sniffer.py
  ```

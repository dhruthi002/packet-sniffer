# Packet Sniffer
## Overview

This C program allows you to capture network packets on a specified network interface and analyze them. It supports IPv4, IPv6, TCP, UDP, and ARP packets. You can customize the capture options and filter packets based on various criteria.

## Features

- Supports capture on Ethernet interfaces.
- Provides options to specify the capture device, snap length, number of packets to capture, and filter expression.
- Analyzes IPv4, IPv6, TCP, UDP, and ARP packets.
- Displays packet details such as source and destination IP addresses, port numbers, and payload content.
- Allows you to set a default filter expression for capturing specific types of packets (e.g., port 53 for DNS).

## Usage
```bash
./sniffer [-s snap_length] [-i interface_name] [-n number_of_packets] [-f filter_expression]
```

You can run the program from the command line using the following options:

- `-s snap_length`: Set the snap length for packet capture.
- `-i interface_name`: Specify the network interface to capture packets from.
- `-n number_of_packets`: Set the number of packets to capture.
- `-f filter_expression`: Specify a filter expression for capturing specific packets.
  
Example:
```bash
./sniffer -i eth0 -s 1500 -n 50 -f "port 80"
```

## Requirements
- libpcap library for packet capture.
- A C compiler (e.g., GCC) to build the program.

## Build
To compile the program, run the following command:

```bash
gcc -o sniffer sniffer.c -lpcap
```
## References
https://www.tcpdump.org/pcap.html

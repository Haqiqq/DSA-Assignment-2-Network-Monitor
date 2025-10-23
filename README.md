# DSA-Assignment-2-Network-Monitor
A Linux-based network packet analyzer built in C++ using raw sockets and custom implementations of stacks and queues. This project captures, dissects, filters, and replays network packets in real time, simulating a robust monitoring system.


HOW TO RUN THE PROJECT?

# Packet Capture and Replay Tool
This project captures network packets on a specified interface, parses Ethernet, IPv4, IPv6, TCP, and UDP headers, and optionally replays packets. It uses custom Stack and Queue implementations for packet management.

## Requirements

- Linux system
- g++ compiler (supports C++11 or later)
- Root privileges to capture packets (`sudo`)


## Files

- `packet.cpp` – Main source file containing the capture, dissection, and replay logic.

## Compilation

1. Open Terminal and navigate to the folder where `packet.cpp` is located:
cd ~/Downloads

## Check your network interfaces (so you know which one to capture):
ip a

## Compile the program using g++:
g++ packet.cpp -o pac -std=c++11

If you get errors about missing headers:
sudo apt update
sudo apt install build-essential linux-headers-$('username')

Run the program as root (required for packet capture):
using sudo keyword.

## Run the program with sudo and arguments
sudo ./pac <interface> <target_IP> <gateway_IP>

Example:
sudo ./pac enp0s3 192.168.1.11 8.8.8.8

enp0s3 → Your network interface
192.168.1.11 → Target IP to capture packets from
8.8.8.8 → Gateway or DNS IP

This packet capture and analysis program demonstrates the practical use of custom stacks and queues for network packet management. It allows capturing, dissecting, and filtering packets in real-time on a single interface. Proper understanding of network layers, data structures, and error handling is essential for extending this project to more advanced network monitoring or security applications.

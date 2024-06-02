# cs478-arp
Collection of ARP attacks for a project presentation in Network Security (CS 478)

## Prerequisites
Docker containers:
- Attacker
- Sender
- Receiver
In this project, the attack is emulated to be within the same network as the sender and receiver to use ARP attacks
## Installation
Newly created dockers will require packages such as ifconfig or ping.
The setup.sh will take care of installing packages for new docker containers
### Usage
    Usage: ./setup.sh <type of container>
    Types of containers: attacker/default
#### Default Container
- ifconfig
- sudo
- ping
#### Attacker Container
Installed dependencies:
- default container dependencies
- wireshark
- tcpdump
- scapy

## Usage
Start the python script:
```
python3 mitm.py <target_ip> <gateway_ip>
```
Where gateway_ip is the gateway IP and target IP is the specific target's IP within the network

The python script contains three attacks:
1. MTIM
2. ARP Flooding
3. Session Hijacking
The script will prompt the user for a specific attack once the correct arguments are specified.
### Wireshark and TCPdump
To capture packets on an interface, store it into a file, and inspect it on wireshark:
#### tcpdump
```
tcpdump -i eth0 -w <output_file>.pcap
```
TCPdump will listen on the eth0 interface and write the output to a specified file in the pcap format
#### Wireshark
To visualize the captured packets based on pcap file using wireshark:
```
wireshark <output_file>.pcap
```
# Resources
[Scapy ARP Poisoining | StackOverFlow](https://stackoverflow.com/questions/53055062/scapy-arp-poisoning)
[How to make an ARP Spoofing attack using Scapy – Python | GeeksforGeeks](https://www.geeksforgeeks.org/how-to-make-a-arp-spoofing-attack-using-scapy-python/)
[Black Hat Python — ARP Cache Poisoning with Scapy](https://ismailakkila.medium.com/black-hat-python-arp-cache-poisoning-with-scapy-7cb1d8b9d242)
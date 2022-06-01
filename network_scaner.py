#!/usr/bin/env python

import scapy.all as scapy 
import optparse

def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="target", help="Target IP/ IP range.")
    options, arguments = parser.parse_args()
    return options

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") #Send request to broadcast address which will send packet to all devices within the network.
    scapy.ls(scapy.Ether()) #To get info about Ether() class
    arp_request_broadcast = broadcast/arp_request #Create a new packet which is combination of previous packets.
    arp_request_broadcast.show() #Display more details about content of packet
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0] #Function which we use to send packet and recive response, this list has 2 list elements first is answerd and second is unanswered we are just interested for answerd
    clients_list = []
    for element in answered_list:
        #make a list of dictionary elements
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(client_dict)
    return clients_list

def print_result(clients_list):
    print("IP\t\t\tMAC Address\n-----------------------------------------") 
    for client in clients_list:
        print(client["ip"] + "\t\t" + client["mac"])

options = get_arguments()
scan_result = scan(options.target)
print_result(scan_result)

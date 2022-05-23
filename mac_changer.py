#!/usr/bin/env python

import subprocess
import optparse
import re

def change_mac(interface, new_mac):
    print("[+] Changing MAC address for " + interface + " to " + new_mac)
    subprocess.call(["ifconfig", interface, "down"])
    subprocess.call(["ifconfig", interface, "hw", "ether", new_mac])
    subprocess.call(["ifconfig", interface, "up"])

def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-i", "--interface", dest="interface", help="Interface to change MAC address.")
    parser.add_option("-m", "--new_mac", dest="new_mac", help="Interface to change MAC address.")
    (options, arguments) = parser.parse_args()
    if not options.interface:
        parser.error("[-] Plese specify an interface")
    elif not options.new_mac:
        parser.error("[-] Please specify a new mac address")
    return options

options = get_arguments()
change_mac(options.interface, options.new_mac)
ifconfig_result = subprocess.check_output(["ifconfig", options.interface])
search_mac = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", str(ifconfig_result))
#If there is more then one match it will create some kind of array and you can easly go trhought it
current_mac_address = search_mac.group(0)
print(options.new_mac)
print(str(current_mac_address))
if current_mac_address == options.new_mac:
    print("[+] MAC address was successfully changed.")
else:
    print("[-] MAC address did not get changed.")


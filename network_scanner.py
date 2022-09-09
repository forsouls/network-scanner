#!/usr/bin/env python

import scapy.all as scapy
import argparse


def get_ip():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-t",
        "--target",
        dest="target",
        help="Target to find MAC Address, for example: --target 190.160.1.1/25",
    )
    options = parser.parse_args()
    if not options.target:
        parser.error(
            "[-] Please specify a Target to find his MAC Addess, use --help for more info."
        )
    return options.target


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    clients_list = []
    for element in answered_list:
        clients_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(clients_dict)
    return clients_list


def print_result(results_list):
    print("--------------------------------------------------")
    print("\tIP\t\t\tMAC Address")
    print("--------------------------------------------------")
    for client in results_list:
        print("   " + client["ip"] + "\t\t     " + client["mac"])


target = get_ip()
scan_result = scan(target)
print_result(scan_result)

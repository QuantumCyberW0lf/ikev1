from scapy.all import *
import os, sys

def openPCAPFile(path: str) -> scapy.plist.PacketList:
    if not os.path.exists(path):
        print("[-] File {} doesn't exists".format(path))
        sys.exit(1)
    packets_list = rdpcap(path)
    return packets_list

def getISAKMPPackets(packets: scapy.plist.PacketList) -> []:
    res = []
    for p in packets:
        if p.haslayer(ISAKMP):
            res.append(p[3]) #4. layer
    return res


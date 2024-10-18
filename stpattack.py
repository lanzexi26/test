from scapy.all import *
from scapy.layers.l2 import Ether, LLC, STP

# Ask for user input on priority and VLAN ID
user_priority = int(input("Enter the bridge priority (should be a multiple of 4096): "))
vlan_id = int(input("Enter the VLAN ID (as a system ID extension): "))

# Ensure the priority is correctly formatted
priority = user_priority if user_priority % 4096 == 0 else (user_priority // 4096) * 4096

# Calculate the final bridge priority including the VLAN ID
bridge_priority = priority + vlan_id  # Ensure the sum does not exceed 65535

# Interface MAC address
src_mac = get_if_hwaddr("eth0")

# Ethernet frame for STP BPDUs
ether = Ether(dst="01:80:C2:00:00:00", src=src_mac)

# STP Configuration BPDU
bpdu = STP(
    version=0,
    bpdutype=0,
    bpduflags=0,
    rootid=bridge_priority,
    rootmac=src_mac,
    pathcost=4,
    bridgeid=bridge_priority,
    bridgemac=src_mac,
    portid=0x8001,
    age=1,
    maxage=20,
    hellotime=2,
    fwddelay=15
)

# Encapsulate in LLC
llc = LLC(dsap=0x42, ssap=0x42, ctrl=3)

# Complete packet
packet = ether / llc / bpdu

try:
    print("Sending packets... Press Ctrl+C to stop.")
    while True:
        sendp(packet, iface="eth0", verbose=False)
except KeyboardInterrupt:
    print("Stopped sending packets.")
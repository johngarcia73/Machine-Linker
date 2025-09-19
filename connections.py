import socket
import struct
import threading
import os

ETH_P_ALL = 0x0003
CUSTOM_ETHERTYPE = 0x1234


def mac_to_bytes(mac):
    return bytes(int(b, 16) for b in mac.split(":"))

def bytes_to_mac(b):
    return ":".join("%02x" % byte for byte in b)

def list_interfaces():
    return os.listdir('/sys/class/net')

def first_non_lo():
    for iface in list_interfaces():
        if iface != 'lo':
            return iface
    raise RuntimeError("No network interface found")

def getting_frames():
    while True:
        raw_frame, addr = s.recvfrom(2048)
        dest_mac = bytes_to_mac(raw_frame[0:6])
        src_mac = bytes_to_mac(raw_frame[6:12])
        eth_type = struct.unpack('!H', raw_frame[12:14])[0]
        payload = raw_frame[14:]
        if eth_type == CUSTOM_ETHERTYPE:  
            print(f"Received IP packet from {src_mac} to {dest_mac}, payload length: {len(payload)} bytes") 
            print(f"Payload: {payload.decode('utf-8', errors='ignore')}")

def connect_to_interface(interface=None):
    if not interface:
        interface = first_non_lo()
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    s.bind((interface, 0))
    return s


# Test ---------------------------------
s = connect_to_interface()
t = threading.Thread(target=getting_frames, daemon=True)  # Omitir el daemon para seguir testeando, o hacerlo false
t.start()

dest_mac = input("Enter destination MAC address (format: xx:xx:xx:xx:xx:xx): ")
coded_dest_mac = mac_to_bytes(dest_mac)

src_mac = s.getsockname()[4].hex(':')
coded_src_mac = mac_to_bytes(src_mac)

coded_eth_type = struct.pack('!H', CUSTOM_ETHERTYPE)

message = input("Enter message to send: ")
payload = message.encode('utf-8')

frame = coded_dest_mac + coded_src_mac + coded_eth_type + payload
s.send(frame)
print("Sent message")
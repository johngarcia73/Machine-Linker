import os
import socket
import struct
import threading
from typing import Dict

class Machine:
   
    ETH_P_ALL = 0x0003      # Capture all protocols
    DEFAULT_ETHERTYPE = 0x1234

    def __init__(self, interface=None, ethertype=DEFAULT_ETHERTYPE,
                 frame_handler=None, buffer_size=2048):
        """
        interface     : Interface name,if None picks the first one different from'lo'.
        ethertype     : Ethertype (p.e. 0x1234).
        frame_handler : A function to use the frame, if None, default (recomended, and not tested yet)(dest_mac, src_mac, payload).
        buffer_size   : Reception buffer size.
        """
        self._interface = interface or self._first_non_lo()
        self._MAC = self.get_interface_mac()
        self.ethertype = ethertype
        self.buffer_size = buffer_size
        self._discovered_machines: Dict[str, str] = {}
        self._discovered_machines[self._MAC] = 'ME'
        self._socket = self._open_socket()
        self._handler = frame_handler
        self._running = False
        self._thread = threading.Thread(target=self._capture_loop, daemon=False)
        self.send_greeting()

    @staticmethod
    def mac_to_bytes(mac):
        """'Obvius, huh?'"""
        return bytes(int(b, 16) for b in mac.split(":"))

    @staticmethod
    def bytes_to_mac(b):
        """:)'"""
        return ":".join("%02x" % byte for byte in b)

    @staticmethod
    def is_introducing(flag):
        return flag == 0b00000001

    @staticmethod
    def is_acknowledging(flag):
        return flag == 0b00000010
    
    @staticmethod
    def is_speaking(flag):
        return flag == 0b00000000

    @staticmethod
    def list_interfaces():
        """Lists available interfaces at /sys/class/net"""
        return [i for i in os.listdir("/sys/class/net")]

    @classmethod
    def _first_non_lo(cls):
        for iface in cls.list_interfaces():
            if iface != "lo":
                return iface
        raise RuntimeError("Only loopback interface found.")

    def _open_socket(self):
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(self.ETH_P_ALL))
        s.bind((self._interface, 0))
        return s

    def start(self):
        """Starts the thread to capture frames."""
        if not self._running:
            self._running = True
            self._thread.start()

    def stop(self):
        """Stops the thread and closes the socket."""
        self._running = False
        self._thread.join(timeout=1)
        self._socket.close()

    def _capture_loop(self):
        while self._running:
            raw_frame, _ = self._socket.recvfrom(self.buffer_size)
            dest_mac = self.bytes_to_mac(raw_frame[0:6])
            src_mac = self.bytes_to_mac(raw_frame[6:12])
            eth_type = struct.unpack("!H", raw_frame[12:14])[0]
            flag = raw_frame[14]
            payload = raw_frame[15:]
            if eth_type == self.ethertype :

                if self.is_introducing(flag):                # If is greeting, I acknowledge and store               
                    self.add_machine(src_mac)
                    self.send_frame(src_mac, b'', flag=0b00000010)  # ACK

                elif self.is_acknowledging(flag):           # If is acknowledging, I store
                    self.add_machine(src_mac)

                elif self.is_speaking(flag):                # If is speaking, handle
                    if self._handler:
                        self._handler(dest_mac, src_mac, payload)
                    else:
                        print("[%s] Frame %s -> %s, len=%d bytes"
                            % (self.interface, src_mac, dest_mac, len(payload)))
                        

    def add_machine(self, mac, name='NEW_MACHINE'):
        """Adds a machine to the discovered list."""
        if mac not in self._discovered_machines:
            self._discovered_machines[mac] = name
            print("Discovered new machine: %s" % (mac))

                    
    def send_frame(self, dest_mac, payload, flag=0b00000000, src_mac=None):
        """
        Sends a frame with configured ethertype.
        dest_mac : Destination MAC
        payload  : Data in bytes.
        src_mac  : Origin MAC.If None, uses interface MAC.
        """
        src_mac = src_mac or self.get_interface_mac()
        frame = self.mac_to_bytes(dest_mac) + self.mac_to_bytes(src_mac)
        frame += struct.pack("!H", self.ethertype) + flag.to_bytes() + payload
        self._socket.send(frame)

    def send_greeting(self):
        """Sends a greeting frame to announce presence."""
        self.send_frame("ff:ff:ff:ff:ff:ff", b'', flag=0b00000001)

    def send_ack(self, dest_mac):
        """Sends an acknowledgment frame to a specific MAC."""
        self.send_frame(dest_mac, b'', flag=0b00000010)

    def send_data(self, dest_mac, data):
        """Sends a data frame to a specific MAC."""
        self.send_frame(dest_mac, data, flag=0b00000000)



    def get_interface_mac(self):
        """Gets the MAC address of the bound interface."""
        with open("/sys/class/net/%s/address" % self._interface) as f:
            return f.read().strip()

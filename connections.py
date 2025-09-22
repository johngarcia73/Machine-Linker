import os
import socket
import struct
import threading


class RawEthernetConnector:
   
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
        self.interface = interface or self._first_non_lo()
        self.ethertype = ethertype
        self.buffer_size = buffer_size
        self._socket = self._open_socket()
        self._handler = frame_handler
        self._running = False
        self._thread = threading.Thread(target=self._capture_loop, daemon=False)


    @staticmethod
    def mac_to_bytes(mac):
        """'Obvius, huh?'"""
        return bytes(int(b, 16) for b in mac.split(":"))

    @staticmethod
    def bytes_to_mac(b):
        """:)'"""
        return ":".join("%02x" % byte for byte in b)

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
        s.bind((self.interface, 0))
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
            payload = raw_frame[14:]
            if eth_type == self.ethertype:
                if self._handler:
                    self._handler(dest_mac, src_mac, payload)
                else:
                    print("[%s] Frame %s -> %s, len=%d bytes"
                        % (self.interface, src_mac, dest_mac, len(payload)))
                    
    def send_frame(self, dest_mac, payload, src_mac=None):
        """
        Sends a frame with configured ethertype.
        dest_mac : Destination MAC
        payload  : Data in bytes.
        src_mac  : Origin MAC.If None, uses interface MAC.
        """
        if src_mac is None:
            src_mac = self.get_interface_mac()
        frame = self.mac_to_bytes(dest_mac) + self.mac_to_bytes(src_mac)
        frame += struct.pack("!H", self.ethertype) + payload
        self._socket.send(frame)

    def get_interface_mac(self):
        """Gets the MAC address of the bound interface."""
        with open("/sys/class/net/%s/address" % self.interface) as f:
            return f.read().strip()

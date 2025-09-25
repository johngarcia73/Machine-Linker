import os
import socket
import struct
import threading
import time
import random
import zlib  # For CRC32 checksum
from typing import Dict, Any

class Machine:

    ETH_P_ALL = 0x0003
    DEFAULT_ETHERTYPE = 0x1234
    MAX_PAYLOAD_SIZE = 1480  # Max payload to avoid fragmentation (standard MTU 1500 - headers)
    TIME_OUT_SECONDS = 60  # Time in seconds to keep incomplete transfers in buffer

    FLAG_SPEAK = 0b00000000      # A single, complete message
    FLAG_GREET = 0b00000001      # Announce presence (broadcast)
    FLAG_ACK = 0b00000010        # Acknowledge a greeting
    FLAG_CHUNK = 0b00000100      # A chunk of a larger message/file

    # ! = network byte order (big-endian)
    
    TRANSPORT_HEADER_FORMAT = "!IIII"   # I = unsigned int (4 bytes)
    TRANSPORT_HEADER_SIZE = struct.calcsize(TRANSPORT_HEADER_FORMAT)
    CHUNK_DATA_SIZE = MAX_PAYLOAD_SIZE - TRANSPORT_HEADER_SIZE

    def __init__(self, interface=None, ethertype=DEFAULT_ETHERTYPE,
                 frame_handler=None, discovery_handler=None, buffer_size=2048):
        self._interface = interface or self._first_non_lo()
        self._MAC = self.get_interface_mac()
        self.ethertype = ethertype
        self.buffer_size = buffer_size
        self._discovered_machines: Dict[str, str] = {}
        self._discovered_machines[self._MAC] = 'ME'
        
        self._socket = self._open_socket()
        self._handler = frame_handler
        self._discovery_handler = discovery_handler
        
        self._running = False
        self._thread = threading.Thread(target=self._capture_loop, daemon=True)

        #               Reassembly Buffer
        # Stores incoming chunks before they are complete.
        # Format: { transfer_id: { "total": int, "chunks": { index: data }, "timestamp": float } }
        self._reassembly_buffer: Dict[int, Dict[str, Any]] = {}
        self.send_greeting()

    @staticmethod
    def mac_to_bytes(mac: str) -> bytes:
        return bytes(int(b, 16) for b in mac.split(":"))

    @staticmethod
    def bytes_to_mac(b: bytes) -> str:
        return ":".join(f"{byte:02x}" for byte in b)

    @staticmethod
    def list_interfaces() -> list[str]:
        return [i for i in os.listdir("/sys/class/net")]


    def _open_socket(self):
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(self.ETH_P_ALL))
        s.bind((self._interface, 0))
        return s

    def start(self):
        if not self._running:
            self._running = True
            self._thread.start()
            print("Machine started.")

    def stop(self):
        if self._running:
            self._running = False
            try:
                self._socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self._thread.join(timeout=1)
            print("Machine stopped.")

    def _capture_loop(self):
        while self._running:
            try:
                raw_frame, _ = self._socket.recvfrom(self.buffer_size)
                
                       #Ethernet Header Parsing
                dest_mac = self.bytes_to_mac(raw_frame[0:6])
                src_mac = self.bytes_to_mac(raw_frame[6:12])
                eth_type = struct.unpack("!H", raw_frame[12:14])[0]
                
                if eth_type != self.ethertype:
                    continue

                    #Custom Protocol
                flag = raw_frame[14]
                payload = raw_frame[15:]

                if flag == self.FLAG_GREET:
                    self.add_machine(src_mac)
                    self.send_ack(src_mac)

                elif flag == self.FLAG_ACK:
                    self.add_machine(src_mac)

                elif flag == self.FLAG_SPEAK:
                    if self._handler:
                        self._handler(dest_mac, src_mac, payload)

                elif flag == self.FLAG_CHUNK:
                    self._process_chunk(dest_mac, src_mac, payload)

            except socket.error:
                if self._running: print("Socket error in capture loop.")
                break

            except Exception as e:
                if self._running: print(f"An error occurred in capture loop: {e}")
                break

        print("Capture loop terminated.")

    def _process_chunk(self, dest_mac, src_mac, payload):
        """Validates and stores a chunk, reassembling the message if complete."""
        if len(payload) < self.TRANSPORT_HEADER_SIZE:
            return # Bad chunk

        # Parse the transport header
        header = payload[:self.TRANSPORT_HEADER_SIZE]
        chunk_data = payload[self.TRANSPORT_HEADER_SIZE:]
        id, index, total, received_crc = struct.unpack(self.TRANSPORT_HEADER_FORMAT, header)

        # Validate chunk integrity
        calculated_crc = zlib.crc32(chunk_data)
        if received_crc != calculated_crc:
            print(f"CRC mismatch for chunk {index}/{total} from {src_mac}. Discarding.")
            return

        # Store the chunk
        if id not in self._reassembly_buffer:
            self._reassembly_buffer[id] = {"total": total, "chunks": {}, "timestamp": time.time()}
        
        self._reassembly_buffer[id]["chunks"][index] = chunk_data

        # Check for completion and reassemble
        if len(self._reassembly_buffer[id]["chunks"]) == self._reassembly_buffer[id]["total"]:
            self._reassemble_chunks(id, dest_mac, src_mac)
        
        self._cleanup_buffer()

    def _reassemble_chunks(self, id, dest_mac, src_mac):
        """Reconstructs the full message from chunks and passes it to the handler."""
        transfer = self._reassembly_buffer.pop(id)
        total_chunks = transfer["total"]
        chunks = transfer["chunks"]

        if len(chunks) != total_chunks:
            print(f"Transfer {id} from {src_mac} is incomplete. Dropping.")
            return

        # Reconstruct the message
        full_data = b"".join(chunks[i] for i in range(total_chunks))
        
        print(f"Reassembled message of {len(full_data)} bytes from {src_mac}.")
        if self._handler:
            self._handler(dest_mac, src_mac, full_data)

    def _cleanup_buffer(self):
        """Removes old, incomplete transfers from the reassembly buffer."""
        current_time = time.time()
        to_delete = [id for id, data in self._reassembly_buffer.items() if current_time - data["timestamp"] > self.TIME_OUT_SECONDS]
        for id in to_delete:
            del self._reassembly_buffer[id]
            print(f"Timed out and removed incomplete transfer {id}.")

    def add_machine(self, mac, name='NEW_MACHINE'):
        if mac not in self._discovered_machines:
            self._discovered_machines[mac] = name
            print(f"Discovered new machine: {mac}")
            if self._discovery_handler:
                self._discovery_handler(mac)


    def send_frame(self, dest_mac: str, payload: bytes, flag: int, src_mac: str = None):
        src_mac_bytes = self.mac_to_bytes(src_mac or self._MAC)
        dest_mac_bytes = self.mac_to_bytes(dest_mac)
        eth_header = dest_mac_bytes + src_mac_bytes + struct.pack("!H", self.ethertype)
        
        frame = eth_header + flag.to_bytes(1, 'big') + payload
        self._socket.send(frame)

    def send_greeting(self):
        self.send_frame("ff:ff:ff:ff:ff:ff", b'', self.FLAG_GREET)

    def send_ack(self, dest_mac: str):
        self.send_frame(dest_mac, b'', self.FLAG_ACK)

    def send_data(self, dest_mac: str, data: bytes):
        """
        Sends data to a specific MAC. Automatically handles fragmentation for large data.
        """
        # If data is small enough, send as a single frame.
        if len(data) <= self.MAX_PAYLOAD_SIZE:
            self.send_frame(dest_mac, data, self.FLAG_SPEAK)
            return

        # If data is too large, divide it.
        print(f"Data is large ({len(data)} bytes). Starting chunked transfer.")
        tid = random.randint(0, 0xFFFFFFFF)
        chunks = [data[i:i + self.CHUNK_DATA_SIZE] for i in range(0, len(data), self.CHUNK_DATA_SIZE)]
        total_chunks = len(chunks)

        for i, chunk_data in enumerate(chunks):
            # Calculate CRC32 checksum for the data part of the chunk
            crc = zlib.crc32(chunk_data)
            
            header = struct.pack(self.TRANSPORT_HEADER_FORMAT, tid, i, total_chunks, crc)
            
            self.send_frame(dest_mac, header + chunk_data, self.FLAG_CHUNK)
            time.sleep(0.001) 
        
        print(f"Sent {total_chunks} chunks for transfer ID {tid}.")

    def get_interface_mac(self) -> str:
        with open(f"/sys/class/net/{self._interface}/address") as f:
            return f.read().strip()

    @classmethod
    def _first_non_lo(cls) -> str:
        for iface in cls.list_interfaces():
            if iface != "lo":
                return iface
        raise RuntimeError("Only loopback interface found.")
import os
import socket
import struct
import threading
import time
import random
import zlib
import hmac
import hashlib
from typing import Dict, Any, Callable

class Machine:
    ETH_P_ALL = 0x0003
    DEFAULT_ETHERTYPE = 0x1234
    MAX_PAYLOAD_SIZE = 1500
    TIME_OUT_SECONDS = 60

    FLAG_SPEAK = 0b00000000
    FLAG_GREET = 0b00000001
    FLAG_ACK = 0b00000010
    FLAG_CHUNK = 0b00000100
    FLAG_CHUNK_ACK = 0b00001000
    FLAG_CHUNK_NACK = 0b00010000

    TRANSPORT_HEADER_FORMAT = "!IIII"
    TRANSPORT_HEADER_SIZE = struct.calcsize(TRANSPORT_HEADER_FORMAT)
    CHUNK_DATA_SIZE = MAX_PAYLOAD_SIZE - TRANSPORT_HEADER_SIZE
    CHUNK_RETRANSMIT_TIMEOUT = 0.5
    SLIDING_WINDOW_SIZE = 16

    # === ENCRYPTION (STD LIB) ===
    STREAM_NONCE_SIZE = 8
    HMAC_TAG_SIZE = 32

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

        # === ENCRYPTION  ===
        self._encryption_enabled = False
        self._psk = b'mi_clave_segura_de_32_bytes_12345678'  # clave precompartida


        #               Reassembly Buffer
        # Stores incoming chunks before they are complete.
        # Format: { transfer_id: { "total": int, "chunks": { index: data }, "timestamp": float } }
        self._reassembly_buffer: Dict[int, Dict[str, Any]] = {}
        self._outgoing_transfers: Dict[int, Dict[str, Any]] = {}
        self._transfer_lock = threading.Lock()
        self.send_greeting()

    # ------------------------ ENCRYPTION API ------------------------
    def set_psk(self, key: bytes):
        """Define la clave precompartida (PSK)."""
        if not isinstance(key, (bytes, bytearray)):
            raise TypeError('PSK debe ser bytes')
        if len(key) < 8:
            raise ValueError('PSK demasiado corta, usa >= 16 bytes')
        self._psk = bytes(key)

    def enable_encryption(self, enabled: bool):
        if enabled and self._psk is None:
            raise RuntimeError('Primero configura la PSK con set_psk()')
        self._encryption_enabled = bool(enabled)

    # ------------------------ ENCRYPTION HELPERS ------------------------
    def _derive_keystream(self, nonce: bytes, length: int) -> bytes:
        out = bytearray()
        ctr = 0
        while len(out) < length:
            ctr_bytes = struct.pack('!I', ctr)
            digest = hashlib.sha256(self._psk + nonce + ctr_bytes).digest()
            out.extend(digest)
            ctr += 1
        return bytes(out[:length])

    def _xor_bytes(self, a: bytes, b: bytes) -> bytes:
        return bytes(x ^ y for x, y in zip(a, b))

    def _attempt_decrypt_payload(self, flag: int, payload: bytes) -> bytes | None:
        if not self._encryption_enabled:
            return payload
        if self._psk is None:
            print('Encriptado activo pero PSK no configurada')
            return None
        if len(payload) < (self.STREAM_NONCE_SIZE + self.HMAC_TAG_SIZE):
            print('Payload cifrado demasiado pequeño — descartar')
            return None
        
        nonce = payload[:self.STREAM_NONCE_SIZE]
        tag = payload[-self.HMAC_TAG_SIZE:]
        ciphertext = payload[self.STREAM_NONCE_SIZE:-self.HMAC_TAG_SIZE]

        flag_byte = flag.to_bytes(1, 'big')
        expected = hmac.new(self._psk, flag_byte + nonce + ciphertext, hashlib.sha256).digest()
        if not hmac.compare_digest(expected, tag):
            print('HMAC inválido — descartar frame')
            return None
        ks = self._derive_keystream(nonce, len(ciphertext))
        plaintext = self._xor_bytes(ciphertext, ks)
        return plaintext


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



    def send_frame(self, dest_mac: str, payload: bytes, flag: int, src_mac: str = None):
        src_mac_bytes = self.mac_to_bytes(src_mac or self._MAC)
        dest_mac_bytes = self.mac_to_bytes(dest_mac)
        eth_header = dest_mac_bytes + src_mac_bytes + struct.pack("!H", self.ethertype)
        flag_byte = flag.to_bytes(1, 'big')

        final_payload = payload
        if self._encryption_enabled:
            nonce = os.urandom(self.STREAM_NONCE_SIZE)
            ks = self._derive_keystream(nonce, len(payload))
            ciphertext = self._xor_bytes(payload, ks)
            tag = hmac.new(self._psk, flag_byte + nonce + ciphertext, hashlib.sha256).digest()
            final_payload = nonce + ciphertext + tag

        frame = eth_header + flag_byte + final_payload
        try:
            self._socket.send(frame)
        except OSError as e:
            print(f"Failed to send frame: {e}")

    def _capture_loop(self):
        while self._running:
            try:
                raw_frame, _ = self._socket.recvfrom(self.buffer_size)
                dest_mac = self.bytes_to_mac(raw_frame[0:6])
                src_mac = self.bytes_to_mac(raw_frame[6:12])
                eth_type = struct.unpack("!H", raw_frame[12:14])[0]

                if eth_type != self.ethertype:
                    continue

                flag = raw_frame[14]
                payload = raw_frame[15:]

                clear_payload = self._attempt_decrypt_payload(flag, payload)
                if clear_payload is None:
                    continue

                if flag == self.FLAG_SPEAK and self._handler:
                    self._handler(dest_mac, src_mac, clear_payload)
                elif flag == self.FLAG_CHUNK:
                    self._process_chunk(dest_mac, src_mac, clear_payload)
                elif flag == self.FLAG_CHUNK_ACK:
                    self._process_chunk_ack(src_mac, clear_payload)
                elif flag == self.FLAG_CHUNK_NACK:
                    self._process_chunk_nack(src_mac, clear_payload)

            except socket.error:
                if self._running:
                    print("Socket error in capture loop.")
                break
            except Exception as e:
                if self._running:
                    print(f"Error in capture loop: {e}")
                break

        print("Capture loop terminated.")


    def _process_chunk(self, dest_mac, src_mac, payload):
        """Validates and stores a chunk, reassembling the message if complete.
        """
        if len(payload) < self.TRANSPORT_HEADER_SIZE:
            return  # Bad chunk

        # Parse the transport header
        header = payload[:self.TRANSPORT_HEADER_SIZE]
        chunk_data = payload[self.TRANSPORT_HEADER_SIZE:]
        tid, index, total, received_crc = struct.unpack(self.TRANSPORT_HEADER_FORMAT, header)

        # Validate chunk integrity
        calculated_crc = zlib.crc32(chunk_data)
        if received_crc != calculated_crc:
            print(f"CRC mismatch for chunk {index}/{total} from {src_mac}. Sending NACK.")
            self.send_chunk_control_frame(src_mac, tid, index, total, self.FLAG_CHUNK_NACK)
            return

        # Store the chunk (create reassembly entry if first chunk)
        now = time.time()
        if tid not in self._reassembly_buffer:
            # include src so reassemble can know origin without
            self._reassembly_buffer[tid] = {
                "total": total,
                "chunks": {},
                "timestamp": now,
                "src": src_mac
            }

        # update timestamp on every chunk arrival (prevents premature timeout)
        self._reassembly_buffer[tid]["timestamp"] = now

        if index not in self._reassembly_buffer[tid]["chunks"]:
            self._reassembly_buffer[tid]["chunks"][index] = chunk_data
        # acknowledge chunk reception to sender
        self.send_chunk_control_frame(src_mac, tid, index, total, self.FLAG_CHUNK_ACK)
        if len(self._reassembly_buffer[tid]["chunks"]) == self._reassembly_buffer[tid]["total"]:
            self._reassemble_chunks(tid)

        self._cleanup_buffer()


    def _process_chunk_ack(self, src_mac, payload):
        if len(payload) < self.TRANSPORT_HEADER_SIZE:
            return
        tid, index, _, _ = struct.unpack(self.TRANSPORT_HEADER_FORMAT, payload)
        with self._transfer_lock:
            if tid in self._outgoing_transfers:
                with self._outgoing_transfers[tid]["lock"]:
                    if index < len(self._outgoing_transfers[tid]["ack_status"]) and not self._outgoing_transfers[tid]["ack_status"][index]:
                        self._outgoing_transfers[tid]["ack_status"][index] = True

    def _process_chunk_nack(self, src_mac, payload):
        if len(payload) < self.TRANSPORT_HEADER_SIZE:
            return
        tid, index, _, _ = struct.unpack(self.TRANSPORT_HEADER_FORMAT, payload)
        with self._transfer_lock:
            if tid in self._outgoing_transfers:
                print(f"NACK received for chunk {index} of transfer {tid}. Retransmitting.")
                with self._outgoing_transfers[tid]["lock"]:
                    self._send_chunk_internal(tid, index)

    def _reassemble_chunks(self, tid):
        transfer = self._reassembly_buffer.pop(tid, None)
        if transfer is None:
            return
        total_chunks = transfer["total"]
        chunks = transfer["chunks"]
        src_mac = transfer.get("src", None)
        if len(chunks) != total_chunks:
            print(f"Transfer {tid} from {src_mac} incomplete. Dropping.")
            return
        try:
            full_data = b"".join(chunks[i] for i in range(total_chunks))
        except KeyError:
            print(f"Transfer {tid} missing chunks from {src_mac}.")
            return
        print(f"Reassembled message of {len(full_data)} bytes from {src_mac}.")
        if self._handler:
            self._handler(self._MAC, src_mac, full_data)

    def _cleanup_buffer(self):
        current_time = time.time()
        to_delete = []
        for tid, data in list(self._reassembly_buffer.items()):
            ts = data.get("timestamp", 0)
            if current_time - ts > self.TIME_OUT_SECONDS:
                to_delete.append(tid)
        for tid in to_delete:
            transfer = self._reassembly_buffer.pop(tid, None)
            if transfer:
                src = transfer.get("src", "<unknown>")
                print(f"Timed out and removed incomplete transfer {tid} from {src}.")

    def add_machine(self, mac, name='NEW_MACHINE'):
        if mac not in self._discovered_machines:
            self._discovered_machines[mac] = name
            print(f"Discovered new machine: {mac}")
            if self._discovery_handler:
                self._discovery_handler(mac)

    def send_greeting(self):
        self.send_frame("ff:ff:ff:ff:ff:ff", b'', self.FLAG_GREET)



    def send_ack(self, dest_mac: str):
        self.send_frame(dest_mac, b'', self.FLAG_ACK)

    def send_chunk_control_frame(self, dest_mac: str, tid: int, index: int, total: int, flag: int):
        header = struct.pack(self.TRANSPORT_HEADER_FORMAT, tid, index, total, 0)
        self.send_frame(dest_mac, header, flag)

    def send_data(self, dest_mac: str, data: bytes, progress_callback: Callable[[int], None] | None = None, completion_callback: Callable[[], None] | None = None):
        if len(data) <= self.MAX_PAYLOAD_SIZE:
            self.send_frame(dest_mac, data, self.FLAG_SPEAK)
            if completion_callback:
                completion_callback()
            return
        tid = random.randint(0, 0xFFFFFFFF)
        chunks = [data[i:i + self.CHUNK_DATA_SIZE] for i in range(0, len(data), self.CHUNK_DATA_SIZE)]
        total_chunks = len(chunks)
        with self._transfer_lock:
            self._outgoing_transfers[tid] = {"dest_mac": dest_mac, "chunks": chunks, "total_chunks": total_chunks,
                                             "ack_status": [False] * total_chunks,
                                             "last_sent_time": [0.0] * total_chunks,
                                             "lock": threading.Lock(),
                                             "progress_callback": progress_callback,
                                             "completion_callback": completion_callback}
        threading.Thread(target=self._manage_transfer, args=(tid,), daemon=True).start()
        print(f"Data is large ({len(data)} bytes). Starting ARQ transfer {tid} with {total_chunks} chunks.")

    def _manage_transfer(self, tid: int):
        try:
            with self._transfer_lock:
                if tid not in self._outgoing_transfers:
                    return
                transfer = self._outgoing_transfers[tid]
            window_start = 0
            last_progress_pct = -1
            while window_start < transfer["total_chunks"]:
                with transfer["lock"]:
                    window_end = min(window_start + self.SLIDING_WINDOW_SIZE, transfer["total_chunks"])
                    for i in range(window_start, window_end):
                        if not transfer["ack_status"][i] and transfer["last_sent_time"][i] == 0.0:
                            self._send_chunk_internal(tid, i)
                    current_time = time.time()
                    for i in range(window_start, window_end):
                        if not transfer["ack_status"][i] and current_time - transfer["last_sent_time"][i] > self.CHUNK_RETRANSMIT_TIMEOUT:
                            print(f"Timeout for chunk {i} of transfer {tid}. Retransmitting.")
                            self._send_chunk_internal(tid, i)
                    while window_start < transfer["total_chunks"] and transfer["ack_status"][window_start]:
                        window_start += 1
                if transfer["progress_callback"]:
                    acked_count = sum(transfer["ack_status"])
                    progress_pct = int((acked_count / transfer["total_chunks"]) * 100)
                    if progress_pct > last_progress_pct:
                        transfer["progress_callback"](progress_pct)
                        last_progress_pct = progress_pct
                time.sleep(0.01)
            if transfer["progress_callback"] and last_progress_pct < 100:
                transfer["progress_callback"](100)
            print(f"Transfer {tid} completed successfully.")
            if transfer["completion_callback"]:
                transfer["completion_callback"]()
        finally:
            with self._transfer_lock:
                if tid in self._outgoing_transfers:
                    del self._outgoing_transfers[tid]
                    print(f"Cleaned up transfer {tid}.")

    def _send_chunk_internal(self, tid: int, index: int):
        transfer = self._outgoing_transfers[tid]
        chunk_data = transfer["chunks"][index]
        crc = zlib.crc32(chunk_data)
        header = struct.pack(self.TRANSPORT_HEADER_FORMAT, tid, index, transfer["total_chunks"], crc)
        self.send_frame(transfer["dest_mac"], header + chunk_data, self.FLAG_CHUNK)
        transfer["last_sent_time"][index] = time.time()


    def get_interface_mac(self) -> str:
        with open(f"/sys/class/net/{self._interface}/address") as f:
            return f.read().strip()

    @classmethod
    def _first_non_lo(cls) -> str:
        for iface in cls.list_interfaces():
            if iface != "lo":
                return iface
        raise RuntimeError("Only loopback interface found.")
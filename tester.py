from connections import RawEthernetConnector
import time

def frame_handler(dest_mac, src_mac, payload):
    print(f"Received frame from {src_mac} to {dest_mac} with payload: {payload}")

con = RawEthernetConnector(interface="eth0", ethertype=0x1234, frame_handler=frame_handler)
con.start()

con.send_frame("ff:ff:ff:ff:ff:ff", b"Hola capa 2!")

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    con.stop()
# Machine-Linker

Machine-Linker: A Reliable Data Link Layer Framework

Machine-Linker is a low-level Python framework that implements a complete data link layer protocol over raw Ethernet frames.
It provides reliable message delivery, flow control, error detection and recovery, and fragmentation/reassembly for large data transfers — all handled transparently between nodes.

The system can be used for educational, experimental, or embedded networking projects where users need full control over communication below the network layer (L3).

🚀 Features

🔹 Raw Ethernet Communication — Works directly over AF_PACKET sockets for total control at Layer 2.

🔹 Automatic Discovery — Machines announce their presence and acknowledge others.

🔹 Reliable Transmission (ARQ) — Uses acknowledgments, retransmissions, and a sliding window protocol for efficiency.

🔹 Fragmentation & Reassembly — Large messages or files are split into fixed-size chunks and reassembled reliably.

🔹 Error Detection & Recovery — Each chunk includes CRC32 verification and automatic retransmission upon mismatch.

🔹 Flow Control — Adjustable sliding window size to control how many frames are in flight simultaneously.

🔹 Timeout Management — Detects lost transfers and cleans up stale sessions automatically.

🔹 Extensible Handlers — Plug in custom frame and discovery handlers to integrate with higher layers or UIs.


In order to work with docker:

sudo docker compose build --- Build images.

sudo docker compose up -d    --- Raise containers.

sudo docker exec -it <image-name> /bin/bash     --- Enters to container: Images are pc1,    pc2 and pc3.

                                                    Example:
                                                                sudo docker exec -it pc1 /bin/bash  

                                                            Then you will be coding at the container`s linux terminal.

python3 run.py      (Inside each one of these linux terminal)

If got a tkinter error, run on host:sudo compos
    xhost +local:root

# That's it, you have up to three virtual machines to test the app!
    
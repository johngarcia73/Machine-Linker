# Networks-Project-1

In order to work:

sudo docker compose build --- Build images.

sudo docker compose up -d    --- Raise containers.

sudo docker exec -it <image-name> /bin/bash     --- Enters to container: Images are pc1,    pc2 and pc3.

                                                    Example:
                                                                sudo docker exec -it pc1 /bin/bash  

                                                            Then you will be coding at the container`s linux terminal.

python3 run.py

If got a tkinter error, run:
    xhost +local:root

    
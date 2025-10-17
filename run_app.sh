#!/bin/bash
set -e

# Configuration
NETWORK_NAME="redlocal"
SUBNET="172.30.0.0/16"    # Adjust if overlaps with existing networks
IMAGE_NAME="p2p_messenger_image"

# Allow GUI (Tkinter/X11) access
xhost +local:docker >/dev/null 2>&1 || echo "⚠️  Could not execute xhost (install xorg-xhost if needed)."

# Create network if it doesn't exist
if ! docker network inspect $NETWORK_NAME >/dev/null 2>&1; then
  echo "Creating network $NETWORK_NAME..."
  if ! docker network create --driver bridge --subnet=$SUBNET $NETWORK_NAME; then
    echo "Error: subnet $SUBNET overlaps with an existing one."
    echo "Active networks:"
    docker network ls
    echo "Tip: change SUBNET to 172.31.0.0/16 or similar."
    exit 1
  fi
else
  echo "✅ Network $NETWORK_NAME already exists."
fi

# Build Docker image
echo "Building Docker image..."
docker build -t $IMAGE_NAME .

# Create containers
for i in 1 2 3; do
  CONTAINER="pc$i"
  if docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER}$"; then
    echo "🧹 Removing old container $CONTAINER..."
    docker rm -f $CONTAINER >/dev/null 2>&1 || true
  fi

  echo "🚀 Creating container $CONTAINER..."
  docker run -d --name $CONTAINER \
    -e DISPLAY=$DISPLAY \
    -v /tmp/.X11-unix:/tmp/.X11-unix \
    --network $NETWORK_NAME \
    $IMAGE_NAME tail -f /dev/null
done

# Detect available terminal emulator
open_terminal_cmd=""
if command -v gnome-terminal >/dev/null 2>&1; then
  open_terminal_cmd="gnome-terminal -- bash -c"
elif command -v konsole >/dev/null 2>&1; then
  open_terminal_cmd="konsole --new-tab -e bash -c"
elif command -v xfce4-terminal >/dev/null 2>&1; then
  open_terminal_cmd="xfce4-terminal -e"
else
  echo "⚠️  No compatible terminal found (gnome-terminal, konsole, or xfce4-terminal)."
  echo "Run manually: docker exec -it pc1 python3 run.py"
  exit 0
fi

# Open terminals and run the application in each container
echo "🖥️  Launching application in three containers..."
for i in 1 2 3; do
  CONTAINER="pc$i"
  eval "$open_terminal_cmd \"docker exec -it $CONTAINER python3 run.py; exec bash\" &"
done

echo "✅ All containers are running."
echo "💡 If Tkinter shows a DISPLAY error, make sure 'xhost +local:docker' executed correctly."

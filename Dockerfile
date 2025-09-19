FROM debian:stable-slim

ENV DEBIAN_FRONTEND=noninteractive

WORKDIR /app
COPY . /app

# Instala los paquetes que necesitas
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        iproute2 \
        iputils-ping \
        python3 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Comando para que el contenedor permanezca vivo
CMD ["tail", "-f", "/dev/null"]

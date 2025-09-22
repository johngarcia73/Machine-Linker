FROM debian:stable-slim

ENV DEBIAN_FRONTEND=noninteractive

WORKDIR /app
COPY . /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        iproute2 \
        iputils-ping \
        python3 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

CMD ["tail", "-f", "/dev/null"]
#CMD ["python3", "tester.py"]

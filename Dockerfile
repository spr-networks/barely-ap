FROM ubuntu

RUN apt-get update && apt-get install -y python3 \
  tmux \
  tcpdump \
  iw \
  nano \
  netcat \
  socat \
  hostapd \
  wpasupplicant \
  pip \
  inetutils-ping \
  iproute2 \
  net-tools

RUN pip3 install scapy

COPY src/pyaes /pyaes/
COPY src/ap.py /

COPY src/run-ap.sh /
COPY src/run-cli.sh /
COPY config/client.conf /

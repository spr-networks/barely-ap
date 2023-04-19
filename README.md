# Barely AP

This is barely an implementation of a WiFi 802.11 Access Point, using Scapy

## What

On Linux, this code lets you spin up a python access point with AES CCMP encryption.

This code just barely gets the job done -- it should NOT be used as a reference
for writing production code. It has NO protocol security, as it is not security
robust despite performing authenticated CCMP encryption.

## How
The project uses mac80211_hwsim. The code is largely self contained to be only python
outside if scapy.

The cryptographic primitives for CCMP are written from scratch rather than using
Cryptodome's AES CCM implementation to show off all of the individual building blocks directly.

## Usage:

Build the container with ./build.sh and then run it with ./setup.sh

```bash
./build.sh
./setup.sh
```

Inspect IP network traffic
```bash
docker exec -it barely-ap tcpdump -i scapyap
```

```bash
docker exec -it barely-sta tcpdump -i wlan1
```


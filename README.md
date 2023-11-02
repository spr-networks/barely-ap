# Barely AP

This is barely an implementation of a WiFi 802.11 Access Point, using Scapy. 

It can run virtuall with mac80211_hwsim or on interfaces in monitor mode. 

It has also been used with socat to relay wifi frames over tcp sockets.

## What

On Linux, this code lets you spin up a python access point. It supports stations connecting with WPA2 & CCMP encryption.

This code just barely gets the job done -- it should NOT be used as a reference
for writing production code. It has NO protocol security, as it is not security
robust despite performing authenticated CCMP encryption.

## How
The code is largely self contained python code (other than scapy). As a demo it's set up to run with mac80211_hwsim.

The cryptographic primitives for CCMP to demonstrate the individual building blocks directly.

## Usage:

Build the container with ./build.sh and then run it with ./setup.sh

```bash
./build.sh
./setup.sh
```

Inspect IP traffic
```bash
docker exec -it barely-ap tcpdump -i scapyap
```

```bash
docker exec -it barely-sta tcpdump -i wlan1
```

![barely](https://user-images.githubusercontent.com/37549748/233030013-214c7324-cf6e-4e91-87ba-a9e0366cafce.png)

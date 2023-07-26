#!/bin/sh
IFACE=wlan1

ip addr add dev wlan1 10.10.10.2/24
stdbuf --output=L wpa_supplicant -B -Dnl80211 -i${IFACE} -c /client.conf | tee cli-supplicant.txt
stdbuf --output=L ping 10.10.10.1 | tee cli-log.txt

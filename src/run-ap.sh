#!/bin/bash
iw dev wlan0 interface add mon0 type monitor
ip link set dev wlan0 up
ip link set dev mon0 up
stdbuf --output=L python3 /ap.py | tee ap-log.txt

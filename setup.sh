#!/bin/sh

move_iface_pid() {
  PID=$(docker inspect --format='{{.State.Pid}}' $2)
  PHY=phy$(iw $1 info | grep wiphy | awk '{print $2}')
  #echo move $1 is $PHY to $2 is $PID
  iw phy $PHY set netns $PID
}

set_iface_radio_group() {
  PHY=phy$(iw $1 info | grep wiphy | awk '{print $2}')
  echo $2 > /sys/kernel/debug/ieee80211/$PHY/hwsim/group
}


#kill if already running
docker kill barely-ap barely-sta 2>/dev/null

# start containers
docker run -d --privileged --rm --name barely-ap -it barely-ap sleep inf
docker run -d --privileged --rm --name barely-sta -it barely-ap sleep inf

#send in some radios
modprobe -r mac80211_hwsim
modprobe mac80211_hwsim radios=2

nmcli dev set wlan0 managed no
nmcli dev set wlan1 managed no

move_iface_pid wlan0 "barely-ap"
move_iface_pid wlan1 "barely-sta"

ip link set dev hwsim0 up

# start the AP
docker exec -d barely-ap /run-ap.sh

# start the client
docker exec -d barely-sta /run-cli.sh

tcpdump -i hwsim0 -n -e "not ( wlan type mgt subtype beacon or wlan type ctl subtype ack )"

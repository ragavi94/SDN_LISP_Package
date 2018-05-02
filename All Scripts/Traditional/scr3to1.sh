ip link set dev ens6 down
ip addr del 192.168.3.1/24 dev ens6
ip addr add 192.168.1.1/24 dev ens6
ip link set dev ens6 up
ip route add 192.168.0.0/16 via 192.168.1.2

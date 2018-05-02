ip link set dev ens6 down 
ip addr del 192.168.3.2/24 dev ens6
ip addr add 192.168.1.2/24 dev ens6
ip link set dev ens6 up

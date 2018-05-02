sysctl net.ipv4.ip_forward=1

apt-get -y install openvswitch-switch

sudo ovs-vsctl add-br br1
sudo ovs-vsctl add-br br2

ovs-vsctl set bridge br1 protocols=OpenFlow13
ovs-vsctl set bridge br2 protocols=OpenFlow13

ip addr del <IP1/24> dev <interface1>
ip addr del <IP2/24> dev <interface2>
ip link set dev <interface1> down
ip link set dev <interface2> down

ip addr add <IP1/24> dev br1
ip addr add <IP2/24> dev br2

sudo ovs-vsctl add-port br1 <interface1>
sudo ovs-vsctl add-port br2 <interface2>

ip link set dev br1 up
ip link set dev br2 up
ip link set ovs-system up

ip link set dev <interface1> up
ip link set dev <interface2> up


sudo ovs-vsctl set-controller br1 tcp:177.10.x.2:6653
sudo ovs-vsctl set-controller br2 tcp:177.10.x.2:6653
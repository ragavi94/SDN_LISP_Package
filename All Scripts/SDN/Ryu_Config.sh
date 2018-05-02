#########RYU####################
sysctl net.ipv4.ip_forward=1
apt -y install python3-pip
apt -y install gcc libffi-dev libssl-dev libxml2-dev libxslt1-dev zlib1g-dev
pip3 install ryu

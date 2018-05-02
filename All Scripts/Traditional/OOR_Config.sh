sudo apt-get -y install build-essential git-core libconfuse-dev gengetopt libcap2-bin libzmq3-dev libxml2-dev
mkdir git
cd git
git clone https://github.com/OpenOverlayRouter/oor.git
cd oor
sudo make install
cd oor
sudo cp oor.conf.example /etc/oor.conf
#echo 'task goes here' | cat - todo.txt > temp && mv temp todo.txt

sudo sysctl net.ipv4.conf.default.rp_filter=0
sudo sysctl net.ipv4.conf.all.rp_filter=0
sudo sysctl net.ipv4.ip_forward=1
sudo sysctl net.ipv6.conf.all.forwarding=1

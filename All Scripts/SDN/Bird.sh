sudo sysctl net.ipv4.ip_forward=1
wget ftp://bird.network.cz/pub/bird/bird-2.0.2.tar.gz
#OR use this
#ftp://bird.network.cz/pub/bird/bird-1.6.4.tar.gz
tar -xvzf bird-2.0.2.tar.gz
cd bird-2.0.2
sudo apt-get -y install m4 binutils flex bison libncurses-dev libreadline-gplv2-dev make
./configure
make
sudo make install 
#vi /usr/local/etc/bird.conf

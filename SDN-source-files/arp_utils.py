import os
import sys
from ryu.ofproto import ether
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet,ether_types
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.lib.packet import icmp
from ryu.lib.packet import arp
from ryu.lib.packet import vlan
from ryu.lib import mac
import array

map_resolver = [
    
            # Structured as:
            # (Detected Source, src_port, Modify Dst IP, dst_port, Modify Src IP)
            

            # SWITCH1
            # Change to Core Network, to ETR dest
            ('192.168.1.0/24', 1, '172.10.2.2', 2, '172.10.1.1'),
            ('192.168.1.2', 1, '172.10.2.2', 2, '172.10.1.1'),
            
            # Revert Back
            ('172.10.2.0/24', 1, '192.168.1.2', 2, '192.168.2.2'),
            ('172.10.2.2', 1, '192.168.1.2', 2, '192.168.2.2'),
            
            # SWITCH2
            # Change to Core Network, to ITR dest
            ('192.168.2.0/24', 1, '172.10.1.1', 2, '172.10.2.2'),
            ('192.168.2.1', 1, '172.10.1.1', 2, '172.10.2.2'),
            
            # Revert Back
            ('172.10.1.0/24', 1, '192.168.2.2', 2, '192.168.1.2'),
            ('172.10.1.1', 1, '192.168.2.2', 2, '192.168.1.2')
            
             ]


arp_resolver = [
    
            # Structured as:
            # (Detected Source, src_port, Modify Dst IP, dst_port, Modify Src IP)
            # REMEMBER LAST OCTECT, is changed

            # SWITCH1
            # Change to Core Network, to ETR dest
            ('192.168.1.2','172.10.1.1'),  # REMEMBER LAST OCTECT, is changed, should be '172.10.1.2'
            
            # Revert Back
            
            ('172.10.1.2','192.168.1.1'), # REMEMBER LAST OCTECT, is changed, should be '192.168.1.1'
            
            # SWITCH2
            
            ('192.168.2.2','172.10.2.2'),  # REMEMBER LAST OCTECT, is changed
                
            
            ('172.10.2.1','192.168.2.1')  # REMEMBER LAST OCTECT, is changed
            
             ]


############################# SOME USEFUL FUNCTIONS #######################################


def get_ip_network(ip):
    if "/" not in ip:
        return IPAddress(ip)
    return IPNetwork(ip)

def cmp_networks(net1, net2): # CHeck this one though
    try:
        return net1 == net2 or net1 in net2 
    except:
        return False
    
    
def packetIsARP(message) :
    pkt = packet.Packet(message.data)

    a = pkt.get_protocol(arp.arp)
    if a is not None :
        return True
    return False

def packetIsRequestARP(message) :
    pkt = packet.Packet(message.data)

    a = pkt.get_protocol(arp.arp)
    if a.opcode == arp.ARP_REQUEST :
        return True
    return False

def packetIsReplyARP(message) :
    pkt = packet.Packet(message.data)

    a = pkt.get_protocol(arp.arp)
    if a.opcode == arp.ARP_REPLY :
        return True
    return False


def packetDstIp(message, ipaddr) :
    if packetIsIP(message):
        pkt = packet.Packet(message.data)
        ip = pkt.get_protocol(ipv4.ipv4)
        if not cmp_networks(ip.dst, ipaddr):
            return True
    return False

def packetSrcIp(message, ipaddr) :
    if packetIsIP(message):
        pkt = packet.Packet(message.data)
        ip = pkt.get_protocol(ipv4.ipv4)
        if not cmp_networks(ip.src, ipaddr):
            return True
    return False


def packetArpDstIp(message, ipaddr) :
    if packetIsARP(message):
        pkt = packet.Packet(message.data)
        a = pkt.get_protocol(arp.arp)
        if not cmp_networks(a.dst_ip, ipaddr):
                return True
    return False

def packetArpSrcIp(message, ipaddr) :
    if packetIsARP(message):
        pkt = packet.Packet(message.data)
        a = pkt.get_protocol(arp.arp)
        if not cmp_networks(a.src_ip, ipaddr):
                return True
    return False



def sendFlowMod(msg, match, actions, hard_timeout, idle_timeout, buffer_id=None):
    datapath = msg.datapath
    ofproto = datapath.ofproto
    parser = datapath.ofproto_parser

    mod = parser.OFPFlowMod(
        datapath=datapath, match=match, cookie=0,
        command=ofproto.OFPFC_ADD, idle_timeout=idle_timeout, hard_timeout=hard_timeout,
        priority=ofproto.OFP_DEFAULT_PRIORITY,
        flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions, buffer_id=buffer_id)
    datapath.send_msg(mod)

############################# SOME USEFUL FUNCTIONS #######################################


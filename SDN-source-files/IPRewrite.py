from apps import App
import configparser as ConfigParser
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import arp
from ryu.lib.packet import icmp
from ryu.lib.packet import ipv4
from netaddr import IPNetwork, IPAddress
import os
from arp_utils import *


SCRIPT_PATH = os.path.dirname(os.path.abspath(__file__))

FLOW_HARD_TIMEOUT = 30
FLOW_IDLE_TIMEOUT = 10





# App starts here
class IP_Rewrite(App):

    def __init__(self, *args, **kwargs):
        super(IP_Rewrite, self).__init__(*args, **kwargs)
        
    
        
        self.port = range(0,5) #<-- We aren't going to have more than 4 ports.
        self.pkt_ct = {}
        # Yet to properly implement




    def multidatapathswitch_register(self, dp, enter_leave=True):
        
        dpid = dp.dp.id
        
        print("\n#####################\n"+str(dpid)+"\n#####################\n")
        for port in dp.ports:
            self.logger.info("\t"+str(port.hw_addr)+ "\t"+str(port.name)+"\t"+ str(port.port_no)+ "\t")
    
    def add_flow(self, datapath,  match, actions, priority=0, idle_timeout=64,
                 buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath,
                                    idle_timeout=idle_timeout,
                                    buffer_id=buffer_id,
                                    priority=priority,
                                    flags=ofproto.OFPFF_SEND_FLOW_REM,
                                    match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath,
                                    idle_timeout=idle_timeout,
                                    priority=priority,
                                    flags=ofproto.OFPFF_SEND_FLOW_REM,
                                    match=match,
                                    instructions=inst)
        datapath.send_msg(mod)    
    
    def event_switch_enter_handler(self, ev):

        dp = ev.dp
        ofproto = dp.ofproto
        parser = dp.ofproto_parser
        self.logger.info("Switch connected %s", dp.id)
 
        # do IP Re-write for following types of packet
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        
        # THIS WORKS!! but sometimes fucks up LLDP
        match = parser.OFPMatch(eth_type= 0x0800) # ICMP/ipv4
        
        # I think this flow just forces this packet to come to controller.
        self.add_flow(dp, match, actions)
    
    def ip_rewrite_func(self,pkt_ipv4): # rewrite source and destination
        print("In ip rewrite function")
        print(pkt_ipv4.src,",",pkt_ipv4.dst)
        
        new_pkt_ipv4 = pkt_ipv4     # Default value
        
        ## MATCH THE SOURCE, THEN SEND TO THE FINAL DESTINATION
        for src,ps,n_dst,pd,n_src in map_resolver:
            
            if pkt_ipv4.src == src:
                print("SOURCES MATCH the list\nPRINTING ORG PACKET DESTINATION: "+str(pkt_ipv4.dst)+", GOING TO MODIFY TO: "+str(n_dst))
                
                print("Original ICMP Echo Request src:"+str(pkt_ipv4.src)+" ----> dest:"+str(pkt_ipv4.dst))
                new_pkt_ipv4.dst = n_dst
                new_pkt_ipv4.src = n_src
                print("ICMP Echo Request changed from src:"+str(new_pkt_ipv4.src)+" ----> dest:"+str(new_pkt_ipv4.dst))
                break # STOP LOOPING
                
        
        return new_pkt_ipv4
    
    
    def packet_in_handler(self, ev):
        
        ######## EXTRACT INFO ###############################
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt = packet.Packet(data=msg.data)
        pkt_ethernet = pkt.get_protocols(ethernet.ethernet)[0]
        pkt_arp = pkt.get_protocol(arp.arp)
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        pkt_icmp = pkt.get_protocol(icmp.icmp)
        ######## EXTRACT INFO ################################
        
        if pkt_ethernet.ethertype == ether_types.ETH_TYPE_LLDP:
            self.logger.info('  _packet_in_handler: LLDP packet in, Ignoring...')
            # ignore lldp packet
            return
        
        if pkt_arp:
            print("WARNING, ARP PACKET DETECTED IN IPRewrite. This shouldn't happen")
            exit()

            
        if pkt_icmp:
            print("\nCorrect Functioning for Packet IN \\m/ \n")
            return self._handle_icmp(datapath, msg, msg.match['in_port'], pkt_ethernet, pkt_ipv4, pkt_icmp)

        if pkt_ipv4:
            print("This application does not support packets more complicated than ICMP\n Exiting...")
            exit()


    def _handle_icmp(self, datapath, msg, in_port, pkt_ethernet, pkt_ipv4, pkt_icmp):
        dpid = datapath.id
        self.pkt_ct.setdefault(dpid, 0)
        
        print("Packet CT is "+str(self.pkt_ct[dpid])+" For DPID: "+str(dpid))
        
        if(in_port>10):
            print("BYe bye LLDP packet")
            return
        
        data = None
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        # USE FOR FLOWS, MATCH ORIGINAL DST
        match = parser.OFPMatch(in_port=in_port, ipv4_dst=pkt_ipv4.dst)
        temp = pkt_ipv4
        ################# DEBUG STATEMENTS##########################################################
        if (pkt_icmp.type == icmp.ICMP_ECHO_REQUEST):
            print("ICMP Echo Request received at "+str(datapath.id)+" with in-port: "+str(in_port) +", "+str(pkt_ipv4.src)+" -----> "+str(pkt_ipv4.dst))
            print("mac source and destination", pkt_ethernet.src," ----> ",pkt_ethernet.dst)

        elif(pkt_icmp.type == icmp.ICMP_ECHO_REPLY):
            print("ICMP Echo Reply received at "+str(datapath.id)+" with in-port: "+str(in_port)+", "+str(pkt_ipv4.src)+" -----> "+str(pkt_ipv4.dst))
            
        else:
            print("Packet with Unkown Type found, \nExiting...")
            exit()
        ################# DEBUG STATEMENTS##########################################################
        

         
        
        no_greater = 0
        for key,value in self.pkt_ct.items():
            print (key, value)
            if(dpid == key):
                pass
            elif(self.pkt_ct[dpid] < value):
                print("Incremented no_greater")
                no_greater+=1
        actions = None
        if (in_port == 1 and no_greater == 0 ):
            print("\nSending packet out through port ---> 2\n")
           
            actions = [parser.OFPActionOutput(2)]
            
        elif (in_port == 2 and no_greater == 1):
            self.ip_rewrite_func(pkt_ipv4)
            print("ICMP from  "+str(datapath.id)+" with in-port: "+str(in_port)+" DST Changed from "+str(temp.dst)+" ----> "+str(pkt_ipv4.dst))
            print("\nSending packet out through port ---> 1\n")
            actions = [parser.OFPActionSetField(eth_dst=pkt_ethernet.dst),parser.OFPActionSetField(ipv4_dst=pkt_ipv4.dst),parser.OFPActionSetField(ipv4_src=pkt_ipv4.src),parser.OFPActionOutput(1)]
        
        elif(in_port == 1 and no_greater == 2 ):
            self.ip_rewrite_func(pkt_ipv4)
            print("ICMP from  "+str(datapath.id)+" with in-port: "+str(in_port)+" DST Changed from "+str(temp.dst)+" ----> "+str(pkt_ipv4.dst))
            print("\nSending packet out through port ---> 2\n")
            actions = [parser.OFPActionSetField(eth_dst=pkt_ethernet.dst),parser.OFPActionSetField(ipv4_dst=pkt_ipv4.dst),parser.OFPActionSetField(ipv4_src=pkt_ipv4.src),parser.OFPActionOutput(2)]
            
        elif (in_port == 2 and no_greater == 3 ):
            print("\nSending packet out through port ---> 1\n")
            actions = [parser.OFPActionOutput(1)]
        
        else:
            print(" \n##################\nWARNING bridge port use detected : " + str(in_port) +"\n###############\n no_greater is:" + str(no_greater))
       
        
        
        
        
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
        
        # THIS LINE IS VERY IMPORTANT 
        self.pkt_ct[dpid]+=1 # Increment packet-in counter for 
        
        return True
   
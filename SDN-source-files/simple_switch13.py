from apps import App
from ryu.lib.packet import packet,icmp,ethernet,ipv4,arp,ether_types
import array
from ryu.lib.mac import haddr_to_bin
from arp_utils import *
FLOW_HARD_TIMEOUT = 30
FLOW_IDLE_TIMEOUT = 10

class SimpleSwitch13(App):
    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.ip_map = {}    # not using temporarily
        self.dpid_to_control_port = {}  # not using temporarily
        ## For double bridge logic
        self.pkt_ct = {}
    
    # Doesn't really do much
    def multidatapathswitch_register(self, dp, enter_leave=True):
        dpid = dp.dp.id
        self.dpid_to_control_port.setdefault(dpid, [])
        for port in dp.ports:
            if str.encode("gre") in port.name:
                self.dpid_to_control_port[dpid].append(port.port_no)
        #IP_Rewrite.multidatapathswitch_register(dp, enter_leave=enter_leave)
            
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)


    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    def ip_rewrite_func(self,pkt_arp):
        print("In arp rewrite function")
        new_pkt_arp = pkt_arp
        src_ip = pkt_arp.src_ip
        
        #changed due to double bridge logic
        #next_hop_ip = None
        for src,n_src in arp_resolver:
            if pkt_arp.src_ip == src:
                new_pkt_arp.src_ip = n_src
                if n_src.split(".")[3] == '1':
                    new_pkt_arp.dst_ip = n_src.split(".")[0]+"."+n_src.split(".")[1]+"."+n_src.split(".")[2]+".2"
                    print("New ARP next hop is: "+str(new_pkt_arp.dst_ip))
                    break
                elif n_src.split(".")[3] == '2':
                    new_pkt_arp.dst_ip = n_src.split(".")[0]+"."+n_src.split(".")[1]+"."+n_src.split(".")[2]+".1"
                    print("New ARP next hop is: "+str(new_pkt_arp.dst_ip))
                    break
                else:
                    print("DEST IP not found. Shouldnt happen")
                
        return new_pkt_arp
       
    def _handle_PacketInARP(self, ev):
        msg = ev.msg
        if(packetIsRequestARP(msg)):
            print("THis is an ARP request")
        elif(packetIsReplyARP(msg)):
            print("THis is an ARP reply")
        else:
            print("WARNING, stray packet detected. This shoudln't happen")
        datapath = msg.datapath
        ## Added for double bridge logic
        in_port=msg.match['in_port']
        dpid = datapath.id
        self.pkt_ct.setdefault(dpid, 0)
        ##
        ofproto = datapath.ofproto	
        arppkt = None
        pkt = packet.Packet(data=msg.data)
        pkt_arp = pkt.get_protocol(arp.arp)
        
   
        data = None
        parser = datapath.ofproto_parser
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        
                
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
            #commented for double bridge logic
            self.ip_rewrite_func(pkt_arp)
            print("ARP from  "+str(datapath.id)+" with in-port: "+str(in_port)+" DST Changed to ----> "+str(pkt_arp.dst_ip))
            print("\nSending packet out through port ---> 1\n")
            
            
           
            actions = [parser.OFPActionSetField(arp_spa=pkt_arp.src_ip),parser.OFPActionSetField(arp_tpa=pkt_arp.dst_ip),parser.OFPActionOutput(1)]
        
        elif(in_port == 1 and no_greater == 2 ):
            self.ip_rewrite_func(pkt_arp)
            print("ARP from  "+str(datapath.id)+" with in-port: "+str(in_port)+" DST Changed to ----> "+str(pkt_arp.dst_ip))
            print("\nSending packet out through port ---> 2\n")
          
            actions = [parser.OFPActionSetField(arp_spa=pkt_arp.src_ip),parser.OFPActionSetField(arp_tpa=pkt_arp.dst_ip),parser.OFPActionOutput(2)]
            
        elif (in_port == 2 and no_greater == 3 ):
            print("\nSending packet out through port ---> 1\n")
            
            actions = [parser.OFPActionOutput(1)]
        
        else:
            print(" \n##################\nWARNING bridge port use detected : " + str(in_port) +"\n###############\n no_greater is:" + str(no_greater))
       
       
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
        
        self.pkt_ct[dpid]+=1 # Increment packet-in counter for 
        
        return

   
    
    def forward_packet(self, msg, out_port) :

        datapath = msg.datapath
        ofproto = datapath.ofproto

        actions = [parser.OFPActionOutput(out_port)]
        
        print("\nACTIONS...:")
        print(actions)
        print(":...ACTIONS\n")
        # install a flow to avoid packet_in next time
        if ofproto.OFPP_FLOOD !=out_port:
            match = getFullMatch( msg )
            sendFlowMod(msg, match, actions, FLOW_HARD_TIMEOUT, FLOW_IDLE_TIMEOUT, msg.buffer_id)
        else :

            sendPacketOut(msg=msg, actions=actions, buffer_id=msg.buffer_id)
    

    
    def packet_in_handler(self, ev):
        print ("Switch Packet in")
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        
        ## Set up to receive the ethernet src / dst addresses
        pak = packet.Packet(array.array('B', msg.data)) # some weird python way of getting data
        eth_pkt = pak.get_protocol(ethernet.ethernet)
        arp_pkt = pak.get_protocol(arp.arp)
        ip4_pkt = pak.get_protocol(ipv4.ipv4)
        icmp_pkt = pak.get_protocol(icmp.icmp)
        
        
        #################MAC Learning#######################
                # THIS IS JUST A LIST ENTRY with dpid as the key, and {} as a value. THAT'S ALL IT IS.
        self.mac_to_port.setdefault(dpid, {})

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][eth_pkt.src] = in_port
        ##################MAC Learning#######################
         
         
        # First ARP handled here
        if arp_pkt:
            pkt = arp_pkt
            print("\nHandling ARP")
            self._handle_PacketInARP(ev)
            print("ARP was handled\n")
            return True
        
            
        elif ip4_pkt:
            if icmp_pkt:
                #pass
                #IP_Rewrite.packet_in_handler(ev)
                return  # GO to IP_Rewrite
            pkt = ip4_pkt
            ip_src = pkt.src
            ip_dst = pkt.dst
            
        elif icmp_pkt:
            #pass
            #IP_Rewrite.packet_in_handler(ev)
            return  # GO to IP_Rewrite
        
        else:
            pkt = eth_pkt

        if eth_pkt.ethertype == ether_types.ETH_TYPE_LLDP:
            self.logger.info('  _packet_in_handler: LLDP packet in, Ignoring...')
            # ignore lldp packet
            return True
        
        self.logger.info('\n##########################################################\n  ------')
        self.logger.info('  _packet_in_handler: src_mac -> %s' % dpid)
        self.logger.info('  _packet_in_handler: src_mac -> %s' % eth_pkt.src)
        self.logger.info('  _packet_in_handler: dst_mac -> %s' % eth_pkt.dst)
        self.logger.info('  _packet_in_handler: %s' % pkt)
        self.logger.info('\n##########################################################\n  ------')

        src = eth_pkt.src  # Set up the src and dst variables so you can use them
        dst = eth_pkt.dst        
    
        
        try:
            self.logger.info("L3 info: packet in %s ---> %s \n",  ip_src, ip_dst)
        except:
            self.logger.info("Packet is not L3\n")

        if dst in self.mac_to_port[dpid]:   # Is destination present for current datapath??
            out_port = self.mac_to_port[dpid][dst]
        else:   # NO? then just FLood
            out_port = ofproto.OFPP_FLOOD


        self.logger.info("Switch: packet in %s %s %s %s To controller using: %s", dpid, src, dst, in_port, out_port)

        # COMMENTED THIS OUT.. because of double bridge logic
        #forward_packet(msg,out_port)


        '''data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)'''
        
        #print("GOING TO IPRe-WRITE") # remove true to make it go to ip-rewrie
        return True
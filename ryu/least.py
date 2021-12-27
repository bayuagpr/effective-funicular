# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import logging
import json
import random

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import inet
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib.packet import arp
from ryu.lib.packet import in_proto
from ryu.lib import mac as mac_lib
from ryu.lib import ip as ip_lib
from ryu.lib import dpid as dpid_lib
from ryu.ofproto import ether, inet
from ryu.ofproto import ofproto_v1_0, ofproto_v1_3

UINT32_MAX = 0xffffffff


class SimpleSwitch13Lb(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13Lb, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.server_index = 0
        self.servers = []
        self.rewrite_ip_header = True
        
        self.total_connection = {} # IP -> total connection

        self.virtual_ip = None
        self.virtual_ip = "192.168.30.100"
        self.virtual_mac = "08:00:27:4b:fe:05"  # Pick something dummy and

        self.servers.append({'ip': "192.168.30.2", 'mac': "08:00:27:ae:ff:01"})
        self.servers.append({'ip': "192.168.30.3", 'mac': "08:00:27:50:84:af"})
        self.servers.append({'ip': "192.168.30.4", 'mac': "08:00:27:8f:e3:ce"})

        for server in self.servers:
            self.total_connection[server['ip']] = 0

        # server = {}
        # server[0] = {'ip':IPAddr("10.0.0.2"), 'mac':EthAddr("00:00:00:00:00:02"), 'outport': 2}
        # server[1] = {'ip':IPAddr("10.0.0.3"), 'mac':EthAddr("00:00:00:00:00:03"), 'outport': 3}
        # server[2] = {'ip':IPAddr("10.0.0.4"), 'mac':EthAddr("00:00:00:00:00:04"), 'outport': 4}
        # total_servers = len(server)

    def get_attachment_port(self, dpid, mac):
        print("dpid", dpid)
        print("mac", mac)
        print("self.mac_to_port", self.mac_to_port)
        if dpid in self.mac_to_port:
            table = self.mac_to_port[dpid]
            if mac in table:
                return table[mac]
        return None

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
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

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = format(datapath.id, "d").zfill(16)
        self.mac_to_port.setdefault(dpid, {})

        # self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # Only handle IPv4 traffic going forward
        if eth.ethertype == ether_types.ETH_TYPE_IP:
            # iphdr = pkt.get_protocols(ipv4.ipv4)[0]
            iphdr = pkt.get_protocols(ipv4.ipv4)[0]
            # Only handle traffic destined to virtual IP
            if iphdr.dst == self.virtual_ip:
                # Only handle TCP traffic
                if iphdr.proto == in_proto.IPPROTO_TCP:
                    tcphdr = pkt.get_protocols(tcp.tcp)[0]
                    print("Load Balancing Start")
                    self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

                    valid_servers = []
                    for server in self.servers:
                        outport = self.get_attachment_port(dpid, self.virtual_mac)
                        if outport != None:
                            server['outport'] = outport
                            valid_servers.append(server)
                    print("valid_servers", valid_servers)

                    total_servers = len(valid_servers)

                    # If we there are no servers with location known, then skip
                    if total_servers == 0:
                        return
                    

                    """
                    Select server with least connections
                    """
                    if len(self.total_connection) == 0:
                        selected_server_ip = valid_servers[0]['ip']
                        selected_server_mac = valid_servers[0]['mac']
                        selected_server_outport = valid_servers[0]['outport']
                    else:
                        ipserver = valid_servers[0]['ip']
                        totalconns = self.total_connection[ipserver]

                        for x in self.total_connection:
                            if self.total_connection[x] < totalconns:
                                ipserver = x
                                totalconns = self.total_connection[x]
                        self.logger.info("Best available server: %s" % ipserver)    


                        # find server element by selected ip
                        index_server = next((index for (index, d) in enumerate(valid_servers) if d["ip"] == ipserver), None)
                        self.logger.info("index_server: %s" % index_server)
                        selected_server_ip = valid_servers[index_server]['ip']
                        selected_server_mac = valid_servers[index_server]['mac']
                        selected_server_outport = valid_servers[index_server]['outport']
                        
                    print
                    "Selected server", selected_server_ip
                    self.logger.info("Selected server: %s" % selected_server_ip)
                    # Increase total connection for selected server
                    self.total_connection[selected_server_ip] += 1

                    ########### Setup route to server
                    match = parser.OFPMatch(in_port=in_port,
                                            eth_type=eth.ethertype, eth_src=eth.src, eth_dst=eth.dst,
                                            ip_proto=iphdr.proto, ipv4_src=iphdr.src, ipv4_dst=iphdr.dst,
                                            tcp_src=tcphdr.src_port, tcp_dst=tcphdr.dst_port)

                    if self.rewrite_ip_header:
                        actions = [parser.OFPActionSetField(eth_dst=selected_server_mac),
                                   parser.OFPActionSetField(ipv4_dst=selected_server_ip),
                                   parser.OFPActionOutput(selected_server_outport)]
                    else:
                        actions = [parser.OFPActionSetField(eth_dst=selected_server_mac),
                                   parser.OFPActionOutput(selected_server_outport)]

                    inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

                    cookie = random.randint(0, 0xffffffffffffffff)

                    mod = parser.OFPFlowMod(datapath=datapath, match=match, idle_timeout=10,
                                            instructions=inst, buffer_id=msg.buffer_id, cookie=cookie)
                    datapath.send_msg(mod)

                    ########### Setup reverse route from server
                    match = parser.OFPMatch(in_port=selected_server_outport,
                                            eth_type=eth.ethertype, eth_src=selected_server_mac, eth_dst=eth.src,
                                            ip_proto=iphdr.proto, ipv4_src=selected_server_ip, ipv4_dst=iphdr.src,
                                            tcp_src=tcphdr.dst_port, tcp_dst=tcphdr.src_port)

                    if self.rewrite_ip_header:
                        actions = ([parser.OFPActionSetField(eth_src=self.virtual_mac),
                                    parser.OFPActionSetField(ipv4_src=self.virtual_ip),
                                    parser.OFPActionOutput(in_port)])
                    else:
                        actions = ([parser.OFPActionSetField(eth_src=self.virtual_mac),
                                    parser.OFPActionOutput(in_port)])

                    inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

                    cookie = random.randint(0, 0xffffffffffffffff)

                    mod = parser.OFPFlowMod(datapath=datapath, match=match, idle_timeout=10,
                                            instructions=inst, cookie=cookie)
                    datapath.send_msg(mod)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)



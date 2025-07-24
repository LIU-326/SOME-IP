import eth_scapy_sd as sd

from network_define import EthParameter

from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP


class SomeipPacker:
    def __init__(self):
        self.eth_para = EthParameter()
        self.sd_session_id = 1
        self.client_session_id = 1

    def update_sd_session_id(self):
        """更新session_id，从0递增到65535"""
        self.sd_session_id += 1
        if self.sd_session_id >= 65535:
            self.sd_session_id = 0

    def update_client_session_id(self):
        self.client_session_id += 1
        if self.client_session_id >= 65535:
            self.client_session_id = 0


    # ===========================#
    #          序列化             #
    # ===========================#
    def packet_subscribe(self, service_id: list, ttl: int):
        """组事件订阅包"""
        subscribe_packager = sd.SD()
        subscribe_packager.setFlag("REBOOT", 1)
        subscribe_packager.setFlag("UNICAST", 1)
        subscribe_packager.len_entry_array = 16 * len(service_id)
        subscribe_packager.len_option_array = 24
        for i in service_id:
            subscribe_packager.entry_array.append(
                sd.SDEntry_EventGroup(
                    type=sd.SDEntry_EventGroup.TYPE_EVTGRP_SUBSCRIBE,
                    srv_id=i,
                    inst_id=0x1,
                    n_opt_1=2,
                    major_ver=0x1,
                    ttl=ttl,
                    eventgroup_id=0x1,
                )
            )
        subscribe_packager.option_array = [
            # UDP EndPoint
            sd.SDOption_IP4_EndPoint(
                addr=self.eth_para.server_ip,
                l4_proto=0x11,
                port=self.eth_para.consumer_prot,
            ),
            # TCP EndPoint
            sd.SDOption_IP4_EndPoint(
                addr=self.eth_para.server_ip,
                l4_proto=0x06,
                port=self.eth_para.consumer_prot,
            ),
        ]
        print(subscribe_packager.show())
        subscribe_package = (
            Ether()
            / IP(src=self.eth_para.server_ip, dst=self.eth_para.client_ip)
            / UDP(sport=self.eth_para.sd_port, dport=self.eth_para.sd_port)
            / subscribe_packager.get_someip_with_session_id(
                self.client_session_id, True
            )
        )
        self.update_client_session_id()
        return subscribe_package

    def packet_subscribe_ack(self, service_id: list, ttl: int):
        """组ack包"""
        ack_packager = sd.SD()
        ack_packager.setFlag("REBOOT", 1)
        ack_packager.setFlag("UNICAST", 1)
        ack_packager.len_entry_array = 16 * len(service_id)
        ack_packager.len_option_array = 0
        for i in service_id:
            ack_packager.entry_array.append(
                sd.SDEntry_EventGroup(
                    type=sd.SDEntry_EventGroup.TYPE_EVTGRP_SUBSCRIBE_ACK,
                    srv_id=i,
                    inst_id=0x1,
                    major_ver=0x1,
                    ttl=ttl,
                    eventgroup_id=0x1,
                )
            )
        print(ack_packager.show())
        ack_package = (
            Ether()
            / IP(src=self.eth_para.server_ip, dst=self.eth_para.client_ip)
            / UDP(sport=self.eth_para.sd_port, dport=self.eth_para.sd_port)
            / ack_packager.get_someip_with_session_id(self.client_session_id, True)
        )
        self.update_client_session_id()
        return ack_package

    def packet_offer(self, service_id: list, ttl: int):
        """组offer包"""
        offer_packager = sd.SD()
        offer_packager.setFlag("REBOOT", 1)
        offer_packager.setFlag("UNICAST", 1)
        offer_packager.len_entry_array = 16 * len(service_id)
        offer_packager.len_option_array = 12
        for i in service_id:
            offer_packager.entry_array.append(
                sd.SDEntry_Service(
                    type=sd.SDEntry_Service.TYPE_SRV_OFFERSERVICE,
                    srv_id=i,
                    inst_id=0x1,
                    n_opt_1=1,
                    major_ver=0x1,
                    minor_ver=0x01,
                    ttl=ttl,
                )
            )
        offer_packager.option_array = [
            sd.SDOption_IP4_EndPoint(
                addr=self.eth_para.server_ip,
                l4_proto=0x11,
                port=self.eth_para.producer_port,
            )
        ]
        print(offer_packager.show())
        offer_package = (
            Ether()
            / IP(src=self.eth_para.server_ip, dst=self.eth_para.sd_ip)
            / UDP(sport=self.eth_para.sd_port, dport=self.eth_para.sd_port)
            / offer_packager.get_someip_with_session_id(self.sd_session_id, True)
        )
        self.update_sd_session_id()
        return offer_package
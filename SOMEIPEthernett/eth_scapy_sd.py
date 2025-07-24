from eth_scapy_someip import SOMEIP  # 添加这行导入
import ctypes
import collections
import struct
from scapy.fields import *
from scapy.packet import *
from scapy.layers.inet6 import IP6Field

class _SDPacketBase(Packet):
    """Base class for all SD Packet definitions."""
    _defaults = {}

    def _set_defaults(self):
        for key in self._defaults.keys():
            try:
                self.get_field(key)
            except KeyError:
                pass
            else:
                self.setfieldval(key, self._defaults[key])

    def init_fields(self, _pkt=None):
        Packet.init_fields(self, _pkt)
        self._set_defaults()

class _SDEntry(_SDPacketBase):
    """Base class for SDEntry packages."""
    TYPE_FMT = ">B"
    TYPE_PAYLOAD_I = 0
    TYPE_SRV_FINDSERVICE = 0x00
    TYPE_SRV_OFFERSERVICE = 0x01
    TYPE_SRV = (TYPE_SRV_FINDSERVICE, TYPE_SRV_OFFERSERVICE)
    TYPE_EVTGRP_SUBSCRIBE = 0x06
    TYPE_EVTGRP_SUBSCRIBE_ACK = 0x07
    TYPE_EVTGRP = (TYPE_EVTGRP_SUBSCRIBE, TYPE_EVTGRP_SUBSCRIBE_ACK)
    OVERALL_LEN = 16

    fields_desc = [
        ByteField("type", 0),
        ByteField("index_1", 0),
        ByteField("index_2", 0),
        BitField("n_opt_1", 0, 4),
        BitField("n_opt_2", 0, 4),
        ShortField("srv_id", 0),
        ShortField("inst_id", 0),
        ByteField("major_ver", 0),
        X3BytesField("ttl", 0),
    ]

    def guess_payload_class(self, payload):
        pl_type = struct.unpack(self.TYPE_FMT, payload[self.TYPE_PAYLOAD_I:self.TYPE_PAYLOAD_I+1])[0]
        if pl_type in self.TYPE_SRV:
            return SDEntry_Service
        elif pl_type in self.TYPE_EVTGRP:
            return SDEntry_EventGroup

class SDEntry_Service(_SDEntry):
    """Service Entry."""
    _defaults = {"type": _SDEntry.TYPE_SRV_FINDSERVICE}
    name = "Service Entry"
    fields_desc = _SDEntry.fields_desc + [IntField("minor_ver", 0)]

class SDEntry_EventGroup(_SDEntry):
    """EventGroup Entry."""
    _defaults = {"type": _SDEntry.TYPE_EVTGRP_SUBSCRIBE}
    name = "Eventgroup Entry"
    fields_desc = _SDEntry.fields_desc + [
        BitField("res", 0, 12),
        BitField("cnt", 0, 4),
        ShortField("eventgroup_id", 0),
    ]

class _SDOption(_SDPacketBase):
    """Base class for SDOption packages."""
    TYPE_FMT = ">B"
    TYPE_PAYLOAD_I = 2
    CFG_TYPE = 0x01
    LOADBALANCE_TYPE = 0x02
    IP4_ENDPOINT_TYPE = 0x04
    IP4_MCAST_TYPE = 0x14
    IP4_SDENDPOINT_TYPE = 0x24
    IP6_ENDPOINT_TYPE = 0x06
    IP6_MCAST_TYPE = 0x16
    IP6_SDENDPOINT_TYPE = 0x26

    def guess_payload_class(self, payload):
        pl_type = struct.unpack(self.TYPE_FMT, payload[self.TYPE_PAYLOAD_I:self.TYPE_PAYLOAD_I+1])[0]
        if pl_type == self.CFG_TYPE:
            return SDOption_Config
        elif pl_type == self.LOADBALANCE_TYPE:
            return SDOption_LoadBalance
        elif pl_type == self.IP4_ENDPOINT_TYPE:
            return SDOption_IP4_EndPoint
        elif pl_type == self.IP4_MCAST_TYPE:
            return SDOption_IP4_Multicast
        elif pl_type == self.IP4_SDENDPOINT_TYPE:
            return SDOption_IP4_SD_EndPoint
        elif pl_type == self.IP6_ENDPOINT_TYPE:
            return SDOption_IP6_EndPoint
        elif pl_type == self.IP6_MCAST_TYPE:
            return SDOption_IP6_Multicast
        elif pl_type == self.IP6_SDENDPOINT_TYPE:
            return SDOption_IP6_SD_EndPoint

class _SDOption_Header(_SDOption):
    fields_desc = [
        ShortField("len", None),
        ByteField("type", 0),
        ByteField("res_hdr", 0),
    ]

class _SDOption_Tail(_SDOption):
    fields_desc = [
        ByteField("res_tail", 0),
        ByteEnumField("l4_proto", 0x06, {0x06: "TCP", 0x11: "UDP"}),
        ShortField("port", 0),
    ]

class _SDOption_IP4(_SDOption):
    fields_desc = [_SDOption_Header, IPField("addr", "0.0.0.0"), _SDOption_Tail]

class _SDOption_IP6(_SDOption):
    fields_desc = [_SDOption_Header, IP6Field("addr", "::1"), _SDOption_Tail]

class SDOption_Config(_SDOption):
    LEN_OFFSET = 0x01
    name = "Config Option"
    _defaults = {"type": _SDOption.CFG_TYPE}
    fields_desc = [_SDOption_Header, StrField("cfg_str", "")]
    
    def post_build(self, p, pay):
        if self.len is None:
            l = len(self.cfg_str) + self.LEN_OFFSET
            p = struct.pack("!H", l) + p[2:]
        return p + pay

class SDOption_LoadBalance(_SDOption):
    name = "LoadBalance Option"
    _defaults = {"type": _SDOption.LOADBALANCE_TYPE, "len": 0x05}
    fields_desc = [_SDOption_Header, ShortField("priority", 0), ShortField("weight", 0)]

class SDOption_IP4_EndPoint(_SDOption_IP4):
    name = "IP4 EndPoint Option"
    _defaults = {"type": _SDOption.IP4_ENDPOINT_TYPE, "len": 0x0009}

class SDOption_IP4_Multicast(_SDOption_IP4):
    name = "IP4 Multicast Option"
    _defaults = {"type": _SDOption.IP4_MCAST_TYPE, "len": 0x0009}

class SDOption_IP4_SD_EndPoint(_SDOption_IP4):
    name = "IP4 SDEndPoint Option"
    _defaults = {"type": _SDOption.IP4_SDENDPOINT_TYPE, "len": 0x0009}

class SDOption_IP6_EndPoint(_SDOption_IP6):
    name = "IP6 EndPoint Option"
    _defaults = {"type": _SDOption.IP6_ENDPOINT_TYPE, "len": 0x0015}

class SDOption_IP6_Multicast(_SDOption_IP6):
    name = "IP6 Multicast Option"
    _defaults = {"type": _SDOption.IP6_MCAST_TYPE, "len": 0x0015}

class SDOption_IP6_SD_EndPoint(_SDOption_IP6):
    name = "IP6 SDEndPoint Option"
    _defaults = {"type": _SDOption.IP6_SDENDPOINT_TYPE, "len": 0x0015}

class SD(_SDPacketBase):
    """SD Packet"""
    SOMEIP_MSGID_SRVID = 0xFFFF
    SOMEIP_MSGID_SUBID = 0x1
    SOMEIP_MSGID_EVENTID = 0x100
    SOMEIP_PROTO_VER = 0x01
    SOMEIP_IFACE_VER = 0x01
    
    _sdFlag = collections.namedtuple("Flag", "mask offset")
    FLAGSDEF = {
        "REBOOT": _sdFlag(mask=0x80, offset=7),
        "UNICAST": _sdFlag(mask=0x40, offset=6),
    }

    fields_desc = [
        ByteField("flags", 0),
        X3BytesField("res", 0),
        FieldLenField("len_entry_array", None, length_of="entry_array", fmt="!I"),
        PacketListField("entry_array", None, _SDEntry, length_from=lambda pkt: pkt.len_entry_array),
        FieldLenField("len_option_array", None, length_of="option_array", fmt="!I"),
        PacketListField("option_array", None, _SDOption, length_from=lambda pkt: pkt.len_option_array),
    ]

    def getFlag(self, name):
        name = name.upper()
        if name in self.FLAGSDEF:
            return (self.flags & self.FLAGSDEF[name].mask) >> self.FLAGSDEF[name].offset
        return None

    def setFlag(self, name, value):
        name = name.upper()
        if name in self.FLAGSDEF:
            self.flags = (self.flags & ~self.FLAGSDEF[name].mask) | ((value & 0x01) << self.FLAGSDEF[name].offset)

    def get_someip_with_session_id(self, session_id, stacked=False):
        p = SOMEIP()
        p.msg_id.srv_id = self.SOMEIP_MSGID_SRVID
        p.msg_id.sub_id = self.SOMEIP_MSGID_SUBID
        p.msg_id.event_id = self.SOMEIP_MSGID_EVENTID
        p.proto_ver = self.SOMEIP_PROTO_VER
        p.iface_ver = self.SOMEIP_IFACE_VER
        p.msg_type = SOMEIP.TYPE_NOTIFICATION
        p.req_id.session_id = session_id
        return p / self if stacked else p
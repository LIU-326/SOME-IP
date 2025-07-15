from scapy.packet import Raw
from typing import Optional
from dataclasses import dataclass

@dataclass
class SomeIPHeaderParams:
    service_id: int
    event_id: int      # 或 event_id，取决于消息类型
    client_id: int
    session_id: int
    msg_type: int
    return_code: int
    length: int
    protocol_version: int
    interface_version: int


class SomeipUnpacker:
    @staticmethod
    def get_someip_header_params(receive_packet) -> Optional[SomeIPHeaderParams]:
        """获取someip header"""
        try:
            if receive_packet.haslayer("SOME/IP"):
                someip_layer = receive_packet["SOME/IP"]
                # 获取someip header值
                service_id = someip_layer.msg_id.srv_id
                sub_id = someip_layer.msg_id.sub_id
                event_id = sub_id << 15 | someip_layer.msg_id.event_id
                # 提取请求 ID（Client ID 和 Session ID）
                req_id = someip_layer.req_id
                client_id = req_id.client_id
                session_id = req_id.session_id

                # 构造头部对象
                return SomeIPHeaderParams(
                    service_id=service_id,
                    event_id=event_id,
                    client_id=client_id,
                    session_id=session_id,
                    msg_type=someip_layer.msg_type,
                    return_code=someip_layer.retcode,
                    length=someip_layer.len,
                    protocol_version=someip_layer.proto_ver,
                    interface_version=someip_layer.iface_ver,
                )
        except (AttributeError, ValueError) as e:
            print(f"解析失败: {e}")
            return None


    @staticmethod
    def get_someip_payload(receive_packet):
        """获取someip payload"""
        try:
            someip_payload = receive_packet[Raw].load
            # print(f"someip_payload: {someip_payload}")
            return someip_payload
        except AttributeError:
            return None
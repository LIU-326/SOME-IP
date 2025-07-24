import io
import sys
sys.stdin = open(0, 'r')
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
from eth_scapy_someip import SOMEIP
import threading
import time
from scapy.sendrecv import sendp, sniff
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
from packet_define import SomeipPacker
from unpack_define import SomeipUnpacker
from network_define import EthParameter
from scapy.utils import PcapWriter

class SomeipController:
    def __init__(self):
        self.packer = SomeipPacker()
        self.unpacker = SomeipUnpacker()
        self._stop_event = threading.Event()
        self.threads = []
        self.pcap_writer = None
        
    def start(self):
        """启动服务线程"""
        self.pcap_writer = PcapWriter("someip_direct.pcapng", append=True, sync=True)
        
        # 启动接收线程
        receiver = SomeIpReceiver(
            eth_desc=EthParameter.server_network_card,
            someip_unpacker=self.unpacker,
            stop_event=self._stop_event,
            pcap_writer=self.pcap_writer
        )
        self.threads.append(receiver)
        time.sleep(1)  # 确保接收线程先启动

        print(f"\nSOME/IP直连服务已启动 (本机IP: {EthParameter.server_ip})")
        print("="*50)
        print("1 - 发送Offer服务公告")
        print("2 - 发送事件订阅请求")
        print("3 - 发送订阅确认ACK")
        print("q - 退出程序")
        print("="*50)

    def stop(self):
        """停止服务线程"""
        self._stop_event.set()
        for thread in self.threads:
            if thread.is_alive():
                thread.join(timeout=1)
        if self.pcap_writer:
            self.pcap_writer.close()
        print("SOME/IP服务已停止")

    def send_offer(self):
        """发送服务Offer包"""
        packet = self.packer.packet_offer(
            service_id=[0xA994], 
            ttl=10  # 生存时间10秒
        )
        sendp(packet, iface=EthParameter.server_network_card, verbose=True)
        print(f"[+] 已向 {EthParameter.client_ip} 发送服务Offer")

    def send_subscribe(self):
        """发送事件订阅包"""
        packet = self.packer.packet_subscribe(
            service_id=[0xA994],
            ttl=10
        )
        sendp(packet, iface=EthParameter.server_network_card, verbose=True)
        print(f"[+] 已向 {EthParameter.client_ip} 发送事件订阅")

    def send_subscribe_ack(self):
        """发送订阅确认包"""
        packet = self.packer.packet_subscribe_ack(
            service_id=[0xA994],
            ttl=10
        )
        sendp(packet, iface=EthParameter.server_network_card, verbose=True)
        print(f"[+] 已向 {EthParameter.client_ip} 发送订阅确认ACK")

class SomeIpReceiver(threading.Thread):
    def __init__(self, eth_desc, someip_unpacker, stop_event, pcap_writer=None):
        super().__init__(daemon=True)
        self.eth_desc = eth_desc
        self.unpacker = someip_unpacker
        self._stop_event = stop_event
        self.pcap_writer = pcap_writer
        self.start()

    def packet_callback(self, packet):
        if packet.haslayer("SOME/IP"):
            # 记录原始报文
            if self.pcap_writer:
                self.pcap_writer.write(packet)
            
            # 解析SOME/IP头部
            header = self.unpacker.get_someip_header_params(packet)
            if header:
                print("\n[收到SOME/IP报文]")
                print(f"来源IP: {packet[IP].src}")
                print(f"服务ID: 0x{header.service_id:04X}")
                print(f"消息类型: {self._get_msg_type_name(header.msg_type)}")
                print(f"会话ID: {header.session_id}")
                
                # 打印Payload（如果有）
                payload = self.unpacker.get_someip_payload(packet)
                if payload:
                    print(f"Payload: {payload.hex()}")

    def _get_msg_type_name(self, msg_type):
        """将消息类型代码转为可读名称"""
        types = {
            0x00: "REQUEST",
            0x01: "REQUEST_NO_RETURN",
            0x02: "NOTIFICATION",
            0x40: "REQUEST_ACK",
            0x41: "REQUEST_NO_RETURN_ACK",
            0x42: "NOTIFICATION_ACK",
            0x80: "RESPONSE",
            0x81: "ERROR"
        }
        return types.get(msg_type, f"UNKNOWN(0x{msg_type:02X})")

    def run(self):
        sniff(
            iface=self.eth_desc,
            prn=self.packet_callback,
            filter=f"udp port {EthParameter.sd_port}",
            stop_filter=lambda x: self._stop_event.is_set(),
            store=False
        )

if __name__ == "__main__":
    controller = SomeipController()
    try:
        controller.start()
        
        # 交互式命令处理
        while True:
            cmd = input("请输入命令: ").strip().lower()
            if cmd == '1':
                controller.send_offer()
            elif cmd == '2':
                controller.send_subscribe()
            elif cmd == '3':
                controller.send_subscribe_ack()
            elif cmd == 'q':
                break
            else:
                print("无效命令，请重新输入")
                
    except KeyboardInterrupt:
        print("\n检测到Ctrl+C中断...")
    finally:
        controller.stop()
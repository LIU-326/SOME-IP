from eth_scapy_someip import SOMEIP
import threading
import time
from scapy.sendrecv import sendp, sniff
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
from packet_define import SomeipPacker
from unpack_define import SomeipUnpacker
from network_define import EthParameter

class SomeipController:
    def __init__(self):
        self.packer = SomeipPacker()
        self.unpacker = SomeipUnpacker()
        self._stop_event = threading.Event()
        self.threads = []

    def start(self):
        """启动所有服务线程"""
        # 启动接收线程
        receiver = SomeIpReceiver(
            eth_desc=EthParameter.server_network_card,
            someip_unpacker=self.unpacker,
            stop_event=self._stop_event
        )
        self.threads.append(receiver)
        time.sleep(1)  # 确保接收线程先启动

        # 启动Offer服务线程
        offer_thread = SomeipServiceThread(
            packer=self.packer,
            service_type="offer",
            service_ids=[0xA994, 0xA995],
            ttl=3,
            interval=2.0,
            stop_event=self._stop_event
        )
        self.threads.append(offer_thread)

        print("SOME/IP 服务已启动")

    def stop(self):
        """停止所有服务线程"""
        self._stop_event.set()
        for thread in self.threads:
            if thread.is_alive():
                thread.join(timeout=1)
        print("SOME/IP 服务已停止")

class SomeipServiceThread(threading.Thread):
    def __init__(self, packer, service_type, service_ids, ttl, interval, stop_event):
        super().__init__(daemon=True)
        self.packer = packer
        self.service_type = service_type
        self.service_ids = service_ids
        self.ttl = ttl
        self.interval = interval
        self._stop_event = stop_event
        self.start()

    def run(self):
        while not self._stop_event.is_set():
            try:
                if self.service_type == "offer":
                    packet = self.packer.packet_offer(
                        service_id=self.service_ids,
                        ttl=self.ttl
                    )
                    dst_ip = EthParameter.sd_ip  # 使用组播地址
                elif self.service_type == "subscribe_ack":
                    packet = self.packer.packet_subscribe_ack(
                        service_id=self.service_ids,
                        ttl=self.ttl
                    )
                    dst_ip = EthParameter.client_ip  # 使用单播地址
                
                sendp(packet, iface=EthParameter.server_network_card, verbose=False)
                time.sleep(self.interval)
            except Exception as e:
                print(f"{self.service_type} 发送异常: {e}")
                if self._stop_event.is_set():
                    break

class SomeIpReceiver(threading.Thread):
    def __init__(self, eth_desc, someip_unpacker, stop_event):
        super().__init__(daemon=True)
        self.eth_desc = eth_desc
        self.unpacker = someip_unpacker
        self._stop_event = stop_event
        self.start()

    def packet_callback(self, packet):
        if packet.haslayer("SOME/IP"):
            header = self.unpacker.get_someip_header_params(packet)
            if header:
                print(f"\n收到 SOME/IP 消息:")
                print(f"服务ID: 0x{header.service_id:04X}")
                print(f"消息类型: {header.msg_type}")
                print(f"会话ID: {header.session_id}")
                
                payload = self.unpacker.get_someip_payload(packet)
                if payload:
                    print(f"Payload 长度: {len(payload)} 字节")

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
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        controller.stop()
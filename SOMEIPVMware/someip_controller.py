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
        self.pcap_writer = PcapWriter("vm_side.pcapng", append=True, sync=True)
        
        receiver = SomeIpReceiver(
            eth_desc=EthParameter.server_network_card,
            someip_unpacker=self.unpacker,
            stop_event=self._stop_event,
            pcap_writer=self.pcap_writer
        )
        self.threads.append(receiver)
        time.sleep(1)

        print(f"\n[虚拟机] SOME/IP服务已启动 (IP: {EthParameter.server_ip})")
        print("="*50)
        print("1 - 发送Offer服务公告 (多播)")
        print("2 - 发送事件订阅请求 (到主机)")
        print("3 - 发送订阅确认ACK (到主机)")
        print("q - 退出程序")
        print("="*50)

    def stop(self):
        self._stop_event.set()
        for thread in self.threads:
            if thread.is_alive():
                thread.join(timeout=1)
        if self.pcap_writer:
            self.pcap_writer.close()
        print("[虚拟机] 服务已停止")

    def show_comm_state(self, direction, msg_type, details):
        color = {
            "offer": "\033[93m",    # 黄色
            "subscribe": "\033[96m", # 青色
            "ack": "\033[92m"       # 绿色
        }.get(msg_type, "\033[0m")
        arrow = "==>" if direction == "send" else "<=="
        print(f"{color}{arrow} {msg_type.upper()} {arrow} {details}\033[0m")

    def send_offer(self):
        packet = self.packer.packet_offer(
            service_id=[0xA994], 
            ttl=10
        )
        sendp(packet, iface=EthParameter.server_network_card, verbose=False)
        self.show_comm_state(
            "send", "offer",
            f"多播地址={EthParameter.sd_ip} 服务ID=0xA994"
        )

    def send_subscribe(self):
        packet = self.packer.packet_subscribe(
            service_id=[0xA994],
            ttl=10
        )
        sendp(packet, iface=EthParameter.server_network_card, verbose=False)
        self.show_comm_state(
            "send", "subscribe",
            f"目标={EthParameter.client_ip} 事件组=0x0001"
        )

    def send_subscribe_ack(self):
        packet = self.packer.packet_subscribe_ack(
            service_id=[0xA994],
            ttl=10
        )
        sendp(packet, iface=EthParameter.server_network_card, verbose=False)
        self.show_comm_state(
            "send", "ack",
            f"目标={EthParameter.client_ip} 会话ID={self.packer.client_session_id}"
        )

class SomeIpReceiver(threading.Thread):
    def __init__(self, eth_desc, someip_unpacker, stop_event, pcap_writer=None):
        super().__init__(daemon=True)
        self.eth_desc = eth_desc
        self.unpacker = someip_unpacker
        self._stop_event = stop_event
        self.pcap_writer = pcap_writer

    def _parse_sd_content(self, sd_layer):
        results = []
        for entry in sd_layer.entry_array:
            if entry.type == 0x01:  # OfferService
                results.append(f"📢 服务ID:0x{entry.srv_id:04X} 版本:{entry.major_ver}.{entry.minor_ver}")
            elif entry.type == 0x06:  # Subscribe
                results.append(f"✏️ 订阅事件组:0x{entry.eventgroup_id:04X}")
            elif entry.type == 0x07:  # SubscribeAck
                results.append(f"✅ 确认事件组:0x{entry.eventgroup_id:04X}")
        return results

    def packet_callback(self, packet):
        if packet.haslayer("SOME/IP"):
            if self.pcap_writer:
                self.pcap_writer.write(packet)
            
            header = self.unpacker.get_someip_header_params(packet)
            if not header:
                return

            print("\n\033[95m<==", end=" ")
            if packet[IP].dst == EthParameter.sd_ip:
                print("多播公告", end=" ")
            else:
                print("单播消息", end=" ")
            print(f"来自: {packet[IP].src}\033[0m")

            if packet.haslayer("SD"):
                for line in self._parse_sd_content(packet["SD"]):
                    print(f"    {line}")

            print(f"    协议详情: 类型={self._get_msg_type_name(header.msg_type)} 会话ID={header.session_id}")

    def _get_msg_type_name(self, msg_type):
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
            filter=f"udp port {EthParameter.sd_port} or udp port {EthParameter.producer_port}",
            stop_filter=lambda x: self._stop_event.is_set(),
            store=False
        )

if __name__ == "__main__":
    controller = SomeipController()
    try:
        controller.start()
        
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
                print("无效命令")
                
    except KeyboardInterrupt:
        print("\n检测到中断信号...")
    finally:
        controller.stop()
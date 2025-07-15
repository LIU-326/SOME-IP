from scapy.all import *
import struct

# 1. 定义 Ethernet/IP/UDP 帧
eth = Ether(dst="00:11:22:33:44:55", src="aa:bb:cc:dd:ee:ff")
ip = IP(src="192.168.1.100", dst="239.255.1.1", ttl=32, id=0x1234)
udp = UDP(sport=50000, dport=30490)  # SOME/IP 标准端口

# 2. 定义 SOME/IP 头部参数
service_id = 0x1234
method_id = 0x5678
client_id = 0x9988
session_id = 0x7766
protocol_version = 0x01
interface_version = 0x02
message_type = 0x00  # REQUEST
return_code = 0x00   # E_OK

# 3. Payload（确保长度对齐，避免乱码）
payload = b"Test payload for SOME/IP"  # 23字节

# 4. 修正 Length 计算（关键！）
# Length = Request ID(4) + Protocol/Interface/Type/ReturnCode(4) + Payload
length = 8 + len(payload)  # 8 = 4 + 4

# 5. 构建 SOME/IP 头部（大端字节序）
someip_header = (
    struct.pack(">HH", service_id, method_id)  # Message ID
    + struct.pack(">I", length)                # Length
    + struct.pack(">HH", client_id, session_id) # Request ID
    + struct.pack(">BBBB",                     # Protocol/Interface/Type/ReturnCode
        protocol_version,
        interface_version,
        message_type,
        return_code
    )
)

# 6. 组合完整数据包
packet = eth / ip / udp / Raw(load=someip_header + payload)

# 7. 保存为 pcap 文件
wrpcap("someip_test.pcap", [packet])

import os
print(f"文件路径: {os.path.abspath('someip_test.pcapng')}")
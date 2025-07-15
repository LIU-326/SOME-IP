class EthParameter:
    # 广播/组播配置
    sd_network_card = "eth0.62"  # 根据实际网卡名称修改
    sd_ip = "239.0.0.255"
    
    # 本机配置
    server_network_card = "Realtek 8852CE WiFi 6E PCI-E NIC"  # 根据实际网卡名称修改
    server_ip = "192.168.62.31"
    
    # 客户端配置
    client_network_card = "eth0.62"  # 根据实际网卡名称修改
    client_ip = "192.168.62.11"
    
    # 端口配置
    sd_port = 30490
    producer_port = 30500
    consumer_prot = 30501  # 注意: 原代码中可能是拼写错误，应为 consumer_port
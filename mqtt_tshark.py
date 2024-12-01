import pyshark

# 指定 TShark 的路径
pyshark.config.get_config().tshark_path = '/usr/bin/tshark'

# 读取PCAP文件
pcap_file = 'mqtt.pcap'  # 替换为你的PCAP文件路径
cap = pyshark.FileCapture(pcap_file, display_filter='mqtt')

# 遍历数据包并提取MQTT数据包的MQTT层信息
mqtt_packets = []
for packet in cap:
    if 'mqtt' in packet:
        mqtt_packets.append(packet.mqtt)

# 输出MQTT数据包的MQTT层信息
print("MQTT解析:")
for mqtt_layer in mqtt_packets:
    print(mqtt_layer)
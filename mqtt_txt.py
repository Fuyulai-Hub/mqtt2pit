import pyshark
import re

# 指定 TShark 的路径
pyshark.config.get_config().tshark_path = '/usr/bin/tshark'

# 读取PCAP文件
pcap_file = 'mqtt.pcap'  # 替换为你的PCAP文件路径
cap = pyshark.FileCapture(pcap_file, display_filter='mqtt')

# 定义一个函数来移除ANSI转义序列
def remove_ansi_escape_codes(text):
    ansi_escape = re.compile(r'(?:\x1B[@-_]|[\x80-\x9F])[0-?]*[ -/]*[@-~]')
    return ansi_escape.sub('', text)

# 遍历数据包并提取MQTT数据包的MQTT层信息
mqtt_packets = []
for packet in cap:
    if 'mqtt' in packet:
        mqtt_packets.append(packet.mqtt)

# 输出MQTT数据包的MQTT层信息，并保存到txt文件
output_file = 'mqtt_output.txt'
with open(output_file, 'w') as file:
    file.write("MQTT解析:\n")
    for mqtt_layer in mqtt_packets:
        cleaned_mqtt_info = remove_ansi_escape_codes(str(mqtt_layer))
        file.write(cleaned_mqtt_info + '\n')

print(f"MQTT解析结果已保存到 {output_file}")
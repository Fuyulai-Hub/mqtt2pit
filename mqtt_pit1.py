import re
import xml.etree.ElementTree as ET
from xml.dom.minidom import parseString

# 定义一个函数来解析MQTT消息并创建Peach XML元素
def parse_mqtt_to_peach(mqtt_data):
    # 定义Peach XML的根元素
    root = ET.Element("Peach", xmlns="http://peachfuzzer.com/2012/Peach", 
                     xmlns_xsi="http://www.w3.org/2001/XMLSchema-instance", 
                     xsi_schemaLocation="http://peachfuzzer.com/2012/Peach ../peach.xsd")

    # 遍历每一层MQTT消息
    for layer in mqtt_data.strip().split("Layer MQTT\n"):
        if not layer.strip():
            continue

        # 解析MQTT消息头部标志、消息类型等信息
        match = re.search(r"Header Flags: 0x(\w+), Message Type: (.+)", layer)
        if match:
            header_flags = match.group(1)
            message_type = match.group(2)

            # 创建DataModel元素
            data_model = ET.SubElement(root, "DataModel", name=message_type, mutable="true")

            # 创建head块
            head = ET.SubElement(data_model, "Block", name="head", mutable="true")
            ET.SubElement(head, "Number", name="message_type", size="8", value=f"{header_flags}", signed="false", endian="network", mutable="false")

            # 根据消息类型添加不同的字段
            if message_type == "Connect Command":
                # 解析Connect Command特有的字段
                protocol_name_match = re.search(r"Protocol Name: (.+)", layer)
                version_match = re.search(r"Version: (.+)", layer)
                connect_flags_match = re.search(r"Connect Flags: 0x(\w+)", layer)
                keep_alive_match = re.search(r"Keep Alive: (\d+)", layer)
                client_id_match = re.search(r"Client ID: (.+)", layer)

                # 创建remaining块
                remaining = ET.SubElement(data_model, "Block", name="remaining", mutable="true")
                ET.SubElement(remaining, "Number", name="protocol_name_length", size="8", value=f"{len(protocol_name_match.group(1))}", signed="false", endian="network", mutable="true")
                ET.SubElement(remaining, "Blob", name="protocol_name", size=f"{len(protocol_name_match.group(1))}", value=protocol_name_match.group(1), mutable="false")
                ET.SubElement(remaining, "Number", name="version", size="8", value=f"{version_match.group(1)}", signed="false", endian="network", mutable="true")
                ET.SubElement(remaining, "Number", name="connect_flags", size="8", value=f"{connect_flags_match.group(1)}", signed="false", endian="network", mutable="true")
                ET.SubElement(remaining, "Number", name="keep_alive", size="16", value=f"{keep_alive_match.group(1)}", signed="false", endian="network", mutable="true")
                ET.SubElement(remaining, "Number", name="client_id_length", size="16", value=f"{len(client_id_match.group(1))}", signed="false", endian="network", mutable="true")
                ET.SubElement(remaining, "Blob", name="client_id", size=f"{len(client_id_match.group(1))}", value=client_id_match.group(1), mutable="false")

    # 返回Peach XML的根元素
    return root

# 读取MQTT分析的文本文件
with open('mqtt_output.txt', 'r') as file:
    mqtt_data = file.read()

# 解析MQTT数据并创建Peach XML
peach_xml = parse_mqtt_to_peach(mqtt_data)

# 将Peach XML保存到文件
tree = ET.ElementTree(peach_xml)
xml_str = ET.tostring(peach_xml, encoding='unicode')
dom = parseString(xml_str.encode('utf-8'))
pretty_xml_str = dom.toprettyxml(indent="    ")
with open("mqtt_peach.xml", "w") as f:
    f.write(pretty_xml_str)
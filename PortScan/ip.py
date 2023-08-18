from typing import List, Dict, Tuple
import ipaddress


def extract_ips(input_str):
    """解析逗号分隔的Ip或者Ip段"""
    ip_list = []
    items = input_str.split(",")

    for item in items:
        item = item.strip()
        try:
            # 尝试解析为单个IP地址
            ip = ipaddress.ip_address(item)
            ip_list.append(str(ip))
        except ValueError:
            try:
                # 尝试解析为IP网段
                network = ipaddress.ip_network(item, strict=False)
                # 遍历网段中的每个IP，并添加到列表中
                for ip in network.hosts():
                    ip_list.append(str(ip))
            except ValueError:
                raise ValueError(f"Invalid IP or network: {item}")

    return ip_list


def extract_ips_from_file(filename):
    """从文件中提取出ip或者ip段"""
    ip_list = []

    try:
        with open(filename, "r") as file:
            for line in file:
                item = line.strip()
                try:
                    # 尝试解析为单个IP地址
                    ip = ipaddress.ip_address(item)
                    ip_list.append(str(ip))
                except ValueError:
                    try:
                        # 尝试解析为IP网段
                        network = ipaddress.ip_network(item, strict=False)
                        # 遍历网段中的每个IP，并添加到列表中
                        for ip in network.hosts():
                            ip_list.append(str(ip))
                    except ValueError:
                        raise ValueError(f"Invalid IP or network in line: {item}")
    except FileNotFoundError:
        raise FileNotFoundError(f"File not found: {filename}")

    return ip_list


def parse_ports(input_str):
    '''"从这样的22,80,7000-8000字符串中提取出端口"'''
    port_list = []
    port_ranges = input_str.split(",")

    for port_range in port_ranges:
        port_range = port_range.strip()
        if "-" in port_range:
            start, end = port_range.split("-")
            try:
                start_port = int(start)
                end_port = int(end)
                if 1 <= start_port <= 65535 and 1 <= end_port <= 65535:
                    port_list.extend(range(start_port, end_port + 1))
                else:
                    raise ValueError("Port values should be in the range 1-65535")
            except ValueError:
                raise ValueError("Invalid port range: " + port_range)
        else:
            try:
                port = int(port_range)
                if 1 <= port <= 65535:
                    port_list.append(port)
                else:
                    raise ValueError("Port value should be in the range 1-65535")
            except ValueError:
                raise ValueError("Invalid port: " + port_range)

    return port_list

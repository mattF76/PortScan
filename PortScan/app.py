from typing import List, Dict, Tuple
import multiprocessing
import os
import time
import asyncio
import os
import csv
import sys

import click

from log import logger
from scan import coroutine_scheduler, find_living_ip
from ip import extract_ips, extract_ips_from_file, parse_ports

# 共享的锁对象，用于同步多进程往一个文件中写数据
lock = multiprocessing.Lock()


def save_to_csv(data_list, file_name="output_scan_result.csv"):
    """多次往同一个csv文件中添加数据"""
    field_names = ["ip", "port", "open"]
    file_exists = os.path.isfile(file_name)

    # 写入CSV文件
    with open(file_name, mode="a", newline="") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=field_names)

        if not file_exists:
            writer.writeheader()  # 写入字段名，仅在文件不存在时写入一次

        # 逐行写入数据
        for data in data_list:
            writer.writerow(data)


def single_process_scan(
    ips: List[str], ports: List[int], process_id=0, coroutine_number=1000
) -> None:
    """单进程扫描一堆ip和端口"""
    print(f"process_id {process_id}负责扫描 {len(ips)}个IP和{len(ports)}个端口")

    loop = asyncio.get_event_loop()
    open_ports: List[Dict] = loop.run_until_complete(
        coroutine_scheduler(
            ips, ports, coroutine_number=coroutine_number, process_id=process_id
        )
    )

    # 获取文件锁，写开放的端口到文件中
    lock.acquire()
    try:
        save_to_csv(open_ports, file_name="result.csv")
    finally:
        # 释放锁
        lock.release()


def split_list_into_chunks(lst: List, n: int) -> List:
    """n等分lst，生成n个大小差不多的小lst"""
    if n <= 0:
        raise ValueError("n must be a positive integer")

    chunk_size = len(lst) // n
    remainder = len(lst) % n
    chunks = []

    start = 0
    for i in range(n):
        end = start + chunk_size + (1 if i < remainder else 0)
        chunks.append(lst[start:end])
        start = end

    return chunks


def process_scheduler(
    target_ips: List[str],
    target_ports: List[int],
    process_number: int = 1,
    coroutine_number: int = 1000,
) -> None:
    """创建合适数目进程去扫描"""
    start_time = time.time()

    # 获取cpu内核数，最多启用MAX_PROCESSES进程数
    MAX_PROCESSES = os.cpu_count()
    if process_number > MAX_PROCESSES:
        process_number = MAX_PROCESSES

    # 判断运行几个进程进行扫描
    target_ips_number = len(target_ips)
    target_ports_number = len(target_ports)

    MIN_ASSING_PORTS_PER_PROCESS = 1000  # 如果端口数少于1000，使用一个进程进行扫描即可
    if target_ips_number * target_ports_number < MIN_ASSING_PORTS_PER_PROCESS:
        print("警告：由于扫描端口数少，根据实际情况使用一个进程进行扫描")
        single_process_scan(
            target_ips, target_ports, 0, coroutine_number=coroutine_number
        )
    else:
        # 通过ip数或者端口数几个进程之间均分任务即可
        processes = []

        if target_ports_number > process_number:
            port_chunks = split_list_into_chunks(target_ports, process_number)

            for i in range(process_number):
                port_chunk = port_chunks[i]

                process = multiprocessing.Process(
                    target=single_process_scan,
                    args=(target_ips, port_chunk, i, coroutine_number),
                )
                processes.append(process)
        elif target_ips_number > process_number:
            ip_chunks = split_list_into_chunks(target_ips, process_number)

            for i in range(process_number):
                ip_chunk = ip_chunks[i]

                process = multiprocessing.Process(
                    target=single_process_scan,
                    args=(ip_chunk, target_ports, i, coroutine_number),
                )
                processes.append(process)
        else:
            # 不可能触发
            process = multiprocessing.Process(
                target=single_process_scan,
                args=(target_ips, target_ports, 0, coroutine_number),
            )
            processes.append(process)

        for process in processes:
            process.start()

        for process in processes:
            process.join()

    print("扫描完成")

    end_time = time.time()
    run_time = end_time - start_time
    print(f"程序运行时间：{run_time:.2f}秒")


CONTEXT_SETTINGS = dict(help_option_names=["-h", "--help"])


@click.command(context_settings=CONTEXT_SETTINGS)
@click.option("--ip", help="ip范围，如'x.x.x.x,x.x.x.x/24'")
@click.option("--port", help="端口范围，如'80,443,8000-8080,9001'")
@click.option("--ip-file", help="ip范围，文件中每一行是一个IP或一个网段")
@click.option("--port-file", help="端口范围，文件只有一行，如'80,443,8000-8080,9001'")
@click.option("--process", "-p", default=1, type=int, help="进程数")
@click.option("--coroutine", "-c", default=1000, type=int, help="协程数")
@click.option(
    "--host-discovery",
    "-d",
    default=False,
    type=bool,
    help="结合ping与常见端口，先判断主机是否存活，然后进行全端口扫描，如True or False",
)
def parse_commandline(
    ip: str,
    port: str,
    ip_file: str,
    port_file: str,
    process: int,
    coroutine: int,
    host_discovery: bool,
) -> None:
    """多进程与协程方式扫描端口是否开放

    \b
    示例：
    1. 扫描C段全端口
    python app.py --ip 192.168.1.0/24 --port 1-65535 -p 6 -d True
    2. 扫描C段几个特定端口
    python app.py --ip 192.168.1.0/24 --port 80,8080,81 -d True
    3. 扫描一个IP上全端口
    python app.py --ip 192.168.1.1 --port 1-65535 -p 6
    4. 读取文件进行扫描
    python app.py --ip-file input_ips.txt --port-file input_ports.txt
    """
    ips_list = []
    ports_list = []

    # 外部未传入任何ip参数情况
    if not (ip or ip_file):
        print("工具用法参考： python app.py --help")
        sys.exit(0)
    elif ip:
        # 从命令行中解析ip
        try:
            ips_list = extract_ips(ip)
            # logger.debug(f"从命令行中读取的待扫描IP: {ips_list}")
        except ValueError as e:
            logger.debug(e)
            sys.exit(1)
    else:
        # 从文件中解析ip
        try:
            ips_list = extract_ips_from_file(ip_file)
            # logger.debug(f"从文件中读取的待扫描IP: {ips_list}")
        except (FileNotFoundError, ValueError) as e:
            logger.debug(e)
            sys.exit(1)

    # 外部未传入任何port参数情况
    if not (port or port_file):
        print("工具用法参考： python app.py --help")
        sys.exit(0)
    elif port:
        # 从命令中提取端口
        try:
            ports_list = parse_ports(port)
            # logger.debug(f"从命令行中读取的待扫描端口: {ports_list}")
        except ValueError as e:
            logger.debug(e)
    else:
        # 从文件中提取端口
        try:
            with open(port_file, "r") as file:
                port_str = file.readline().strip()
            ports_list = parse_ports(port_str)
            logger.debug(f"从文件中读取的待扫描端口: {ports_list}")
        except ValueError as e:
            logger.debug(e)

    # 判断主机是否存活
    if host_discovery:
        print("开始检测存活ip")
        ips_list = asyncio.run(find_living_ip(ips_list))
        print(f"检测到{len(ips_list)}个存活ip")
        # logger.debug(f"检测到这些存活ip: {ips_list}")

    print("开始端口扫描")
    process_scheduler(
        target_ips=ips_list,
        target_ports=ports_list,
        process_number=process,
        coroutine_number=coroutine,
    )


if __name__ == "__main__":
    parse_commandline()

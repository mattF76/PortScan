import asyncio
import itertools
from typing import Dict, List
import time

from log import logger

global_total_task = 0  # 总任务数
global_finished_task = 0  # 完成任务数
global_process_id = -1  # 进程id
global_start_time = time.time()
global_current_time = 0


async def scan_single_port(ip: str, port: int, semaphore) -> Dict:
    # 在这里执行单个端口的扫描操作，此处省略具体实现
    try:
        async with semaphore:
            port_is_open = False

            # print(f"Scanning {ip}:{port}")
            # await asyncio.sleep(3)  # 模拟扫描操作的异步等待
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port), timeout=1
                )
                # print(f"{port} 端口开放")
                port_is_open = True
                writer.close()
                await writer.wait_closed()
            except asyncio.TimeoutError:
                # logger.debug(f"scan {ip}:{port} 超1s")
                pass
            except ConnectionRefusedError:
                pass
    except asyncio.TimeoutError:
        logger.debug(f"信号灯超时，可能协程数太大")
        pass

    # 打印扫描进度
    global global_finished_task
    global_finished_task += 1
    global global_current_time
    if (global_finished_task % 2000) == 0:
        progress = (global_finished_task / global_total_task) * 100
        print(
            f"进程{global_process_id} 扫描完成{global_finished_task}/{global_total_task}, 进度{progress:.2f}%"
        )
    if (global_finished_task % (2000 * 5)) == 0:
        global_current_time = time.time()
        run_time = global_current_time - global_start_time
        print(f"耗时：{run_time:.2f}秒")

    # 返回扫描结果
    if port_is_open:
        print(f"{ip}:{port} is open")
        return {"ip": ip, "port": port, "open": True}
    else:
        return {"ip": ip, "port": port, "open": False}


async def scan_ips_and_ports(
    ip_list: List[str], port_list: List[int], semaphore
) -> List[Dict]:
    # 一个协程负责扫描多个Ip和多个端口
    tasks = [
        scan_single_port(ip, port, semaphore)
        for ip, port in itertools.product(ip_list, port_list)
    ]
    port_open_results = await asyncio.gather(*tasks)

    # 只关心开放的端口
    open_ports = []
    for port_open_result in port_open_results:
        if port_open_result["open"]:
            open_ports.append(port_open_result)

    return open_ports


async def coroutine_scheduler(
    ip_list: List[str],
    port_list: List[int],
    coroutine_number: int = 1000,
    process_id: int = 0,
) -> List[Dict]:
    """创建合适协程数去扫描"""
    open_ports = []  # 开放端口情况

    # 使用全局变量记录扫描进度
    global global_total_task
    global_total_task = len(ip_list) * len(port_list)
    global global_process_id
    global_process_id = process_id

    semaphore = asyncio.Semaphore(coroutine_number)  # 限制并发量为1000
    open_ports = await scan_ips_and_ports(ip_list, port_list, semaphore)
    return open_ports


#### 判断IP是否存活  ###


async def ping(ip):
    """ping方式测试IP是否存活"""
    try:
        proc = await asyncio.create_subprocess_shell(
            f"ping -c 1 {ip}",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await proc.communicate()
        return proc.returncode == 0
    except asyncio.CancelledError:
        proc.terminate()
        raise


async def test_port(ip, port):
    """访问端口方式测试IP是否存活"""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=1
        )
        writer.close()
        await writer.wait_closed()
        return True
    except (asyncio.TimeoutError, ConnectionRefusedError):
        return False


async def test_ip(ip: str, test_ports: List[int]):
    """测试一个IP是否存活"""
    if await ping(ip):
        return ip, True

    tasks = []
    for port in test_ports:
        tasks.append(test_port(ip, port))

    results = await asyncio.gather(*tasks)

    for status in results:
        # print(f"IP: {ip} is {'online' if status else 'offline'}")
        if status:
            return ip, True

    return ip, False


async def find_living_ip(
    ips_list: List[str],
) -> List[str]:
    """存活主机发现"""
    alive_ips_list = []
    test_ports = [21, 22, 80, 443, 3306, 3389, 7000, 7001, 8000, 8080]

    tasks = []
    for ip in ips_list:
        tasks.append(test_ip(ip, test_ports))
    results = await asyncio.gather(*tasks)

    for ip, open in results:
        if open:
            alive_ips_list.append(ip)

    return alive_ips_list

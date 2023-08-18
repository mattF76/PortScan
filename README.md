# PortScan
python使用多进程与协程方式进行端口扫描

## 依赖安装
`pip install click`

## 使用
```
python .\app.py -h
Usage: app.py [OPTIONS]

  多进程与协程方式扫描端口是否开放

  示例：
  1. 扫描C段全端口
  python app.py --ip 192.168.1.0/24 --port 1-65535 -p 6 -d True
  2. 扫描C段几个特定端口
  python app.py --ip 192.168.1.0/24 --port 80,8080,81 -d True
  3. 扫描一个IP上全端口
  python app.py --ip 192.168.1.1 --port 1-65535 -p 6
  4. 读取文件进行扫描
  python app.py --ip-file input_ips.txt --port-file input_ports.txt

Options:
  --ip TEXT                     ip范围，如'x.x.x.x,x.x.x.x/24'
  --port TEXT                   端口范围，如'80,443,8000-8080,9001'
  --ip-file TEXT                ip范围，文件中每一行是一个IP或一个网段
  --port-file TEXT              端口范围，文件只有一行，如'80,443,8000-8080,9001'
  -p, --process INTEGER         进程数
  -c, --coroutine INTEGER       协程数
  -d, --host-discovery BOOLEAN  结合ping与常见端口，先判断主机是否存活，然后进行全端口扫描，如True or False
  -h, --help                    Show this message and exit.
```

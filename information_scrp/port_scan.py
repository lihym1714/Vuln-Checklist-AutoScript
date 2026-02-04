import socket
import sys
import subprocess
import re
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from logging_utils import info, success, error, GREEN, RED, RESET

PORTS = range(1,1025)
TARGET = sys.argv[1]

def scan_port(port, target):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((target, port))
        sock.close()
        if result == 0:
            return port
    except Exception:
        pass
    return None

def get_ip_addr():
    info(f"nslookup {TARGET} ...")
    sysMsg = subprocess.getstatusoutput(f"nslookup {TARGET}")

    text = sysMsg[1].split("Non-authoritative answer:")[1]
    addresses = re.findall(r"Address:\s+([\d\.]+)", text)

    print(f"Found IP addresses: {addresses}")
    return addresses

def main():
    info(f"Port Scanning Start ... 1 ~ 1024 ports for {TARGET}")

    ip_addrs = get_ip_addr()

    for i in ip_addrs:
        success(f"Scanning {i} ...")

        open_ports = []

        with ThreadPoolExecutor(max_workers=100) as executor:
            results = executor.map(lambda p: scan_port(p, i), PORTS)

        for port in results:
            if port:
                open_ports.append(port)

        if open_ports:
            print(f"{GREEN}[+] Open ports: {open_ports}{RESET}")
        else:
            error("No open ports found.", colored=False)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        error("Please enter target", colored=False)
        sys.exit(1)
    try:
        main()
    except Exception as e:
        error(f"Error: can not find domain. {e}")

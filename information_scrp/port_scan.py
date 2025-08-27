import socket
import sys
import subprocess
import re
from concurrent.futures import ThreadPoolExecutor

GREEN = "\033[32m"
RED = "\033[31m"
RESET = "\033[0m"

PORTS = range(1,1025)
TARGET = sys.argv[1]

def scan_port(port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((TARGET, port))
        sock.close()
        if result == 0:
            return port
    except Exception:
        pass
    return None

def get_ip_addr():
    print(f"[*] nslookup {TARGET} ...")
    sysMsg = subprocess.getstatusoutput(f"nslookup {TARGET}")

    text = sysMsg[1].split("Non-authoritative answer:")[1]
    addresses = re.findall(r"Address:\s+([\d\.]+)", text)

    print(f"발견된 IP 주소 {addresses}")
    return addresses

def main():
    print("[*] Port Scanning Start ... 1 ~ 1024")

    ip_addrs = get_ip_addr()

    for i in ip_addrs:
        print(f"[+] Scanning {i} ...")
        
        open_ports = []
        TARGET = i

        with ThreadPoolExecutor(max_workers=100) as executor:
            results = executor.map(scan_port, PORTS)

        for port in results:
            if port:
                open_ports.append(port)

        if open_ports:
            print(f"{GREEN}[+] Open ports: {open_ports}{RESET}")
        else:
            print("[-] No open ports found.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("[-] Please enter target")
        sys.exit(1)
    try:    
        main()
    except Exception as e:
        print(f"[-] Error domain을 찾을 수 없습니다. {e}")
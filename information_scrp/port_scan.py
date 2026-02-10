import socket
import sys
import subprocess
import re
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

from typing import Any

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from logging_utils import info, success, error, GREEN, RED, RESET

PORTS = range(1,1025)
NSLOOKUP_TIMEOUT_SECONDS = 10.0

def scan_port(port: int, target: str, *, timeout: float = 0.5) -> int | None:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((target, port))
        sock.close()
        if result == 0:
            return port
    except Exception:
        pass
    return None

def _run_nslookup(target: str, *, timeout: float = NSLOOKUP_TIMEOUT_SECONDS) -> str:
    try:
        proc = subprocess.run(
            ["nslookup", target],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError as exc:
        raise RuntimeError("nslookup command not found") from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"nslookup timeout after {timeout}s") from exc

    output = (proc.stdout or "") + ("\n" + proc.stderr if proc.stderr else "")
    return output.strip()


def get_ip_addr(target: str) -> list[str]:
    info(f"nslookup {target} ...")
    output = _run_nslookup(target)

    # Original implementation parsed only the non-authoritative answer section.
    text = output
    if "Non-authoritative answer:" in output:
        try:
            text = output.split("Non-authoritative answer:", 1)[1]
        except Exception:
            text = output

    # We currently scan with IPv4 sockets; keep only IPv4 addresses.
    addresses = re.findall(r"Address:\s+(\d+\.\d+\.\d+\.\d+)", text)
    # Deduplicate while preserving order.
    seen: set[str] = set()
    unique_addrs: list[str] = []
    for addr in addresses:
        if addr in seen:
            continue
        seen.add(addr)
        unique_addrs.append(addr)

    print(f"Found IP addresses: {unique_addrs}")
    return unique_addrs

def scan_target(target: str, *, max_workers: int = 100, port_timeout: float = 0.5) -> dict[str, Any]:
    info(f"Port Scanning Start ... 1 ~ 1024 ports for {target}")

    result: dict[str, Any] = {
        "target": target,
        "ip_addresses": [],
        "open_ports": {},
        "error": None,
    }

    try:
        ip_addrs = get_ip_addr(target)
        result["ip_addresses"] = ip_addrs
    except Exception as exc:
        msg = f"Error: can not find domain. {exc}"
        error(msg)
        result["error"] = msg
        return result

    for ip in ip_addrs:
        success(f"Scanning {ip} ...")

        open_ports: list[int] = []

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            results_iter = executor.map(lambda p: scan_port(p, ip, timeout=port_timeout), PORTS)

        for port in results_iter:
            if port:
                open_ports.append(port)

        result["open_ports"][ip] = open_ports

        if open_ports:
            print(f"{GREEN}[+] Open ports: {open_ports}{RESET}")
        else:
            error("No open ports found.", colored=False)

    return result


def main(target: str) -> dict[str, Any]:
    return scan_target(target)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        error("Please enter target", colored=False)
        sys.exit(1)
    main(sys.argv[1])

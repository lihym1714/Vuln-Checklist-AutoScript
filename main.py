import subprocess
import sys
from urllib.parse import urlparse

from information_scrp import important_search, major_dir_file, cookie_scan


def read_targets(file_path: str) -> list[str]:
    with open(file_path, "r") as f:
        return [line.strip() for line in f if line.strip()]


def normalize_url(value: str) -> str:
    if value.startswith("http://") or value.startswith("https://"):
        return value
    return f"http://{value}"


def extract_host(value: str) -> str:
    parsed = urlparse(normalize_url(value))
    return parsed.hostname or value


def run_port_scan(host: str) -> str:
    result = subprocess.run(
        [sys.executable, "information_scrp/port_scan.py", host],
        capture_output=True,
        text=True,
    )
    output = (result.stdout or "").strip()
    if output:
        return output
    return (result.stderr or "").strip()


def action_major_dir_file(url: str) -> None:
    major_dir_file.main(url)


def action_important_search(url: str) -> None:
    important_search.main(url)


def action_port_scan(url: str) -> None:
    port_scan_output = run_port_scan(extract_host(url))
    if port_scan_output:
        print(port_scan_output)


def action_cookie_scan(url: str) -> None:
    cookie_scan.main([url])


def main(targets_path: str) -> None:
    for target in read_targets(targets_path):
        main_process(target)


def main_process(target: str) -> None:
    url = normalize_url(target)
    action_major_dir_file(url)
    action_important_search(url)
    action_port_scan(url)
    action_cookie_scan(url)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python main.py <targets_file>")
        sys.exit(1)
    else:
        main(sys.argv[1])

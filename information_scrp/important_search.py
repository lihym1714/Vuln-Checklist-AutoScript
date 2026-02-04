import re
import sys
from pathlib import Path
from typing import Dict, List

import requests

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from logging_utils import info, success, error


PATTERNS: Dict[str, str] = {
    "Email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-z]{2,}",
    "AWS Key": r"AKIA[0-9A-Z]{16}",
    "JWT Token": r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9._-]{10,}\.[a-zA-Z0-9._-]{10,}",
    "File Path": r"(\/[a-zA-Z0-9_\-]+)+\.[a-zA-Z]{2,4}",
    "Error Message": r"(Exception|Traceback|SQL syntax|ORA-\d+|Warning:)"
}

REQUEST_TIMEOUT: int = 10
MAX_MATCHES_DISPLAY: int = 3


# 헤더 확인
def check_headers(resp: requests.Response) -> None:
    for key, value in resp.headers.items():
        if "server" in key.lower() or "powered" in key.lower():
            success(f"Header Info: {key}: {value}")
            # 버전 정보 추출
            version = re.findall(r"\d+\.\d+(\.\d+)?", value)
            if version:
                success(f"{key} Version Info: {', '.join(version)}")


def normalize_url(url: str) -> str:
    if not url.startswith("http://") and not url.startswith("https://"):
        return f"http://{url}"
    return url


# 바디 검사
def main(url: str) -> None:
    normalized_url = normalize_url(url)
    info(f"Checking important information for {normalized_url}")

    try:
        headers = {"User-Agent": "Mozilla/5.0 (compatible; VCLAS/1.0)"}
        resp = requests.get(normalized_url, headers=headers, timeout=REQUEST_TIMEOUT)
        success(f"Status Code: {resp.status_code}")

        if resp.status_code >= 400:
            error(f"HTTP Error: {resp.status_code} - {resp.reason}")
            return

        check_headers(resp)
        body = resp.text

        for name, pattern in PATTERNS.items():
            matches: List[str] = re.findall(pattern, body)
            if matches:
                success(f"{name} Exposure Detected: {matches[:MAX_MATCHES_DISPLAY]}")

    except requests.exceptions.Timeout:
        error(f"Request timeout after {REQUEST_TIMEOUT}s for {normalized_url}")
    except requests.exceptions.ConnectionError:
        error(f"Connection failed for {normalized_url}")
    except requests.exceptions.RequestException as e:
        error(f"Request error for {normalized_url}: {e}")
    except Exception as e:
        error(f"Unexpected error: {e}")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        main(sys.argv[1])
    else:
        print("Usage: python important_search.py <http|https://example.com/>")
        sys.exit(1)

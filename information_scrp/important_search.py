import re
import sys
from pathlib import Path
from typing import Dict, List

from typing import Any

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


def extract_headers_info(resp: requests.Response) -> List[Dict[str, Any]]:
    header_infos: List[Dict[str, Any]] = []
    for key, value in resp.headers.items():
        if "server" in key.lower() or "powered" in key.lower():
            value_str = str(value)
            success(f"Header Info: {key}: {value_str}")

            # 버전 정보 추출
            versions = re.findall(r"\d+\.\d+(\.\d+)?", value_str)
            if versions:
                success(f"{key} Version Info: {', '.join(versions)}")

            header_infos.append({
                "header": key,
                "value": value_str,
                "versions": versions,
            })
    return header_infos


def normalize_url(url: str) -> str:
    if not url.startswith("http://") and not url.startswith("https://"):
        return f"http://{url}"
    return url


def scan(url: str) -> Dict[str, Any]:
    normalized_url = normalize_url(url)
    info(f"Checking important information for {normalized_url}")

    result: Dict[str, Any] = {
        "url": normalized_url,
        "status_code": None,
        "header_infos": [],
        "exposures": {},
        "error": None,
    }

    try:
        headers = {"User-Agent": "Mozilla/5.0 (compatible; VCLAS/1.0)"}
        resp = requests.get(normalized_url, headers=headers, timeout=REQUEST_TIMEOUT)
        success(f"Status Code: {resp.status_code}")

        result["status_code"] = resp.status_code

        if resp.status_code >= 400:
            msg = f"HTTP Error: {resp.status_code} - {resp.reason}"
            error(msg)
            result["error"] = msg
            return result

        result["header_infos"] = extract_headers_info(resp)
        body = resp.text

        for name, pattern in PATTERNS.items():
            matches: List[str] = re.findall(pattern, body)
            if matches:
                success(f"{name} Exposure Detected: {matches[:MAX_MATCHES_DISPLAY]}")
                result["exposures"][name] = matches

        return result

    except requests.exceptions.Timeout:
        msg = f"Request timeout after {REQUEST_TIMEOUT}s for {normalized_url}"
        error(msg)
        result["error"] = msg
    except requests.exceptions.ConnectionError:
        msg = f"Connection failed for {normalized_url}"
        error(msg)
        result["error"] = msg
    except requests.exceptions.RequestException as e:
        msg = f"Request error for {normalized_url}: {e}"
        error(msg)
        result["error"] = msg
    except Exception as e:
        msg = f"Unexpected error: {e}"
        error(msg)
        result["error"] = msg

    return result


def main(url: str) -> Dict[str, Any]:
    return scan(url)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        main(sys.argv[1])
    else:
        print("Usage: python important_search.py <http|https://example.com/>")
        sys.exit(1)

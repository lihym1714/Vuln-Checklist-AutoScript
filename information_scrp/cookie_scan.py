import argparse
import csv
import json
import sys
from pathlib import Path
from typing import List, Dict, Tuple

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import requests

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from logging_utils import info, success, error, GREEN, RED, RESET

MFA_KEYWORDS = ["mfa", "2fa", "otp", "authenticator", "verification code", "2-step", "2factor"]


def safe_to_str(value) -> str:
    if value is None:
        return ""
    try:
        if isinstance(value, bytes):
            return value.decode(errors="ignore")
        return str(value)
    except Exception:
        return ""


def extract_all_cookies(resp) -> List[Dict]:
    cookies = []
    for key, value in resp.headers.items():
        if "cookie" in key.lower():
            header_str = safe_to_str(value)
            parts = [p.strip() for p in header_str.split(";")]
            for part in parts:
                if "=" in part:
                    k, v = part.split("=", 1)
                    cookies.append({
                        "name": k.strip(),
                        "value": v.strip(),
                        "raw_header": key,
                    })
                else:
                    cookies.append({
                        "name": part,
                        "value": None,
                        "raw_header": key,
                    })
    return cookies


def detect_mfa(resp) -> bool:
    body = safe_to_str(resp.text).lower()
    if any(k in body for k in MFA_KEYWORDS):
        return True
    if "location" in resp.headers:
        loc = safe_to_str(resp.headers["Location"]).lower()
        if any(k in loc for k in MFA_KEYWORDS):
            return True
    return False


def scan_url(url: str, timeout: float = 5.0) -> Tuple[List[Dict], bool]:
    try:
        resp = requests.get(url, timeout=timeout, allow_redirects=True, verify=False)
    except Exception as e:
        error(f"요청 실패: {e}")
        return [], False

    cookies_info = extract_all_cookies(resp)
    mfa = detect_mfa(resp)
    return cookies_info, mfa


def save_json(path: str, cookies: List[Dict], mfa: bool):
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"cookies": cookies, "mfa_detected": mfa}, f, ensure_ascii=False, indent=2)

def save_csv(path: str, cookies: List[Dict], mfa: bool):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["name", "value", "raw_header"])
        for c in cookies:
            w.writerow([c["name"], c["value"], c["raw_header"]])
        w.writerow([])
        w.writerow(["MFA Detected", mfa])


def parse_args(argv: List[str]):
    p = argparse.ArgumentParser(description="All Cookies + MFA Scanner")
    p.add_argument("url", help="Target URL (ex: https://example.com/login)")
    p.add_argument("--timeout", type=float, default=5.0, help="Request timeout (seconds)")

    out = p.add_mutually_exclusive_group()
    out.add_argument("--json", action="store_true", help="Output results as JSON")
    out.add_argument("--csv", action="store_true", help="Output results as CSV")
    p.add_argument("-o", "--output", help="Output file path")
    return p.parse_args(argv)

def main(argv: List[str]) -> int:
    args = parse_args(argv)
    url = args.url

    info(f"Checking Cookie & MFA for {url}")

    cookies, mfa = scan_url(url, timeout=args.timeout)

    if args.json:
        if args.output:
            save_json(args.output, cookies, mfa)
        print(json.dumps({"cookies": cookies, "mfa_detected": mfa}, ensure_ascii=False, indent=2))
    elif args.csv:
        if args.output:
            save_csv(args.output, cookies, mfa)
        else:
            success("CSV output requires --output option.", colored=False)
    else:
        print()
        success(f"Target: {url}")
        success(f"Cookies found: {len(cookies)}")
        for c in cookies:
            print(f"{GREEN}- {c['name']}{RESET}")
            print(f"    value       = {c['value']}")
            print(f"    raw_header  = {c['raw_header']}")
            print()
        mfa_status = f"{GREEN}Detected{RESET}" if mfa else f"{RED}Not Detected{RESET}"
        success(f"Estimated MFA: {mfa_status}", colored=False)

        if args.output:
            save_json(args.output, cookies, mfa)
            success(f"JSON saved: {args.output}")

    return 0

if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except KeyboardInterrupt:
        error("User interrupted")
        sys.exit(130)

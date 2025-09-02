#!/usr/bin/env python3
"""
cookie_mfa_scanner.py — 웹 애플리케이션의 보안 속성 수집기

특정 도메인/URL을 입력하면:
  1) 응답 헤더의 Set-Cookie를 파싱하여 쿠키 속성(Secure, HttpOnly, SameSite 등) 수집
  2) HTML/리다이렉션에서 MFA(다중 인증) 관련 키워드 추정 검출
  3) JSON 또는 CSV로 결과 저장 가능

의존성:
  pip install requests

사용 예시:
  $ python cookie_mfa_scanner.py https://example.com
  $ python cookie_mfa_scanner.py https://example.com/login --json -o result.json
  $ python cookie_mfa_scanner.py https://example.com --csv -o cookies.csv

주의: 본인 소유/허가된 시스템에서만 사용하세요.
"""
import urllib3
import argparse
import csv
import json
import sys
import urllib.parse
from http.cookies import SimpleCookie
from typing import List, Dict, Tuple

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import requests

GREEN = "\033[32m"
RED = "\033[31m"
RESET = "\033[0m"

MFA_KEYWORDS = [
    "mfa", "2fa", "otp", "authenticator", "verification code", "2-step", "2factor"
]


def safe_to_str(value) -> str:
    """유니코드/바이너리 응답을 안전하게 문자열로 변환"""
    if value is None:
        return ""
    try:
        if isinstance(value, bytes):
            return value.decode(errors="ignore")
        return str(value)
    except Exception:
        return ""


def analyze_cookies(set_cookie_headers: List[str], host: str) -> List[Dict]:
    results = []
    for header in set_cookie_headers:
        header_str = safe_to_str(header)
        sc = SimpleCookie()
        sc.load(header_str)

        for name, morsel in sc.items():
            # 기본 정보
            cookie_info = {
                "cookie": name,
                "domain": morsel["domain"] or host,
                "path": morsel["path"] or "/",
                "secure": False,
                "httponly": False,
                "samesite": None,
                "expires": morsel["expires"] or None,
                "max-age": None,
                "partitioned": False,
            }

            # 속성 분석 (RFC6265 기준)
            parts = header_str.split(";")
            for part in parts[1:]:
                token = part.strip()
                low = token.lower()
                if low == "secure":
                    cookie_info["secure"] = True
                elif low == "httponly":
                    cookie_info["httponly"] = True
                elif low.startswith("samesite"):
                    cookie_info["samesite"] = token.split("=", 1)[-1].strip()
                elif low.startswith("expires"):
                    cookie_info["expires"] = token.split("=", 1)[-1].strip()
                elif low.startswith("max-age"):
                    cookie_info["max-age"] = token.split("=", 1)[-1].strip()
                elif low == "partitioned":
                    cookie_info["partitioned"] = True
                elif low.startswith("domain") and not morsel["domain"]:
                    cookie_info["domain"] = token.split("=", 1)[-1].strip()
                elif low.startswith("path") and not morsel["path"]:
                    cookie_info["path"] = token.split("=", 1)[-1].strip()

            results.append(cookie_info)
    return results



def detect_mfa(resp: requests.Response) -> bool:
    body = safe_to_str(resp.text).lower()
    for keyword in MFA_KEYWORDS:
        if keyword in body:
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
        print(f"[-] 요청 실패: {e}")
        return [], False

    set_cookie_headers = resp.headers.get("Set-Cookie")
    cookies_info: List[Dict] = []
    if set_cookie_headers:
        if isinstance(set_cookie_headers, str):
            set_cookie_headers = [set_cookie_headers]
        cookies_info = analyze_cookies(set_cookie_headers, urllib.parse.urlparse(url).hostname)

    mfa = detect_mfa(resp)
    return cookies_info, mfa


def save_json(path: str, cookies: List[Dict], mfa: bool):
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"cookies": cookies, "mfa_detected": mfa}, f, ensure_ascii=False, indent=2)


def save_csv(path: str, cookies: List[Dict], mfa: bool):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["cookie", "domain", "path", "secure", "httponly", "samesite", "expires"])
        for c in cookies:
            w.writerow([c["cookie"], c["domain"], c["path"], c["secure"], c["httponly"], c["samesite"], c["expires"]])
        w.writerow([])
        w.writerow(["MFA Detected", mfa])


def parse_args(argv: List[str]):
    p = argparse.ArgumentParser(description="Cookie Properties + MFA Detection Scanner")
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

    cookies, mfa = scan_url(url, timeout=args.timeout)

    if args.json:
        if args.output:
            save_json(args.output, cookies, mfa)
        print(json.dumps({"cookies": cookies, "mfa_detected": mfa}, ensure_ascii=False, indent=2))

    elif args.csv:
        if args.output:
            save_csv(args.output, cookies, mfa)
        else:
            print("[+] CSV output requires --output option.")

    else:
        print(f"[+] Target: {url}")
        print(f"[+] Cookies found: {len(cookies)}")
        for c in cookies:
            print(f"{GREEN}- {c['cookie']}{RESET}")
            print(f"    domain      = {c['domain']}")
            print(f"    path        = {c['path']}")
            print(f"    secure      = {c['secure']}")
            print(f"    httponly    = {c['httponly']}")
            print(f"    samesite    = {c['samesite']}")
            print(f"    expires     = {c['expires']}")
            print(f"    max-age     = {c['max-age']}")
            print(f"    partitioned = {c['partitioned']}")
            print()

        print(f"[+] Estimated MFA: {f'{GREEN}Detected{RESET}' if mfa else f'{RED}Not Detected{RESET}'}")

        if args.output:
            save_json(args.output, cookies, mfa)
            print(f"[+] JSON saved: {args.output}")

    return 0



if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except KeyboardInterrupt:
        print("\n[-] User interrupted")
        sys.exit(130)

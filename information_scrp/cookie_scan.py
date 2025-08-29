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
import argparse
import csv
import json
import sys
import urllib.parse
from http.cookies import SimpleCookie
from typing import List, Dict, Tuple

import requests

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
            results.append({
                "cookie": name,
                "domain": morsel["domain"] or host,
                "path": morsel["path"] or "/",
                "secure": "secure" in header_str.lower(),
                "httponly": "httponly" in header_str.lower(),
                "samesite": morsel["samesite"] or ("samesite" in header_str.lower() and header_str.split("SameSite=")[-1].split(";")[0]),
                "expires": morsel["expires"] or None,
            })
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
    p = argparse.ArgumentParser(description="쿠키 속성 + MFA 감지 스캐너")
    p.add_argument("url", help="대상 URL (예: https://example.com/login)")
    p.add_argument("--timeout", type=float, default=5.0, help="요청 타임아웃 (초)")

    out = p.add_mutually_exclusive_group()
    out.add_argument("--json", action="store_true", help="JSON으로 결과 출력")
    out.add_argument("--csv", action="store_true", help="CSV로 결과 출력")
    p.add_argument("-o", "--output", help="출력 파일 경로")
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
            print("[+] CSV 출력은 --output 필요")
    else:
        print(f"[+] 대상: {url}")
        print(f"[+] 쿠키 발견: {len(cookies)}개")
        for c in cookies:
            print(f"- {c['cookie']} (domain={c['domain']}, secure={c['secure']}, httponly={c['httponly']}, samesite={c['samesite']})")
        print(f"[+] MFA 적용 추정: {'예' if mfa else '미검출'}")

        if args.output:
            save_json(args.output, cookies, mfa)
            print(f"[+] JSON 저장 완료: {args.output}")

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except KeyboardInterrupt:
        print("\n[-] 사용자 중단")
        sys.exit(130)

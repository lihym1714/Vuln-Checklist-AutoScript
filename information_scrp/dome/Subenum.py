#!/usr/bin/env python3
"""
subenum.py — 간단하지만 실전형 서브도메인 스캐너

특정 도메인을 입력하면 다음을 수행합니다:
  1) 워드리스트 기반 브루트포스(병렬 해석)
  2) 와일드카드 DNS 감지 및 노이즈 필터링
  3) (옵션) crt.sh를 통한 CT 로그 기반 패시브 수집
  4) (옵션) HTTP/HTTPS 가용성(HEAD) 프로빙
  5) 결과를 콘솔, JSON, CSV로 저장 가능

의존성(선택):
  - requests (패시브 수집 및 HTTP 프로빙 시 권장)
  - certifi (HTTPS 검증 안정성)

표준 라이브러리만으로도 DNS 해석은 동작합니다(시스템 리졸버 사용).

사용 예시:
  $ python subenum.py example.com
  $ python subenum.py example.com -w subdomains.txt -t 300 -o result.json --json
  $ python subenum.py example.com --passive crtsh --probe --ports 80,443,8080
    
"""
from __future__ import annotations
import argparse
import concurrent.futures as cf
import contextlib
import csv
import ipaddress
import json
import os
import random
import socket
import string
import sys
import time
from dataclasses import dataclass, asdict
from typing import Iterable, List, Optional, Set, Tuple

try:
    import requests  # type: ignore
except Exception:  # pragma: no cover
    requests = None  # requests가 없으면 패시브/프로빙 기능 일부 제한

# ---- 기본 내장 워드리스트(경량) ----
DEFAULT_WORDS = (
    "www api dev test stage staging prod production beta alpha admin portal cdn img static media files mail smtp pop imap vpn sso auth login blog wiki help docs status m mobile mta ftp ns1 ns2 dns1 dns2 gateway gw proxy router git gitlab github ci cd jenkins build infra internal intranet qa uat preview edge cache assets shop store payments billing pay s3 oos oss bucket downloads dl node app backend frontend web nginx apache mysql db redis kafka mq rabbit elastic es log graylog grafana prometheus metrics monitor monitoring kibana search seo tracking analytics pixel click collector ad ads adserver api1 api2 api3 v1 v2 v3 site1 site2 legacy old new sandbox demo trial customer client partner vendor office corp global hk jp kr us eu de fr uk ca au sg in br ru cn".split()
)

# ---- 데이터 모델 ----
@dataclass
class Finding:
    host: str
    addresses: List[str]
    is_wildcard: bool
    http_open: Optional[bool] = None
    http_status: Optional[int] = None
    https_open: Optional[bool] = None
    https_status: Optional[int] = None

# ---- 유틸 ----

def chunked(iterable: Iterable[str], size: int) -> Iterable[List[str]]:
    batch = []
    for item in iterable:
        batch.append(item)
        if len(batch) >= size:
            yield batch
            batch = []
    if batch:
        yield batch

def dedupe(seq: Iterable[str]) -> List[str]:
    s: Set[str] = set()
    out: List[str] = []
    for x in seq:
        if x not in s:
            s.add(x)
            out.append(x)
    return out

# ---- DNS 관련 ----

def resolve_host(host: str, timeout: float = 2.5) -> List[str]:
    """시스템 리졸버로 A/AAAA 조회. 해석 실패 시 빈 리스트."""
    try:
        # getaddrinfo가 CNAME 체인을 따라가며 A/AAAA를 반환
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP, timeout=timeout)
        addrs = sorted({info[4][0] for info in infos if info and info[4]})
        # IPv6이 너무 많으면 축약
        return addrs
    except Exception:
        return []

@contextlib.contextmanager
def resolver_timeout(seconds: float):
    # socket에 전역 타임아웃 적용
    old = socket.getdefaulttimeout()
    socket.setdefaulttimeout(seconds)
    try:
        yield
    finally:
        socket.setdefaulttimeout(old)

def detect_wildcard(domain: str, tries: int = 3, timeout: float = 2.5) -> Set[str]:
    """랜덤 서브도메인을 조회하여 와일드카드 응답 IP set을 추정."""
    wc_ips: Set[str] = set()
    with resolver_timeout(timeout):
        for _ in range(tries):
            label = ''.join(random.choice(string.ascii_lowercase) for _ in range(16))
            host = f"{label}.{domain}"
            addrs = resolve_host(host, timeout=timeout)
            for a in addrs:
                wc_ips.add(a)
    return wc_ips

# ---- 패시브 소스 ----

def from_crtsh(domain: str, timeout: float = 8.0) -> List[str]:
    """crt.sh에서 하위 도메인 후보 수집. requests가 없으면 빈 리스트 반환."""
    if requests is None:
        return []
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        r = requests.get(url, timeout=timeout, headers={"User-Agent": "subenum/1.0"})
        if r.status_code != 200:
            return []
        data = r.json()
        names: Set[str] = set()
        for row in data:
            name_value = row.get("name_value", "")
            for n in name_value.split("\n"):
                n = n.strip().lower()
                if n.endswith(f".{domain}") or n == domain:
                    names.add(n)
        return sorted(names)
    except Exception:
        return []

# ---- HTTP 프로빙 ----

def probe_http(host: str, ports: List[int], timeout: float = 3.0) -> Tuple[Optional[Tuple[bool,int]], Optional[Tuple[bool,int]]]:
    """HEAD 요청으로 HTTP/HTTPS 가용성 확인. (requests 필요)"""
    if requests is None:
        return (None, None)
    http_res: Optional[Tuple[bool,int]] = None
    https_res: Optional[Tuple[bool,int]] = None
    for p in ports:
        # 먼저 HTTPS 시도
        if https_res is None:
            with contextlib.suppress(Exception):
                resp = requests.head(f"https://{host}:{p}", timeout=timeout, allow_redirects=True)
                https_res = (True, resp.status_code)
        # HTTP 시도
        if http_res is None:
            with contextlib.suppress(Exception):
                resp = requests.head(f"http://{host}:{p}", timeout=timeout, allow_redirects=True)
                http_res = (True, resp.status_code)
        if http_res and https_res:
            break
    return http_res, https_res

# ---- 메인 스캐닝 로직 ----

def enumerate_subdomains(
    domain: str,
    words: List[str],
    threads: int = 200,
    timeout: float = 2.5,
    use_passive: bool = False,
    probe: bool = False,
    ports: Optional[List[int]] = None,
) -> List[Finding]:
    ports = ports or [80, 443]

    # 후보 생성
    candidates = [f"{w.strip().lower()}.{domain}" for w in words if w.strip()]
    candidates = dedupe(candidates)

    # 패시브 소스 추가
    if use_passive:
        passive = from_crtsh(domain)
        candidates = dedupe(list(candidates) + passive)

    # 와일드카드 감지
    wildcard_ips = detect_wildcard(domain, tries=3, timeout=timeout)

    findings: List[Finding] = []

    def worker(host: str) -> Optional[Finding]:
        addrs = resolve_host(host, timeout=timeout)
        if not addrs:
            return None
        # 와일드카드 필터: 응답 IP가 전부 와일드카드 집합과 동일하면 제외
        is_wc = False
        if wildcard_ips:
            if set(addrs).issubset(wildcard_ips):
                is_wc = True
        f = Finding(host=host, addresses=addrs, is_wildcard=is_wc)
        if (not is_wc) and probe:
            http_res, https_res = probe_http(host, ports=ports)
            if http_res:
                f.http_open, f.http_status = http_res
            if https_res:
                f.https_open, f.https_status = https_res
        return f

    with cf.ThreadPoolExecutor(max_workers=max(4, threads)) as ex:
        for res in ex.map(worker, candidates, chunksize=64):
            if res is not None and not res.is_wildcard:
                findings.append(res)

    # 호스트명 알파벳 정렬
    findings.sort(key=lambda x: x.host)
    return findings

# ---- 입출력 ----

def load_words(wordlist: Optional[str]) -> List[str]:
    if wordlist and os.path.isfile(wordlist):
        with open(wordlist, "r", encoding="utf-8", errors="ignore") as f:
            words = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        return words
    return list(DEFAULT_WORDS)


def save_json(path: str, findings: List[Finding]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump([asdict(x) for x in findings], f, ensure_ascii=False, indent=2)


def save_csv(path: str, findings: List[Finding]) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["host", "addresses", "http_open", "http_status", "https_open", "https_status"])
        for x in findings:
            w.writerow([
                x.host,
                ";".join(x.addresses),
                x.http_open if x.http_open is not None else "",
                x.http_status if x.http_status is not None else "",
                x.https_open if x.https_open is not None else "",
                x.https_status if x.https_status is not None else "",
            ])


# ---- CLI ----

def parse_args(argv: List[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="서브도메인 스캐너")
    p.add_argument("domain", help="대상 도메인 (예: example.com)")
    p.add_argument("-w", "--wordlist", help="워드리스트 파일 경로", default=None)
    p.add_argument("-t", "--threads", help="동시 스레드 수", type=int, default=200)
    p.add_argument("--timeout", help="DNS 타임아웃(초)", type=float, default=2.5)
    p.add_argument("--passive", choices=["crtsh"], help="패시브 소스 사용", default=None)
    p.add_argument("--probe", action="store_true", help="HTTP/HTTPS 프로빙 수행(HEAD)")
    p.add_argument("--ports", default="80,443", help="프로빙 포트 목록 (쉼표 구분)")

    out = p.add_mutually_exclusive_group()
    out.add_argument("--json", action="store_true", help="JSON으로 결과 출력")
    out.add_argument("--csv", action="store_true", help="CSV로 결과 출력")
    p.add_argument("-o", "--output", help="출력 파일 경로", default=None)
    return p.parse_args(argv)


def main(argv: List[str]) -> int:
    args = parse_args(argv)
    domain = args.domain.strip().lower()

    words = load_words(args.wordlist)
    use_passive = args.passive == "crtsh"
    ports = [int(x) for x in str(args.ports).split(",") if x.strip().isdigit()]

    start = time.time()
    findings = enumerate_subdomains(
        domain=domain,
        words=words,
        threads=args.threads,
        timeout=args.timeout,
        use_passive=use_passive,
        probe=args.probe,
        ports=ports,
    )
    elapsed = time.time() - start

    # 출력
    if args.json:
        data = [asdict(x) for x in findings]
        text = json.dumps(data, ensure_ascii=False, indent=2)
        if args.output:
            save_json(args.output, findings)
        print(text)
    elif args.csv:
        if args.output:
            save_csv(args.output, findings)
        # 콘솔에는 간단 출력
        for x in findings:
            print(f"{x.host}, {','.join(x.addresses)}")
    else:
        # 사람이 읽기 쉬운 출력
        print(f"[+] 대상: {domain}")
        print(f"[+] 후보 개수: {len(load_words(args.wordlist))} (패시브={'ON' if use_passive else 'OFF'})")
        print(f"[+] 발견: {len(findings)}개 (경과 {elapsed:.2f}s)\n")
        for f in findings:
            line = f"- {f.host:40s} {','.join(f.addresses)}"
            if args.probe:
                tags = []
                if f.http_open:
                    tags.append(f"http:{f.http_status}")
                if f.https_open:
                    tags.append(f"https:{f.https_status}")
                if tags:
                    line += "  [" + ", ".join(tags) + "]"
            print(line)

    if args.output and not (args.json or args.csv):
        # 사람이 읽기 쉬운 출력만 선택했고 파일 경로를 준 경우 JSON으로 별도 저장
        save_json(args.output, findings)
        print(f"\n[+] JSON으로 저장: {args.output}")

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except KeyboardInterrupt:
        print("\n[-] 사용자 중단")
        sys.exit(130)

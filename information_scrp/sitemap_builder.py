#!/usr/bin/env python3
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import re
import sys
import urllib.parse
import requests
from collections import deque

# 제외할 키워드 (여기에 원하는 키워드를 넣으면 해당 URL은 트리에 포함되지 않음)
EXCLUDE_KEYWORDS = ["github", "linkedin", "facebook", "twitter", "instagram", "youtube", "javascript:", "google"]

URL_PATTERN = re.compile(r'href=["\'](.*?)["\']', re.IGNORECASE)

output_file = "data/sitemap_tree.txt"

def extract_urls(base_url: str, body: str):
    # HTML 바디에서 URL 추출 후 절대경로 변환
    found = []
    for match in URL_PATTERN.findall(body):
        if match.startswith("#") or match.startswith("javascript:") or match.startswith("mailto:"):
            continue
        abs_url = urllib.parse.urljoin(base_url, match)
        # 필터링: 제외 키워드 포함된 URL은 건너뜀
        if any(keyword.lower() in abs_url.lower() for keyword in EXCLUDE_KEYWORDS):
            continue
        found.append(abs_url)
    return found

def crawl(start_url: str, max_depth: int = 3, timeout: float = 5.0):
    # start_url부터 sitemap 탐색 (트리 구조 유지)
    visited = set()
    queue = deque([(start_url, 0, None)])  # (url, depth, parent)
    tree = {}

    while queue:
        url, depth, parent = queue.popleft()
        if url in visited:
            continue
        # 필터링: 제외 키워드 포함된 URL이면 스킵
        if any(keyword.lower() in url.lower() for keyword in EXCLUDE_KEYWORDS):
            continue
        visited.add(url)

        # 트리 구조 삽입
        node = tree
        if parent:
            for p in parent:
                node = node.setdefault(p, {})
            node = node.setdefault(url, {})
        else:
            node.setdefault(url, {})

        if depth >= max_depth:
            continue

        try:
            resp = requests.get(url, timeout=timeout, verify=False)
            if "text/html" not in resp.headers.get("Content-Type", ""):
                continue
            body = resp.text
        except Exception as e:
            print(f"[-] Requests Failed: {url} ({e})")
            continue

        for new_url in extract_urls(url, body):
            if new_url not in visited:
                queue.append((new_url, depth + 1, (parent or []) + [url]))

    return tree

def print_tree(tree: dict, prefix: str = "", is_last: bool = True):
    """트리 구조 출력"""
    for i, (url, children) in enumerate(tree.items()):
        connector = "└── " if i == len(tree) - 1 else "├── "
        print(prefix + connector + url)
        new_prefix = prefix + ("    " if i == len(tree) - 1 else "│   ")
        print_tree(children, new_prefix, i == len(tree) - 1)

def save_tree_to_txt(tree: dict, file_path: str, prefix: str = "", is_last: bool = True):
    """트리 구조를 텍스트 파일로 저장"""
    with open(file_path, "w", encoding="utf-8") as f:
        def _write_tree(node, prefix, is_last):
            for i, (url, children) in enumerate(node.items()):
                connector = "└── " if i == len(node) - 1 else "├── "
                f.write(prefix + connector + url + "\n")
                new_prefix = prefix + ("    " if i == len(node) - 1 else "│   ")
                _write_tree(children, new_prefix, i == len(node) - 1)
        _write_tree(tree, prefix, is_last)

def main(start_url: str,max_depth=100):
    tree = crawl(start_url, max_depth=max_depth)

    print("\n[+] Sitemap Tree (Filtered):")
    print_tree(tree)

    if output_file:
        save_tree_to_txt(tree, output_file)
        print(f"[+] Tree data has been saved to {output_file}.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage : {sys.argv[0]} <start_url> [max_depth]")
        sys.exit(1)

    start_url = sys.argv[1]
    max_depth = int(sys.argv[2]) if len(sys.argv) > 2 else 2
    main(start_url, max_depth)

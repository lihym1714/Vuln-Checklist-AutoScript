import re
import requests
import sys


# 패턴 정의 (정규식 기반)
patterns = {
    "Email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-z]{2,}",
    "AWS Key": r"AKIA[0-9A-Z]{16}",
    "JWT Token": r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9._-]{10,}\.[a-zA-Z0-9._-]{10,}",
    "File Path": r"(\/[a-zA-Z0-9_\-]+)+\.[a-zA-Z]{2,4}",
    "Error Message": r"(Exception|Traceback|SQL syntax|ORA-\d+|Warning:)"
}


# 헤더 확인
def check_headers(resp):
    for key, value in resp.headers.items():
        if "server" in key.lower() or "powered" in key.lower():
            print(f"[+] Header Info: {key}: {value}")
            # 버전 정보 추출
            version = re.findall(r"\d+\.\d+(\.\d+)?", value)
            if version:
                print(f"[+] {key} Version Info: {', '.join(version)}")

# 바디 검사
def main(url):
    try:
        if not url.startswith("http://") and not url.startswith("https://"):
            url = "http://" + url  # 기본적으로 http로 시작
    except Exception as e:
        print(f"[-] Error processing URL: {e}")
        return
    try:
        resp = requests.get(url)
        print(f"[+] Status Code: {resp.status_code}")
        check_headers(resp)
        body = resp.text
        for name, pattern in patterns.items():
            matches = re.findall(pattern, body)
            if matches:
                print(f"[+] {name} Exposure Detected: {matches[:3]}")  # 일부만 출력
    except Exception as e:
        print(f"[-] Error during request: {e}")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        main(sys.argv[1])
    else:
        print("Usage: python important_search.py <http|https://example.com/>")
        sys.exit(1)
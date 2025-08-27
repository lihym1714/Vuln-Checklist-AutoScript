import subprocess

TARGET = "naver.com"

sysMsg = subprocess.getstatusoutput(f"nslookup {TARGET}")
print(sysMsg[1])
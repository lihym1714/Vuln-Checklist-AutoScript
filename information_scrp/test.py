import subprocess

TARGET = "example.com"

sysMsg = subprocess.getstatusoutput(f"nslookup {TARGET}")
print(sysMsg[1])

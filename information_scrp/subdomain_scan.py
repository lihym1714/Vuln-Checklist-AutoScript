import subprocess
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from logging_utils import info, error


def main(Target):
    info(f"Subdomain Scan for {Target}")
    domains = []
    sysMsg = subprocess.getstatusoutput(f"echo {Target} | subfinder -silent | httpx -silent -probe -title -status-code")
    domains.append(f"https://{Target}/")
    domains.append(f"http://{Target}/")
    if len(sysMsg[1]) == 0:
        error("No subdomains found.", colored=False)
    else:
        for i in sysMsg[1].split("\n"):
            print(i)
            domains.append(i.split(" ")[0])

    output_path = "data/subdomains.txt"
    if output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            for domain in domains:
                f.write(domain + "\n")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python subdomain_scan.py <domain>")
        sys.exit(1)
    else:
        main(sys.argv[1])
    

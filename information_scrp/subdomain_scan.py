import subprocess
import sys

def main(Target):
    domains = []
    sysMsg = subprocess.getstatusoutput(f"echo {Target} | subfinder -silent | httpx -silent -probe -title -status-code")
    domains.append(f"https://{Target}/")
    domains.append(f"http://{Target}/")
    if len(sysMsg[1]) == 0:
        print("[-] No subdomains found.")
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
    
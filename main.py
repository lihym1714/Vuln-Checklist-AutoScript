import subprocess
import sys
from information_scrp import important_search, major_dir_file, cookie_scan

def main(Targets):
    filename = Targets
    with open(filename, "r") as f:
        domains = [line.strip() for line in f if line.strip()]
    for Target in domains:
        main_process(Target)

def main_process(domain):
    print(f"========================================== {domain} ==========================================")
    print("========================================== Major Directory/File Search ==========================================")
    major_dir_file.main(domain)
    # print("========================================== Important Info Search ==========================================")
    # important_search.main(domain)
    print("========================================== Port Scan ==========================================")
    open_ports = subprocess.getstatusoutput(f"python3 information_scrp/port_scan.py {domain.split('//')[-1][:-1]}")
    print(open_ports[1])
    print("========================================== Cookie/MFA Scan ==========================================")
    cookie_scan.main([domain])

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python main.py <target>")
        sys.exit(1)
    else:
        main(sys.argv[1])
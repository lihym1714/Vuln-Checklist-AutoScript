#!/bin/bash

base_url="http://minpeter.uk/"  # 대상 base URL로 변경
domain="minpeter.uk"  # 대상 Domain로 변경

echo "========================================== Subdomain Scan =========================================="
echo $domain | subfinder -silent | httpx -silent -probe -title -status-code

echo "========================================== Dir/File Scan =========================================="
python information_scrp/public_dir_file.py "$base_url"

echo "========================================== Port Scan =========================================="
python information_scrp/port_scan.py "$domain"

echo "========================================== Cookie/MFA Scan =========================================="
python information_scrp/cookie_scan.py "$base_url"
#!/bin/bash

base_url="http://localhost:8000/"  # 대상 base URL로 변경
domain="everspin.global"  # 대상 Domain로 변경

echo "========================================== Dir/File Scan =========================================="
python information_scrp/public_dir_file.py "$base_url"

echo "========================================== Port Scan =========================================="
python information_scrp/port_scan.py "$domain"
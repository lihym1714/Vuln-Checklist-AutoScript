base_url="http://example.com/"  # Change to target base URL
domain="example.com"  # Change to target Domain

echo "========================================== Subdomain Scan =========================================="
echo $domain | subfinder -silent | httpx -silent -probe -title -status-code

echo "========================================== Dir/File Scan =========================================="
python information_scrp/public_dir_file.py "$base_url"

echo "========================================== Port Scan =========================================="
python information_scrp/port_scan.py "$domain"

echo "========================================== Cookie/MFA Scan =========================================="
python information_scrp/cookie_scan.py "$base_url"
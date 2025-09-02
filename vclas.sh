domain="everspin.global"  # Change to target Domain without Second Level Domain

sub_domain_path="data/subdomains.txt"  # Subdomain wordlist path - Fixed

mkdir -p "data/"

echo "========================================== Process Start =========================================="
echo "========================================== Subdomain Scan =========================================="
python information_scrp/subdomain_scan.py "$domain"

python main.py "$sub_domain_path"

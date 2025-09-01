import requests
import sys
from urllib.parse import urljoin

GREEN = "\033[32m"
RED = "\033[31m"
RESET = "\033[0m"

dir_paths = [
    'robots.txt', '.htaccess', 'admin/', 'login/', 'config.php', 'backup/', 'old/', 'test/', 'dev/', 'api/', 'private/', 'tmp/', 'data/', 
    'uploads/', 'files/', 'images/', 'css/', 'js/', '.git/', '.svn/', 'README.md', 'LICENSE', 'index.php', 'index.html', '/etc/passwd', 
    '/.env', 'wp-admin/', 'wp-login.php', 'xmlrpc.php', 'sitemap.xml', 'admin.php', 'user.php', 'dashboard/', 'setup/', 'install/', 
    'cgi-bin/', 'shell.php', 'phpinfo.php', 'info.php', 'db_backup/', 'database/', 'dump.sql', 'backup.sql', 'config.json', 'config.yaml', 
    'config.yml', 'settings.py', 'appsettings.json', 'web.config', 'package.json', 'composer.json', '.htpasswd', '.DS_Store', 'Thumbs.db',
    'etc/hosts', 'etc/shadow', 'var/log/', 'logs/', 'error.log', 'access.log', 'debug.log', 'mail/', 'inbox/', 'outbox/', 'archive/', 'oldsite/', 
    'newsite/', 'staging/', 'beta/', 'test.php', 'dev.php', 'temp/', 'temporary/', 'cache/', 'static/', 'media/', 'etc/nginx/', 'etc/apache2/', 
    'var/www/', 'srv/www/', 'home/user/', 'home/admin/', 'users/', 'admins/', 'members/', 'profiles/', 'account/', 'accounts/', 'auth/',
]

def main(base_url, paths=dir_paths):
    print(f"[*] Base Url: {base_url}")
    print(f"[*] {base_url} Information scrapping start.")
    results = []
    for path in paths:
        url = urljoin(base_url, path)
        try:
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                results.append(f"{GREEN}[+] {path}:\tResponse exist (200 OK){RESET}")
            else:
                results.append(f"[+] {path}:\tResponse code {response.status_code}")
        except requests.RequestException as e:
            results.append(f"[-] {path}: Request Failed ({e})")
    print("\n".join(results))

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python public_dir_file.py <http|https://example.com/> <optional:dir_paths>")
        sys.exit(1)
    main(sys.argv[1])
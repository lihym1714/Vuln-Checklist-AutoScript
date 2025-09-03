import requests
import sys
from urllib.parse import urljoin

GREEN = "\033[32m"
RED = "\033[31m"
RESET = "\033[0m"

admin_paths = [
    'admin/', 'administrator/', 'admin.php', 'admin.html', 'admin/login.php', 'admin/index.php', 'admin/dashboard.php', 'adminpanel/', 
    'admin_area/', 'admin_login/', 'adminsite/', 'adminconsole/', 'adminportal/', 'cpanel/', 'controlpanel/', 'manage/', 'management/', 
    'moderator/', 'mod/', 'superadmin/', 'root/', 'sysadmin/', 'systemadmin/', 'admin123/', 'admin2023/', 'admin2024/', 'admin_test/', 
    'admin_test.php',
    'wp-admin/', 'wp-login.php', 'login/', 'auth/', 'account/', 'accounts/', 'admins/',
]

site_map_paths = [
    'sitemap.xml', 'sitemap_index.xml', 'sitemap1.xml', 'sitemap-news.xml', 'sitemap-products.xml', 'sitemap-pages.xml', 'sitemap-posts.xml', 
    'sitemap-categories.xml', 'sitemap-tags.xml', 'sitemap-images.xml', 'sitemap-videos.xml', 'sitemap-articles.xml', 'sitemap-blogs.xml', 
    'sitemap-events.xml', 'sitemap-collections.xml', 'sitemap-feeds.xml', 'sitemap-2023.xml', 'sitemap-2024.xml', 'sitemap-1.xml', 'sitemap-2.xml',
]

server_paths = [
    'server-status', 'server-info', 'phpinfo.php', 'info.php', 'test.php', 'status.php', 'uptime.php', 'version.php', 'config.php', 
    'db_backup/', 'database/', 'dump.sql', 'backup.sql', 'logs/', 'error.log', 'access.log', 'debug.log', 'var/log/', 'mail/', 
    'inbox/', 'outbox/', 'archive/', 'etc/apache2/', 'etc/nginx/', 'var/www/', 'srv/www/', 'home/user/',
    '/etc/passwd', 'etc/hosts', 'etc/shadow', 'tmp/', 'temp/', 'temporary/', 'cache/', 'backup/', 'cgi-bin/',
]


settings_paths = [
    'config.php', 'config.json', 'config.yaml', 'config.yml', 'settings.py', 'appsettings.json', 'web.config', 'database.yml', 'database.php',
    '/.env', '.DS_Store', '.git/', '.svn/', 'account/', 'accounts/', 'auth/', 'login/', 'wp-login.php', 'wp-admin/',
]

misc_paths = [
    # 문서/메타파일
    'README.md', 'LICENSE', 'CHANGELOG.md', 'CONTRIBUTING.md', 'CODE_OF_CONDUCT.md', 'SECURITY.md', 'INSTALL.md', 'UPGRADE.md', 
    'AUTHORS.md', 'COPYING', 'Makefile', 'Dockerfile', 'Vagrantfile', 'Gemfile', 'Rakefile', 'Gruntfile.js', 'gulpfile.js', 'webpack.config.js', 
    'package.json', 'composer.json', 'Pipfile', 'requirements.txt', 'environment.yml', '.htaccess', '.htpasswd', 'robots.txt', 'favicon.ico', 
    'crossdomain.xml',
    # 개발/테스트용
    'test/', 'dev/', 'dev.php', 'old/', 'oldsite/', 'newsite/', 'staging/', 'beta/', 'setup/', 'install/', 'dashboard/', 'shell.php',
    # 프론트엔드/리소스
    'media/', 'files/', 'uploads/', 'images/', 'css/', 'js/', 'static/', 'data/',
    # 유저 관련
    'users/', 'user.php', 'profiles/', 'members/', 'home/admin/',
    # 기타 파일
    'index.php', 'index.html', 'Thumbs.db',
]


dir_paths = {"admin":admin_paths, "site_map":site_map_paths, "server":server_paths, "settings":settings_paths, "misc":misc_paths}



def main(base_url, paths=dir_paths):
    print(f"[*] Base Url: {base_url}")
    print(f"[*] {base_url} Information scrapping start.")
    for category, path_list in paths.items():
        print(f"[*] Checking paths in category '{category}' with {len(path_list)} entries...")
        results = []
        for path in path_list:
            url = urljoin(base_url, path)
            try:
                response = requests.get(url, timeout=5)
                if response.status_code == 200:
                    results.append(f"{GREEN}[+] {path}:\tResponse exist (200 OK){RESET}")
            except requests.RequestException as e:
                results.append(f"{RED}[-] {path}: Request Failed{RESET}")
        if len(results) == 0:
            print(f"{RED}[-] No interesting directories or files found.{RESET}")
        else:
            print("\n".join(results))

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python major_dir_file.py <http|https://example.com/> <optional:dir_paths>")
        sys.exit(1)
    main(sys.argv[1])
import requests
import sys
from pathlib import Path
from urllib.parse import urljoin
from typing import Any

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from logging_utils import info, success, error, GREEN, RED, RESET

admin_paths = [
    'admin/', 'administrator/', 'admin.php', 'admin.html', 'admin/login.php', 'admin/index.php', 'admin/dashboard.php', 'adminpanel/', 
    'admin_area/', 'admin_login/', 'adminsite/', 'adminconsole/', 'adminportal/', 'cpanel/', 'controlpanel/', 'manage/', 'management/', 
    'moderator/', 'mod/', 'superadmin/', 'root/', 'sysadmin/', 'systemadmin/', 'admin123/', 'admin2023/', 'admin2024/','admin2025/','admin2026/', 
    'admin_test/', 'admin_test.php',
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



def scan(base_url: str, paths: dict[str, list[str]] = dir_paths, *, timeout: float = 5.0) -> dict[str, Any]:
    info(f"Base Url: {base_url}")
    info(f"{base_url} Information scrapping start.")

    scan_result: dict[str, Any] = {
        "base_url": base_url,
        "timeout": timeout,
        "categories": [],
    }

    for category, path_list in paths.items():
        info(f"Checking paths in category '{category}' with {len(path_list)} entries...")
        results = []

        category_result: dict[str, Any] = {
            "category": category,
            "checked": len(path_list),
            "found": [],
            "errors": [],
        }

        for path in path_list:
            url = urljoin(base_url, path)
            try:
                response = requests.get(url, timeout=timeout)
                if response.status_code == 200:
                    results.append(f"{GREEN}[+] {path}:\tResponse exist (200 OK){RESET}")
                    category_result["found"].append(
                        {
                            "path": path,
                            "url": url,
                            "status_code": response.status_code,
                        }
                    )
            except requests.RequestException as e:
                results.append(f"{RED}[-] {path}: Request Failed{RESET}")

                # Keep the error details for the dashboard report.
                category_result["errors"].append(
                    {
                        "path": path,
                        "url": url,
                        "error": str(e),
                    }
                )
        if len(results) == 0:
            error("No interesting directories or files found.")
        else:
            print("\n".join(results))

        scan_result["categories"].append(category_result)

    return scan_result


def main(base_url: str, paths: dict[str, list[str]] = dir_paths):
    return scan(base_url, paths)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python major_dir_file.py <http|https://example.com/> <optional:dir_paths>")
        sys.exit(1)
    main(sys.argv[1])

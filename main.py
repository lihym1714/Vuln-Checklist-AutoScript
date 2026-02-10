import json
import sys
from datetime import datetime, timezone
from html import escape
from pathlib import Path
from urllib.parse import urlparse

from information_scrp import important_search, major_dir_file, cookie_scan, port_scan


def read_targets(file_path: str) -> list[str]:
    with open(file_path, "r") as f:
        raw = [line.strip() for line in f if line.strip()]

    def _canonicalize(value: str) -> str:
        parsed = urlparse(normalize_url(value))
        # Treat a bare root path as equivalent ("https://a/" -> "https://a").
        path = "" if parsed.path == "/" else (parsed.path or "")
        return parsed._replace(path=path).geturl()

    seen: set[str] = set()
    out: list[str] = []
    for value in raw:
        canon = _canonicalize(value)
        if canon in seen:
            continue
        seen.add(canon)
        out.append(canon)
    return out


def normalize_url(value: str) -> str:
    if value.startswith("http://") or value.startswith("https://"):
        return value
    return f"http://{value}"


def extract_host(value: str) -> str:
    parsed = urlparse(normalize_url(value))
    return parsed.hostname or value

ROOT_DIR = Path(__file__).resolve().parent
DATA_DIR = ROOT_DIR / "data"


def action_major_dir_file(url: str) -> dict:
    return major_dir_file.main(url)


def action_important_search(url: str) -> dict:
    return important_search.main(url)


def action_port_scan(url: str) -> dict:
    return port_scan.main(extract_host(url))


def action_cookie_scan(url: str) -> dict:
    cookies, mfa = cookie_scan.scan_and_render(url)
    return {
        "url": url,
        "cookies": cookies,
        "mfa_detected": mfa,
    }


def _write_json(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def _read_text_if_exists(path: Path, *, max_chars: int = 200_000) -> str | None:
    if not path.exists():
        return None
    content = path.read_text(encoding="utf-8", errors="replace")
    if len(content) > max_chars:
        return content[:max_chars] + "\n... (truncated)\n"
    return content


def _render_table(headers: list[str], rows: list[list[str]]) -> str:
    if not rows:
        return "<p class='muted'>No results.</p>"
    parts: list[str] = []
    parts.append("<div class='table-wrap'><table>")
    parts.append("<thead><tr>" + "".join(f"<th>{escape(h)}</th>" for h in headers) + "</tr></thead>")
    parts.append("<tbody>")
    for row in rows:
        parts.append("<tr>" + "".join(f"<td>{escape(cell)}</td>" for cell in row) + "</tr>")
    parts.append("</tbody></table></div>")
    return "".join(parts)


def _render_html_report(report: dict) -> str:
    generated_at = str(report.get("generated_at") or "")
    targets = report.get("targets") or []
    per_target = report.get("per_target") or []

    css = """
:root {
  --bg0: #0b0f19;
  --bg1: #0f172a;
  --card: rgba(255,255,255,.06);
  --card2: rgba(255,255,255,.09);
  --text: #e5e7eb;
  --muted: rgba(229,231,235,.65);
  --line: rgba(255,255,255,.12);
  --accent: #38bdf8;
  --accent2: #a78bfa;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  color: var(--text);
  background:
    radial-gradient(1100px 600px at 12% 10%, rgba(56,189,248,.18), transparent 60%),
    radial-gradient(900px 520px at 80% 12%, rgba(167,139,250,.16), transparent 55%),
    linear-gradient(180deg, var(--bg0), var(--bg1));
  font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, sans-serif;
}
header {
  padding: 22px 18px 12px;
  border-bottom: 1px solid var(--line);
  background: rgba(0,0,0,.12);
  backdrop-filter: blur(10px);
  position: sticky;
  top: 0;
  z-index: 20;
}
h1 {
  margin: 0;
  letter-spacing: .2px;
  font-size: 20px;
}
.meta { margin-top: 6px; color: var(--muted); font-size: 12px; }
main { padding: 16px 18px 42px; max-width: 1160px; margin: 0 auto; }
.grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
  gap: 12px;
  margin: 14px 0 16px;
}
.kpi {
  background: var(--card);
  border: 1px solid var(--line);
  border-radius: 14px;
  padding: 12px 12px;
}
.kpi .label { color: var(--muted); font-size: 12px; }
.kpi .value { margin-top: 6px; font-size: 18px; font-weight: 650; }
section {
  background: rgba(0,0,0,.10);
  border: 1px solid var(--line);
  border-radius: 16px;
  padding: 12px;
  margin: 12px 0;
}
section h2 { margin: 0 0 8px; font-size: 15px; }
details {
  background: var(--card);
  border: 1px solid var(--line);
  border-radius: 14px;
  padding: 10px 10px;
  margin: 10px 0;
}
summary { cursor: pointer; font-weight: 650; }
.muted { color: var(--muted); }
.badge {
  display: inline-block;
  padding: 1px 8px;
  border-radius: 999px;
  border: 1px solid var(--line);
  background: rgba(255,255,255,.06);
  color: var(--muted);
  font-size: 12px;
  margin-left: 8px;
}
.table-wrap { overflow-x: auto; border-radius: 12px; border: 1px solid var(--line); }
table { width: 100%; border-collapse: collapse; min-width: 540px; }
th, td { padding: 8px 10px; border-bottom: 1px solid var(--line); text-align: left; font-size: 13px; }
th { background: rgba(255,255,255,.06); color: var(--text); position: sticky; top: 0; }
tr:hover td { background: rgba(255,255,255,.04); }
code, pre { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }
pre {
  background: rgba(255,255,255,.04);
  border: 1px solid var(--line);
  border-radius: 14px;
  padding: 10px;
  overflow: auto;
  max-height: 420px;
}
@media (max-width: 640px) {
  header { position: static; }
  table { min-width: 420px; }
}
"""

    parts: list[str] = []
    parts.append("<!doctype html><html><head><meta charset='utf-8'>")
    parts.append("<meta name='viewport' content='width=device-width, initial-scale=1'>")
    parts.append("<title>VCLAS Results</title>")
    parts.append(f"<style>{css}</style></head><body>")

    parts.append("<header>")
    parts.append("<h1>Vuln-Checklist-AutoScript Results</h1>")
    parts.append(f"<div class='meta'>Generated at: <code>{escape(generated_at)}</code></div>")
    parts.append("</header>")

    parts.append("<main>")
    parts.append("<div class='grid'>")
    parts.append(f"<div class='kpi'><div class='label'>Targets</div><div class='value'>{len(targets)}</div></div>")
    parts.append(f"<div class='kpi'><div class='label'>Sections</div><div class='value'>5</div></div>")
    parts.append(f"<div class='kpi'><div class='label'>Targets File</div><div class='value'><code>{escape(str(report.get('targets_path') or ''))}</code></div></div>")
    parts.append("</div>")

    # Subdomains / Targets
    parts.append("<section id='subdomains'>")
    parts.append(f"<h2>Subdomains / Targets <span class='badge'>{len(targets)}</span></h2>")
    if targets:
        rows = [[t] for t in targets]
        parts.append(_render_table(["target"], rows))
    else:
        parts.append("<p class='muted'>No targets.</p>")
    parts.append("</section>")

    # Major Dir/File
    parts.append("<section id='major-dir-file'>")
    parts.append("<h2>Major Dir/File</h2>")
    for item in per_target:
        url = str(item.get("url") or item.get("target") or "")
        major = item.get("major_dir_file") or {}
        categories = major.get("categories") or []

        found_rows: list[list[str]] = []
        error_count = 0
        for cat in categories:
            cat_name = str(cat.get("category") or "")
            found = cat.get("found") or []
            errs = cat.get("errors") or []
            error_count += len(errs)
            for entry in found:
                found_rows.append([
                    cat_name,
                    str(entry.get("path") or ""),
                    str(entry.get("url") or ""),
                    str(entry.get("status_code") or ""),
                ])

        summary = f"{url}"
        badges = []
        if found_rows:
            badges.append(f"found: {len(found_rows)}")
        if error_count:
            badges.append(f"errors: {error_count}")
        badge_str = "".join(f"<span class='badge'>{escape(b)}</span>" for b in badges)

        parts.append("<details>")
        parts.append(f"<summary>{escape(summary)}{badge_str}</summary>")
        parts.append(_render_table(["category", "path", "url", "status"], found_rows))
        parts.append("</details>")
    parts.append("</section>")

    # Important Search
    parts.append("<section id='important-search'>")
    parts.append("<h2>Important Search</h2>")
    for item in per_target:
        url = str(item.get("url") or item.get("target") or "")
        imp = item.get("important_search") or {}
        status = imp.get("status_code")
        header_infos = imp.get("header_infos") or []
        exposures = imp.get("exposures") or {}

        exposure_rows: list[list[str]] = []
        for name, matches in exposures.items():
            matches_list = matches if isinstance(matches, list) else []
            sample = ", ".join(str(m) for m in matches_list[:5])
            exposure_rows.append([str(name), str(len(matches_list)), sample])

        header_rows: list[list[str]] = []
        for hi in header_infos:
            header_rows.append([
                str(hi.get("header") or ""),
                str(hi.get("value") or ""),
                ", ".join(str(v) for v in (hi.get("versions") or [])),
            ])

        badge_str = f"<span class='badge'>status: {escape(str(status))}</span>" if status is not None else ""
        parts.append("<details>")
        parts.append(f"<summary>{escape(url)}{badge_str}</summary>")
        parts.append("<h3 class='muted'>Header Info</h3>")
        parts.append(_render_table(["header", "value", "versions"], header_rows))
        parts.append("<h3 class='muted'>Exposures</h3>")
        parts.append(_render_table(["type", "count", "sample"], exposure_rows))
        parts.append("</details>")
    parts.append("</section>")

    # Port Scan
    parts.append("<section id='port-scan'>")
    parts.append("<h2>Port Scan</h2>")
    for item in per_target:
        host = str(item.get("host") or extract_host(str(item.get("url") or "")))
        port = item.get("port_scan") or {}
        ip_addrs = port.get("ip_addresses") or []
        open_ports = port.get("open_ports") or {}
        port_rows: list[list[str]] = []
        for ip in ip_addrs:
            ports = open_ports.get(ip) or []
            port_rows.append([str(ip), ", ".join(str(p) for p in ports) if ports else "-"])
        parts.append("<details>")
        parts.append(f"<summary>{escape(host)}<span class='badge'>ips: {len(ip_addrs)}</span></summary>")
        parts.append(_render_table(["ip", "open_ports"], port_rows))
        parts.append("</details>")
    parts.append("</section>")

    # Cookie Scan
    parts.append("<section id='cookie-scan'>")
    parts.append("<h2>Cookie & MFA</h2>")
    for item in per_target:
        url = str(item.get("url") or item.get("target") or "")
        cs = item.get("cookie_scan") or {}
        cookies = cs.get("cookies") or []
        mfa = bool(cs.get("mfa_detected"))
        cookie_rows: list[list[str]] = []
        for c in cookies:
            cookie_rows.append([
                str(c.get("name") or ""),
                str(c.get("value") or ""),
                str(c.get("raw_header") or ""),
            ])
        parts.append("<details>")
        parts.append(
            f"<summary>{escape(url)}<span class='badge'>cookies: {len(cookies)}</span><span class='badge'>mfa: {'yes' if mfa else 'no'}</span></summary>"
        )
        parts.append(_render_table(["name", "value", "raw_header"], cookie_rows))
        parts.append("</details>")
    parts.append("</section>")

    # Optional sitemap tree
    sitemap_text = report.get("sitemap_tree")
    if isinstance(sitemap_text, str) and sitemap_text.strip():
        parts.append("<section id='sitemap'>")
        parts.append("<h2>Sitemap Tree</h2>")
        parts.append(f"<pre>{escape(sitemap_text)}</pre>")
        parts.append("</section>")

    parts.append("</main></body></html>")
    return "".join(parts)


def main(targets_path: str) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    targets = read_targets(targets_path)
    per_target: list[dict] = []
    port_scan_cache: dict[str, dict] = {}
    for target in targets:
        per_target.append(main_process(target, port_scan_cache=port_scan_cache))

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "targets_path": targets_path,
        "targets": targets,
        "per_target": per_target,
        "sitemap_tree": _read_text_if_exists(DATA_DIR / "sitemap_tree.txt"),
    }

    _write_json(DATA_DIR / "results.json", report)
    (DATA_DIR / "results.html").write_text(_render_html_report(report), encoding="utf-8")

    # Convenience per-tool JSON files for dashboard sections.
    _write_json(DATA_DIR / "subdomains.json", {"targets": targets})
    _write_json(DATA_DIR / "major_dir_file.json", [t.get("major_dir_file") for t in per_target])
    _write_json(DATA_DIR / "important_search.json", [t.get("important_search") for t in per_target])
    _write_json(DATA_DIR / "port_scan.json", [t.get("port_scan") for t in per_target])
    _write_json(DATA_DIR / "cookie_scan.json", [t.get("cookie_scan") for t in per_target])


def main_process(target: str, *, port_scan_cache: dict[str, dict] | None = None) -> dict:
    url = normalize_url(target)

    major = action_major_dir_file(url)
    imp = action_important_search(url)
    host = extract_host(url)
    if port_scan_cache is not None and host in port_scan_cache:
        port = port_scan_cache[host]
    else:
        port = action_port_scan(url)
        if port_scan_cache is not None:
            port_scan_cache[host] = port
    cookie = action_cookie_scan(url)

    return {
        "target": target,
        "url": url,
        "host": host,
        "major_dir_file": major,
        "important_search": imp,
        "port_scan": port,
        "cookie_scan": cookie,
    }

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python main.py <targets_file>")
        sys.exit(1)
    else:
        main(sys.argv[1])

import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from logging_utils import info, error


TOTAL_TIMEOUT_SECONDS = 110
SUBFINDER_TIMEOUT_SECONDS = 55
HTTPX_TIMEOUT_SECONDS = 50


def _extract_domain(target: str) -> str:
    value = (target or "").strip()
    if not value:
        return ""
    if value.startswith("http://") or value.startswith("https://"):
        parsed = urlparse(value)
        return (parsed.hostname or "").strip()

    # If user passed something like example.com/path, keep only host-ish part.
    return value.split("/", 1)[0].strip()


def _run_cmd(args: list[str], *, timeout_seconds: float, stdin_text: str | None = None) -> tuple[int, str, str]:
    def _to_text(value: object) -> str:
        if value is None:
            return ""
        if isinstance(value, bytes):
            return value.decode(errors="replace")
        return str(value)

    try:
        result = subprocess.run(
            args,
            input=stdin_text,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
        return result.returncode, result.stdout or "", result.stderr or ""
    except FileNotFoundError:
        return 127, "", f"Command not found: {args[0]}"
    except subprocess.TimeoutExpired as e:
        stdout = _to_text(e.stdout)
        stderr = _to_text(e.stderr)
        return 124, stdout, f"Timeout after {timeout_seconds}s: {' '.join(args)}\n{stderr}".strip()


def _dedupe_keep_order(values: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for v in values:
        item = (v or "").strip()
        if not item or item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


def main(target: str) -> None:
    domain = _extract_domain(target)
    info(f"Subdomain Scan for {domain or target}")

    output_path = ROOT_DIR / "data" / "subdomains.txt"
    output_path.parent.mkdir(parents=True, exist_ok=True)

    start = time.monotonic()
    subdomains: list[str] = []

    if not domain:
        error("Invalid target domain.", colored=False)
    else:
        remaining = max(1.0, TOTAL_TIMEOUT_SECONDS - (time.monotonic() - start))
        subfinder_timeout = min(SUBFINDER_TIMEOUT_SECONDS, remaining)

        # No stdin piping: pass domain via -d/-domain argument.
        code, out, err = _run_cmd(
            ["subfinder", "-silent", "-d", domain],
            timeout_seconds=subfinder_timeout,
        )
        if code not in (0,):
            if err.strip():
                error(err.strip(), colored=False)
        subdomains = [line.strip() for line in out.splitlines() if line.strip()]

        if not subdomains:
            error("No subdomains found.", colored=False)

    targets_for_httpx = _dedupe_keep_order([domain, *subdomains] if domain else subdomains)

    urls: list[str] = []
    if domain:
        urls.extend([f"https://{domain}/", f"http://{domain}/"])

    if targets_for_httpx:
        remaining = TOTAL_TIMEOUT_SECONDS - (time.monotonic() - start)
        if remaining <= 1:
            error(f"Skipping httpx: overall timeout budget exceeded ({TOTAL_TIMEOUT_SECONDS}s).", colored=False)
        else:
            httpx_timeout = min(HTTPX_TIMEOUT_SECONDS, remaining)
            stdin_text = "\n".join(targets_for_httpx) + "\n"
            code, out, err = _run_cmd(
                ["httpx", "-silent", "-probe", "-title", "-status-code"],
                timeout_seconds=httpx_timeout,
                stdin_text=stdin_text,
            )

            if err.strip() and code not in (0,):
                error(err.strip(), colored=False)

            for line in (out or "").splitlines():
                line = line.strip()
                if not line:
                    continue
                # Preserve dashboard logs.
                print(line)
                urls.append(line.split(" ", 1)[0])

    if not targets_for_httpx:
        error("No targets to probe with httpx.", colored=False)

    urls = _dedupe_keep_order(urls)
    with open(output_path, "w", encoding="utf-8") as f:
        for url in urls:
            f.write(url + "\n")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python subdomain_scan.py <domain>")
        sys.exit(1)
    else:
        main(sys.argv[1])
    

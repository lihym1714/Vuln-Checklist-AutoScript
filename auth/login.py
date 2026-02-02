from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping
from urllib.parse import urljoin

import requests
import urllib3

DEFAULT_HEADERS: dict[str, str] = {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36",
    "Accept": "*/*",
    "Content-Type": "application/json",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
}


class LoginError(RuntimeError):
    pass


@dataclass(frozen=True)
class LoginConfig:
    host_url: str
    login_path: str
    logout_path: str = "/api/auth/logout"
    id_field: str = "id"
    password_field: str = "password"
    headers: Mapping[str, str] = field(default_factory=lambda: DEFAULT_HEADERS)
    timeout: float = 10.0
    verify_ssl: bool = True
    expected_statuses: tuple[int, ...] = (200, 204)
    disable_warnings: bool = False


def _build_url(host_url: str, path: str) -> str:
    base = host_url.rstrip("/") + "/"
    return urljoin(base, path.lstrip("/"))


def _maybe_disable_warnings(disable_warnings: bool, verify_ssl: bool) -> None:
    if disable_warnings and not verify_ssl:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def _response_excerpt(resp: requests.Response, limit: int = 200) -> str:
    text = resp.text or ""
    return text[:limit].replace("\n", " ").strip()


def create_session(config: LoginConfig) -> requests.Session:
    session = requests.Session()
    session.headers.update(dict(config.headers))
    return session


def build_login_payload(
    user_id: str,
    password: str,
    config: LoginConfig,
    extra_payload: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        config.id_field: user_id,
        config.password_field: password,
    }
    if extra_payload:
        payload.update(extra_payload)
    return payload


def get_login_session(
    user_id: str,
    password: str,
    *,
    config: LoginConfig,
    extra_payload: Mapping[str, Any] | None = None,
    session: requests.Session | None = None,
) -> requests.Session:
    _maybe_disable_warnings(config.disable_warnings, config.verify_ssl)
    active_session = session or create_session(config)
    login_url = _build_url(config.host_url, config.login_path)
    payload = build_login_payload(user_id, password, config, extra_payload)

    try:
        resp = active_session.post(
            login_url,
            json=payload,
            timeout=config.timeout,
            verify=config.verify_ssl,
        )
    except requests.RequestException as exc:
        raise LoginError(f"Login request failed: {exc}") from exc

    if resp.status_code not in config.expected_statuses:
        excerpt = _response_excerpt(resp)
        detail = f" (body: {excerpt})" if excerpt else ""
        raise LoginError(
            f"Login failed with status code: {resp.status_code}{detail}"
        )

    return active_session


def logout(
    session: requests.Session,
    *,
    config: LoginConfig,
) -> requests.Response:
    _maybe_disable_warnings(config.disable_warnings, config.verify_ssl)
    logout_url = _build_url(config.host_url, config.logout_path)

    try:
        resp = session.post(
            logout_url,
            timeout=config.timeout,
            verify=config.verify_ssl,
        )
    except requests.RequestException as exc:
        raise LoginError(f"Logout request failed: {exc}") from exc

    if resp.status_code not in config.expected_statuses:
        excerpt = _response_excerpt(resp)
        detail = f" (body: {excerpt})" if excerpt else ""
        raise LoginError(
            f"Logout failed with status code: {resp.status_code}{detail}"
        )

    return resp

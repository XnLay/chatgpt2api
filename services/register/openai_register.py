from __future__ import annotations

import base64
import hashlib
import json
import os
import random
import secrets
import string
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse

import requests
import urllib3
from curl_cffi import requests as curl_requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from services.account_service import account_service
from services.register import mail_provider
from utils.sentinel import (
    DEFAULT_SENTINEL_FLOW_TIMEOUT_MS,
    SentinelArtifacts,
    build_sentinel_artifacts as _build_sentinel_artifacts,
    build_sentinel_token as _build_sentinel_token_tuple,
)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

MAIL_ENV_SETTING_KEYS = ("request_timeout", "wait_timeout", "wait_interval", "user_agent", "proxy")


def _env_value(*names: str) -> tuple[str, str]:
    for name in names:
        value = os.getenv(name)
        if value is not None and value.strip():
            return name, value.strip()
    return "", ""


def _env_json(*names: str) -> tuple[str, Any | None]:
    name, raw = _env_value(*names)
    if not raw:
        return "", None
    try:
        return name, json.loads(raw)
    except json.JSONDecodeError as error:
        raise ValueError(f"环境变量 {name} 必须是合法 JSON: {error.msg}") from error


def _env_bool(value: Any, default: bool = True) -> bool:
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"1", "true", "yes", "on"}:
            return True
        if lowered in {"0", "false", "no", "off"}:
            return False
    if value is None:
        return default
    return bool(value)


def _env_float(name: str) -> float | None:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return None
    try:
        return float(raw)
    except ValueError as error:
        raise ValueError(f"环境变量 {name} 必须是数字") from error


def _env_string_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    text = str(value or "").strip()
    if not text:
        return []
    return [item.strip() for item in text.replace("\n", ",").split(",") if item.strip()]


def _normalize_env_provider(entry: Any, source: str) -> dict:
    if not isinstance(entry, dict):
        raise ValueError(f"{source} 中的邮箱 provider 必须是 JSON 对象")
    provider = dict(entry)
    provider_type = str(provider.get("type") or "").strip()
    if not provider_type:
        raise ValueError(f"{source} 中的邮箱 provider 缺少 type")
    provider["type"] = provider_type
    provider["enable"] = _env_bool(provider.get("enable"), True)
    for key in ("domain", "cf_domain"):
        if key in provider:
            provider[key] = _env_string_list(provider.get(key))
    if provider_type == "cloudmail_gen" and "subdomain" in provider:
        provider["subdomain"] = _env_string_list(provider.get("subdomain"))
    return provider


def _merge_env_mail_object(overrides: dict, value: Any, source: str, allow_single_provider: bool = False) -> None:
    if not isinstance(value, dict):
        raise ValueError(f"环境变量 {source} 必须是 JSON 对象")
    for key in MAIL_ENV_SETTING_KEYS:
        if key in value:
            overrides[key] = value[key]
    providers = value.get("providers")
    if isinstance(providers, list):
        overrides["providers"] = [_normalize_env_provider(item, source) for item in providers]
    elif providers is not None:
        raise ValueError(f"环境变量 {source}.providers 必须是 JSON 数组")
    elif allow_single_provider and "type" in value:
        overrides["providers"] = [_normalize_env_provider(value, source)]


def _merge_env_provider_overrides(overrides: dict) -> None:
    name, value = _env_json("REGISTER_MAIL_PROVIDERS", "REGISTER_MAIL_PROVIDERS_JSON")
    if value is None:
        config_name, provider_config = _env_json("REGISTER_MAIL_PROVIDER_CONFIG", "REGISTER_MAIL_PROVIDER_JSON")
        provider_config = provider_config or {}
        if not isinstance(provider_config, dict):
            raise ValueError(f"环境变量 {config_name} 必须是 JSON 对象")
        provider_type = os.getenv("REGISTER_MAIL_PROVIDER") or provider_config.get("type") or ""
        provider_type = str(provider_type).strip()
        if provider_type:
            overrides["providers"] = [_normalize_env_provider({**provider_config, "type": provider_type}, "REGISTER_MAIL_PROVIDER_CONFIG")]
        return
    if isinstance(value, list):
        overrides["providers"] = [_normalize_env_provider(item, name) for item in value]
        return
    if isinstance(value, dict):
        provider_overrides: dict[str, Any] = {}
        _merge_env_mail_object(provider_overrides, value, name, allow_single_provider=True)
        if "providers" in provider_overrides:
            overrides.update(provider_overrides)
            return
    raise ValueError(f"环境变量 {name} 必须是 provider 对象、provider 数组，或包含 providers 数组的对象")


def _env_mail_overrides() -> dict:
    overrides: dict[str, Any] = {}

    _, mail_object = _env_json("REGISTER_MAIL", "REGISTER_MAIL_JSON")
    if mail_object is not None:
        _merge_env_mail_object(overrides, mail_object, "REGISTER_MAIL")

    _merge_env_provider_overrides(overrides)

    env_field_map = {
        "REGISTER_MAIL_REQUEST_TIMEOUT": "request_timeout",
        "REGISTER_MAIL_WAIT_TIMEOUT": "wait_timeout",
        "REGISTER_MAIL_WAIT_INTERVAL": "wait_interval",
    }
    for env_name, key in env_field_map.items():
        value = _env_float(env_name)
        if value is not None:
            overrides[key] = value

    _, user_agent = _env_value("REGISTER_MAIL_USER_AGENT")
    if user_agent:
        overrides["user_agent"] = user_agent
    _, proxy = _env_value("REGISTER_MAIL_PROXY")
    if proxy:
        overrides["proxy"] = proxy
    return overrides


def apply_env_overrides(source: dict) -> dict:
    """应用注册机环境变量覆盖；环境变量优先级高于持久化配置。"""
    cfg = json.loads(json.dumps(source, ensure_ascii=False))
    overrides = _env_mail_overrides()
    if not overrides:
        return cfg
    mail = cfg.get("mail") if isinstance(cfg.get("mail"), dict) else {}
    cfg["mail"] = {**mail, **overrides}
    return cfg


base_dir = Path(__file__).resolve().parent
config = {
    "mail": {
        "request_timeout": 30,
        "wait_timeout": 30,
        "wait_interval": 2,
        "api_use_register_proxy": True,
        "providers": [],
    },
    "proxy": "",
    "total": 10,
    "threads": 3,
}
register_config_file = base_dir.parents[1] / "data" / "register.json"
try:
    saved_config = json.loads(register_config_file.read_text(encoding="utf-8"))
    config.update({key: saved_config[key] for key in ("mail", "proxy", "total", "threads") if key in saved_config})
except Exception:
    pass
config = apply_env_overrides(config)

auth_base = "https://auth.openai.com"
platform_base = "https://platform.openai.com"
platform_oauth_client_id = "app_2SKx67EdpoN0G6j64rFvigXD"
platform_oauth_redirect_uri = f"{platform_base}/auth/callback"
platform_oauth_audience = "https://api.openai.com/v1"
platform_auth0_client = "eyJuYW1lIjoiYXV0aDAtc3BhLWpzIiwidmVyc2lvbiI6IjEuMjEuMCJ9"
user_agent = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/145.0.0.0 Safari/537.36"
)
sec_ch_ua = '"Google Chrome";v="145", "Not?A_Brand";v="8", "Chromium";v="145"'
sec_ch_ua_full_version_list = '"Chromium";v="145.0.0.0", "Not:A-Brand";v="99.0.0.0", "Google Chrome";v="145.0.0.0"'
default_timeout = 30
print_lock = threading.Lock()
stats_lock = threading.Lock()
stats = {"done": 0, "success": 0, "fail": 0, "start_time": 0.0}
register_log_sink = None

common_headers = {
    "accept": "application/json",
    "accept-language": "en-US,en;q=0.9",
    "content-type": "application/json",
    "origin": auth_base,
    "priority": "u=1, i",
    "user-agent": user_agent,
    "sec-ch-ua": sec_ch_ua,
    "sec-ch-ua-arch": '"x86_64"',
    "sec-ch-ua-bitness": '"64"',
    "sec-ch-ua-full-version-list": sec_ch_ua_full_version_list,
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-model": '""',
    "sec-ch-ua-platform": '"Windows"',
    "sec-ch-ua-platform-version": '"10.0.0"',
    "sec-fetch-dest": "empty",
    "sec-fetch-mode": "cors",
    "sec-fetch-site": "same-origin",
}

navigate_headers = {
    "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "accept-language": "en-US,en;q=0.9",
    "user-agent": user_agent,
    "sec-ch-ua": sec_ch_ua,
    "sec-ch-ua-arch": '"x86_64"',
    "sec-ch-ua-bitness": '"64"',
    "sec-ch-ua-full-version-list": sec_ch_ua_full_version_list,
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-model": '""',
    "sec-ch-ua-platform": '"Windows"',
    "sec-ch-ua-platform-version": '"10.0.0"',
    "sec-fetch-dest": "document",
    "sec-fetch-mode": "navigate",
    "sec-fetch-site": "same-origin",
    "sec-fetch-user": "?1",
    "upgrade-insecure-requests": "1",
}


def log(text: str, color: str = "") -> None:
    text = str(text or "")
    if len(text) > 1000:
        text = text[:997].rstrip() + "..."
    colors = {"red": "\033[31m", "green": "\033[32m", "yellow": "\033[33m"}
    if register_log_sink:
        try:
            register_log_sink(text, color)
        except Exception:
            pass
    with print_lock:
        prefix = colors.get(color, "")
        suffix = "\033[0m" if prefix else ""
        print(f"{prefix}{datetime.now().strftime('%H:%M:%S')} {text}{suffix}")


def step(index: int, text: str, color: str = "") -> None:
    log(f"[任务{index}] {text}", color)


def _make_trace_headers() -> dict[str, str]:
    trace_id = str(random.getrandbits(64))
    parent_id = str(random.getrandbits(64))
    return {
        "traceparent": f"00-{uuid.uuid4().hex}-{format(int(parent_id), '016x')}-01",
        "tracestate": "dd=s:1;o:rum",
        "x-datadog-origin": "rum",
        "x-datadog-parent-id": parent_id,
        "x-datadog-sampling-priority": "1",
        "x-datadog-trace-id": trace_id,
    }


def _generate_pkce() -> tuple[str, str]:
    code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(64)).rstrip(b"=").decode("ascii")
    code_challenge = base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode("ascii")).digest()).rstrip(b"=").decode("ascii")
    return code_verifier, code_challenge


def _random_password(length: int = 16) -> str:
    chars = string.ascii_letters + string.digits + "!@#$%"
    value = list(
        secrets.choice(string.ascii_uppercase)
        + secrets.choice(string.ascii_lowercase)
        + secrets.choice(string.digits)
        + secrets.choice("!@#$%")
        + "".join(secrets.choice(chars) for _ in range(max(0, length - 4)))
    )
    random.shuffle(value)
    return "".join(value)


def _random_name() -> tuple[str, str]:
    return random.choice(["James", "Robert", "John", "Michael", "David", "Mary", "Emma", "Olivia"]), random.choice(
        ["Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller"]
    )


def _random_birthdate() -> str:
    return f"{random.randint(1996, 2006):04d}-{random.randint(1, 12):02d}-{random.randint(1, 28):02d}"


def _response_json(resp) -> dict:
    try:
        data = resp.json()
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _response_debug_detail(resp, limit: int = 180) -> str:
    if resp is None:
        return ""
    data = _response_json(resp)
    parts = [
        f"url={str(getattr(resp, 'url', '') or '')[:300]}",
        f"content_type={str(getattr(resp, 'headers', {}).get('content-type') or '')}",
    ]
    for key in ("cf-ray", "x-request-id", "openai-processing-ms"):
        value = str(getattr(resp, "headers", {}).get(key) or "").strip()
        if value:
            parts.append(f"{key}={value}")
    if data:
        parts.append(f"json={json.dumps(data, ensure_ascii=False)[:limit]}")
    else:
        parts.append(f"body={str(getattr(resp, 'text', '') or '')[:limit]}")
    return ", ".join(parts)


def _is_cloudflare_challenge(resp) -> bool:
    if resp is None:
        return False
    text = str(getattr(resp, "text", "") or "").lower()
    headers = getattr(resp, "headers", {}) or {}
    content_type = str(headers.get("content-type") or "").lower()
    cf_mitigated = str(headers.get("cf-mitigated") or "").lower()
    server = str(headers.get("server") or "").lower()
    if cf_mitigated == "challenge":
        return True
    challenge_markers = (
        "challenges.cloudflare.com",
        "/cdn-cgi/challenge-platform",
        "cf-chl-",
        "cf_chl_",
        "cf-browser-verification",
        "<title>just a moment",
        "attention required! | cloudflare",
        "enable cookies",
    )
    if any(marker in text for marker in challenge_markers):
        return True
    # Cloudflare 也常作为正常 API 网关，单独的 `server: cloudflare`
    # 不能视为拦截；只有返回 HTML 挑战页特征时才判定为 Cloudflare challenge。
    return "cloudflare" in server and "text/html" in content_type and "challenge" in text


def _truthy(value: object, fallback: bool = True) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return fallback
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "on"}:
        return True
    if text in {"0", "false", "no", "off"}:
        return False
    return fallback


def _mail_config(register_proxy: str = "") -> dict:
    mail = config["mail"] if isinstance(config.get("mail"), dict) else {}
    use_register_proxy = _truthy(mail.get("api_use_register_proxy"), True)
    proxy = str(register_proxy or "").strip() if use_register_proxy else ""
    return {**mail, "api_use_register_proxy": use_register_proxy, "proxy": proxy}


def _authorize_landed_page(resp) -> str:
    """诊断用：粗判 authorize 之后落在哪个页面。返回 signup / login / "" 仅供日志。

    注意：email-verification / email_otp_verification 在注册和登录流程里都会出现，
    无法据此可靠区分，所以这里只用于打日志，绝不据此中断注册流程。
    """
    if resp is None:
        return ""
    final_url = str(getattr(resp, "url", "") or "").lower()
    data = _response_json(resp)
    page_type = ""
    page = data.get("page") if isinstance(data, dict) else None
    if isinstance(page, dict):
        page_type = str(page.get("type") or "").lower()
    if "create-account" in final_url or "signup" in final_url or "create_account" in page_type:
        return "signup"
    if "/log-in" in final_url or "/login" in final_url or page_type in {"login", "password_verification"}:
        return "login"
    return ""


def create_mailbox(username: str | None = None, register_proxy: str = "") -> dict:
    return mail_provider.create_mailbox(_mail_config(register_proxy), username)


def wait_for_code(mailbox: dict, register_proxy: str = "") -> str | None:
    return mail_provider.wait_for_code(_mail_config(register_proxy), mailbox)


def build_sentinel_token(session: requests.Session, device_id: str, flow: str) -> str:
    """请求 sentinel token，返回 sentinel header 字符串（兼容旧接口）。"""
    sentinel_val, _oai_sc_val = _build_sentinel_token_tuple(
        session,
        device_id,
        flow,
        user_agent=user_agent,
        sec_ch_ua=sec_ch_ua,
    )
    return sentinel_val


def build_sentinel_artifacts(
    session: requests.Session,
    device_id: str,
    flow: str,
    *,
    observer_timeout_ms: int = DEFAULT_SENTINEL_FLOW_TIMEOUT_MS,
) -> SentinelArtifacts:
    return _build_sentinel_artifacts(
        session,
        device_id,
        flow,
        user_agent=user_agent,
        sec_ch_ua=sec_ch_ua,
        observer_timeout_ms=observer_timeout_ms,
    )


def _is_socks_proxy(proxy: str) -> bool:
    candidate = str(proxy or "").strip().lower()
    return candidate.startswith("socks5://") or candidate.startswith("socks5h://")


def create_session(proxy: str = "") -> Any:
    if _is_socks_proxy(proxy):
        return curl_requests.Session(impersonate="chrome", verify=False, proxy=proxy)
    session = requests.Session()
    retry = Retry(total=2, connect=2, read=2, backoff_factor=0.5, status_forcelist=(429, 500, 502, 503, 504))
    adapter = HTTPAdapter(max_retries=retry, pool_connections=50, pool_maxsize=50)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.verify = False
    if proxy:
        session.proxies.update({"http": proxy, "https": proxy})
    return session


def request_with_local_retry(session: requests.Session, method: str, url: str, retry_attempts: int = 3, **kwargs):
    last_error = ""
    for _ in range(max(1, retry_attempts)):
        try:
            return session.request(method.upper(), url, timeout=default_timeout, **kwargs), ""
        except Exception as error:
            last_error = str(error)
            time.sleep(1)
    return None, last_error


def validate_otp(session: requests.Session, device_id: str, code: str):
    headers = dict(common_headers)
    headers["referer"] = f"{auth_base}/email-verification"
    headers["oai-device-id"] = device_id
    headers.update(_make_trace_headers())
    resp, error = request_with_local_retry(session, "post", f"{auth_base}/api/accounts/email-otp/validate", json={"code": code}, headers=headers, verify=False)
    if resp is not None and resp.status_code == 200:
        return resp, ""
    sentinel_val, oai_sc_val = _build_sentinel_token_tuple(
        session,
        device_id,
        "authorize_continue",
        user_agent=user_agent,
        sec_ch_ua=sec_ch_ua,
    )
    headers["openai-sentinel-token"] = sentinel_val
    if oai_sc_val:
        for domain in (".openai.com", "openai.com", ".auth.openai.com", "auth.openai.com"):
            try:
                session.cookies.set("oai-sc", oai_sc_val, domain=domain)
            except Exception:
                continue
    resp, error = request_with_local_retry(session, "post", f"{auth_base}/api/accounts/email-otp/validate", json={"code": code}, headers=headers, verify=False)
    return resp, error


def extract_oauth_callback_params_from_url(url: str) -> dict[str, str] | None:
    if not url:
        return None
    try:
        params = parse_qs(urlparse(url).query)
    except Exception:
        return None
    code = str((params.get("code") or [""])[0]).strip()
    if not code:
        return None
    return {"code": code, "state": str((params.get("state") or [""])[0]).strip(), "scope": str((params.get("scope") or [""])[0]).strip()}


def _extract_callback_params_from_response(resp, data: dict | None = None) -> dict[str, str] | None:
    candidates = [str((data or {}).get("continue_url") or "").strip()]
    headers = getattr(resp, "headers", {}) or {}
    candidates.append(str(headers.get("location") or headers.get("Location") or "").strip())
    candidates.append(str(getattr(resp, "url", "") or "").strip())
    for item in candidates:
        callback_params = extract_oauth_callback_params_from_url(item)
        if callback_params:
            return callback_params
    return None


def request_platform_oauth_token(session: requests.Session, code: str, code_verifier: str) -> dict | None:
    if not str(code or "").strip():
        raise RuntimeError("token换取失败: OAuth code 为空，create_account 未返回有效回调 code")
    if not str(code_verifier or "").strip():
        raise RuntimeError("token换取失败: code_verifier 为空")
    headers = {
        "accept": "*/*",
        "accept-language": "zh-CN,zh;q=0.9",
        "auth0-client": platform_auth0_client,
        "cache-control": "no-cache",
        "content-type": "application/json",
        "origin": platform_base,
        "pragma": "no-cache",
        "priority": "u=1, i",
        "referer": f"{platform_base}/",
        "sec-ch-ua": sec_ch_ua,
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-site",
        "user-agent": user_agent,
    }
    resp = session.post(
        f"{auth_base}/api/accounts/oauth/token",
        headers=headers,
        json={
            "client_id": platform_oauth_client_id,
            "code_verifier": code_verifier,
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": platform_oauth_redirect_uri,
        },
        verify=False,
        timeout=60,
    )
    if resp.status_code != 200:
        raise RuntimeError(f"token换取失败: oauth_token_http_{resp.status_code}, {_response_debug_detail(resp)}")
    return _response_json(resp)


class PlatformRegistrar:
    def __init__(self, proxy: str = "") -> None:
        self.proxy = str(proxy or "").strip()
        self.session = create_session(self.proxy)
        self.device_id = str(uuid.uuid4())
        self.code_verifier = ""
        self.platform_auth_code = ""

    def close(self) -> None:
        self.session.close()

    def _navigate_headers(self, referer: str = "") -> dict[str, str]:
        headers = dict(navigate_headers)
        if referer:
            headers["referer"] = referer
        return headers

    def _json_headers(self, referer: str) -> dict[str, str]:
        headers = dict(common_headers)
        headers["referer"] = referer
        headers["oai-device-id"] = self.device_id
        headers.update(_make_trace_headers())
        return headers

    def _apply_sentinel_cookie(self, artifacts: SentinelArtifacts) -> None:
        value = str(getattr(artifacts, "oai_sc_value", "") or "").strip()
        if not value:
            return
        for domain in (".openai.com", "openai.com", ".auth.openai.com", "auth.openai.com"):
            try:
                self.session.cookies.set("oai-sc", value, domain=domain)
            except Exception:
                continue

    def _log_sentinel_artifacts(self, index: int, flow: str, artifacts: SentinelArtifacts) -> None:
        step(
            index,
            "Sentinel 准备完成"
            f" flow={flow}"
            f" sdk={artifacts.sdk_version or '?'}"
            f" token_len={len(str(artifacts.token or ''))}"
            f" so_token={'yes' if artifacts.so_token else 'no'}"
            f" so_len={len(str(artifacts.so_token or ''))}"
            f" wait_ms={artifacts.observer_timeout_ms}",
        )

    def _build_sentinel(self, flow: str, index: int, *, observer_timeout_ms: int = DEFAULT_SENTINEL_FLOW_TIMEOUT_MS) -> SentinelArtifacts:
        artifacts = build_sentinel_artifacts(
            self.session,
            self.device_id,
            flow,
            observer_timeout_ms=observer_timeout_ms,
        )
        self._apply_sentinel_cookie(artifacts)
        self._log_sentinel_artifacts(index, flow, artifacts)
        return artifacts

    def _platform_authorize(self, email: str, index: int) -> None:
        step(index, "开始 platform authorize")
        self.session.cookies.set("oai-did", self.device_id, domain=".auth.openai.com")
        self.session.cookies.set("oai-did", self.device_id, domain="auth.openai.com")
        self.code_verifier, code_challenge = _generate_pkce()
        params = {
            "issuer": auth_base,
            "client_id": platform_oauth_client_id,
            "audience": platform_oauth_audience,
            "redirect_uri": platform_oauth_redirect_uri,
            "device_id": self.device_id,
            "screen_hint": "signup",
            "max_age": "0",
            "login_hint": email,
            "scope": "openid profile email offline_access",
            "response_type": "code",
            "response_mode": "query",
            "state": secrets.token_urlsafe(32),
            "nonce": secrets.token_urlsafe(32),
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "auth0Client": platform_auth0_client,
        }
        resp, error = request_with_local_retry(self.session, "get", f"{auth_base}/api/accounts/authorize?{urlencode(params)}", headers=self._navigate_headers(f"{platform_base}/"), allow_redirects=True, verify=False)
        if resp is None:
            raise RuntimeError(error or "platform_authorize_failed")
        if _is_cloudflare_challenge(resp):
            # Cloudflare 挑战页通常返回完整 HTML，实时日志只保留结论，避免刷屏。
            step(index, "platform authorize 返回 Cloudflare challenge，按 1.1.7 兼容策略继续尝试；", "yellow")
        elif resp.status_code != 200:
            err = _response_json(resp).get("error", {})
            detail = f": {err.get('code', '')} - {err.get('message', '')}".strip(" -") if err else ""
            debug = _response_debug_detail(resp)
            step(index, f"platform authorize 返回 HTTP {resp.status_code}{detail}，继续使用已建立的授权会话；{debug}", "yellow")
        step(index, "platform authorize 完成")

    def _register_user(self, email: str, password: str, index: int) -> None:
        step(index, "开始提交注册密码")
        headers = self._json_headers(f"{auth_base}/create-account/password")
        headers["openai-sentinel-token"] = self._build_sentinel("username_password_create", index).token
        resp, error = request_with_local_retry(self.session, "post", f"{auth_base}/api/accounts/user/register", json={"username": email, "password": password}, headers=headers, verify=False)
        if resp is None or resp.status_code != 200:
            data = _response_json(resp) if resp is not None else {}
            if data.get("message") == "Failed to create account. Please try again.":
                step(index, "注册失败提示: 邮箱域名很可能因滥用被封禁，请更换邮箱域名", "yellow")
            detail = f", detail={json.dumps(data, ensure_ascii=False)}" if data else ""
            raise RuntimeError(error or f"user_register_http_{getattr(resp, 'status_code', 'unknown')}{detail}")
        step(index, "提交注册密码完成")

    def _send_otp(self, index: int) -> None:
        step(index, "开始发送验证码")
        resp, error = request_with_local_retry(self.session, "get", f"{auth_base}/api/accounts/email-otp/send", headers=self._navigate_headers(f"{auth_base}/create-account/password"), allow_redirects=True, verify=False)
        if resp is None or resp.status_code not in (200, 302):
            raise RuntimeError(error or f"send_otp_http_{getattr(resp, 'status_code', 'unknown')}")
        step(index, "发送验证码完成")

    def _validate_otp(self, code: str, index: int) -> None:
        step(index, f"开始校验验证码 {code}")
        resp, error = validate_otp(self.session, self.device_id, code)
        if resp is None or resp.status_code != 200:
            body = ""
            try:
                body = (resp.text or "")[:500] if resp is not None else ""
            except Exception:
                pass
            raise RuntimeError(error or f"validate_otp_http_{getattr(resp, 'status_code', 'unknown')}_body={body}")
        step(index, "验证码校验完成")

    def _create_account(self, name: str, birthdate: str, index: int) -> None:
        step(index, "开始创建账号资料")
        headers = self._json_headers(f"{auth_base}/about-you")
        artifacts = self._build_sentinel("oauth_create_account", index, observer_timeout_ms=5000)
        headers["openai-sentinel-token"] = artifacts.token
        if artifacts.so_token:
            headers["openai-sentinel-so-token"] = artifacts.so_token
        else:
            step(index, "Sentinel 未生成 so-token，create_account 成功率可能偏低", "yellow")
        resp, error = request_with_local_retry(self.session, "post", f"{auth_base}/api/accounts/create_account", json={"name": name, "birthdate": birthdate}, headers=headers, verify=False)
        if resp is None or resp.status_code not in (200, 302):
            data = _response_json(resp) if resp is not None else {}
            if data.get("message") == "Failed to create account. Please try again.":
                step(index, "创建账号失败提示: 邮箱域名很可能因滥用被封禁，请更换邮箱域名", "yellow")
            detail = f", detail={json.dumps(data, ensure_ascii=False)}" if data else ""
            raise RuntimeError(error or f"create_account_http_{getattr(resp, 'status_code', 'unknown')}{detail}")
        data = _response_json(resp)
        callback_params = _extract_callback_params_from_response(resp, data)
        self.platform_auth_code = str((callback_params or {}).get("code") or "").strip()
        if not self.platform_auth_code:
            raise RuntimeError("创建账号资料完成但未获得 OAuth code，无法换 token")
        step(index, "创建账号资料完成")

    def _exchange_registered_tokens(self, index: int) -> dict:
        step(index, "开始换 token")
        tokens = request_platform_oauth_token(self.session, self.platform_auth_code, self.code_verifier)
        if not tokens:
            raise RuntimeError("token换取失败")
        step(index, "token 换取完成")
        return tokens

    def register(self, index: int) -> dict:
        step(index, "开始创建邮箱")
        mailbox = create_mailbox(register_proxy=self.proxy)
        email = str(mailbox.get("address") or "").strip()
        if not email:
            raise RuntimeError("邮箱服务未返回 address")
        label = str(mailbox.get("label") or "")
        step(index, f"邮箱创建完成[{label}]: {email}")
        password = _random_password()
        first_name, last_name = _random_name()
        self._platform_authorize(email, index)
        self._register_user(email, password, index)
        self._send_otp(index)
        step(index, "开始等待注册验证码")
        code = wait_for_code(mailbox, register_proxy=self.proxy)
        if not code:
            raise RuntimeError("等待注册验证码超时")
        step(index, f"收到注册验证码: {code}")
        self._validate_otp(code, index)
        self._create_account(f"{first_name} {last_name}", _random_birthdate(), index)
        tokens = self._exchange_registered_tokens(index)
        return {
            "email": email,
            "password": password,
            "access_token": str(tokens.get("access_token") or "").strip(),
            "refresh_token": str(tokens.get("refresh_token") or "").strip(),
            "id_token": str(tokens.get("id_token") or "").strip(),
            "source_type": "web",
            "created_at": datetime.now(timezone.utc).isoformat(),
        }


def worker(index: int) -> dict:
    start = time.time()
    registrar = PlatformRegistrar(config["proxy"])
    try:
        step(index, "任务启动")
        result = registrar.register(index)
        cost = time.time() - start
        access_token = str(result["access_token"])
        account_service.add_account_items([result])
        refresh_result = account_service.refresh_accounts([access_token])
        if refresh_result.get("errors"):
            step(index, f"账号已保存，刷新状态暂未成功，稍后可重试: {refresh_result['errors']}", "yellow")
        with stats_lock:
            stats["done"] += 1
            stats["success"] += 1
            avg = (time.time() - stats["start_time"]) / stats["success"]
        log(f'{result["email"]} 注册成功，本次耗时{cost:.1f}s，全局平均每个号注册耗时{avg:.1f}s', "green")
        return {"ok": True, "index": index, "result": result}
    except Exception as e:
        cost = time.time() - start
        with stats_lock:
            stats["done"] += 1
            stats["fail"] += 1
        log(f"任务{index} 注册失败，本次耗时{cost:.1f}s，原因: {e}", "red")
        return {"ok": False, "index": index, "error": str(e)}
    finally:
        registrar.close()

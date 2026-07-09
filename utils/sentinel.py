"""OpenAI Sentinel 请求/令牌工具。

优先加载当前官方 Sentinel SDK 生成 prepare token / token / so-token；
若 SDK 获取或执行失败，再回退到旧版本地兼容逻辑。
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from utils.pow import DEFAULT_POW_SCRIPT, build_legacy_requirements_token, build_proof_token

if TYPE_CHECKING:
    from curl_cffi.requests import Session


DEFAULT_SENTINEL_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/145.0.0.0 Safari/537.36"
)
DEFAULT_SENTINEL_SEC_CH_UA = '"Chromium";v="145", "Google Chrome";v="145", "Not/A)Brand";v="99"'
DEFAULT_SENTINEL_FLOW_TIMEOUT_MS = 5000
DEFAULT_SENTINEL_FRAME_URL = "https://sentinel.openai.com/backend-api/sentinel/frame.html"
DEFAULT_SENTINEL_ASSET_CACHE_TTL_SECS = 1800
_SENTINEL_SDK_RUNNER = Path(__file__).with_name("sentinel_sdk_runner.js")
_sentinel_sdk_asset_cache: dict[str, Any] = {}


@dataclass(slots=True)
class SentinelArtifacts:
    token: str
    oai_sc_value: str = ""
    so_token: str = ""
    sdk_url: str = ""
    sdk_version: str = ""
    flow: str = ""
    observer_timeout_ms: int = DEFAULT_SENTINEL_FLOW_TIMEOUT_MS
    raw: dict[str, Any] = field(default_factory=dict, repr=False)


def _coerce_dict(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _nested_requirements(data: dict[str, Any]) -> dict[str, Any]:
    requirements = data.get("requirements")
    return requirements if isinstance(requirements, dict) else data


def _extract_sdk_url(data: dict[str, Any]) -> str:
    candidates: list[object] = [
        data.get("sdk_url"),
        (_coerce_dict(data.get("sdk"))).get("url"),
        (_coerce_dict(_nested_requirements(data).get("sdk"))).get("url"),
        _nested_requirements(data).get("sdk_url"),
        DEFAULT_POW_SCRIPT,
    ]
    for item in candidates:
        value = str(item or "").strip()
        if value:
            return value
    return DEFAULT_POW_SCRIPT


def _extract_sdk_url_from_frame_html(html: str) -> str:
    match = re.search(r"""src=['"]([^'"]+/sentinel/[^'"]+/sdk\.js[^'"]*)['"]""", str(html or ""))
    return str((match.group(1) if match else "") or "").strip()


def _extract_sdk_version(sdk_url: str) -> str:
    value = str(sdk_url or "").strip()
    if not value:
        return ""
    match = re.search(r"/sentinel/([^/]+)/sdk\.js", value)
    if match:
        return match.group(1)
    match = re.search(r"[?&](?:v|version|build)=([^&#]+)", value)
    if match:
        return match.group(1)
    tail = value.rstrip("/").split("/")[-1]
    return tail[:64]


def _requirements_prepare_token(user_agent: str, sdk_url: str) -> str:
    return build_legacy_requirements_token(user_agent, script_sources=[sdk_url or DEFAULT_POW_SCRIPT], data_build="")


def _extract_pow_spec(node: dict[str, Any], *keys: str) -> dict[str, Any]:
    for key in keys:
        value = node.get(key)
        if isinstance(value, dict) and value:
            return value
    return {}


def _extract_direct_token(node: dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = str(node.get(key) or "").strip()
        if value:
            return value
    return ""


def _solve_requirement_token(spec: dict[str, Any], user_agent: str, sdk_url: str) -> str:
    if not spec:
        return ""
    direct = str(spec.get("token") or spec.get("value") or spec.get("result") or "").strip()
    if direct:
        return direct
    if not spec.get("required"):
        return ""
    seed = str(spec.get("seed") or "").strip()
    difficulty = str(spec.get("difficulty") or "").strip()
    if not seed or not difficulty:
        return ""
    return build_proof_token(seed, difficulty, user_agent, script_sources=[sdk_url or DEFAULT_POW_SCRIPT], data_build="")


def _build_sentinel_headers(user_agent: str, sec_ch_ua: str) -> dict[str, str]:
    return {
        "Content-Type": "text/plain;charset=UTF-8",
        "Referer": DEFAULT_SENTINEL_FRAME_URL,
        "Origin": "https://sentinel.openai.com",
        "User-Agent": user_agent,
        "sec-ch-ua": sec_ch_ua,
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
    }


def _request_sentinel_requirements(
    session: "Session",
    device_id: str,
    flow: str,
    prepare_token: str,
    *,
    user_agent: str,
    sec_ch_ua: str,
):
    resp = session.post(
        "https://sentinel.openai.com/backend-api/sentinel/req",
        data=json.dumps({"p": prepare_token, "id": device_id, "flow": flow}, separators=(",", ":")),
        headers=_build_sentinel_headers(user_agent, sec_ch_ua),
        timeout=20,
        verify=False,
    )
    try:
        data = resp.json() if resp.text else {}
    except Exception:
        data = {}
    if not isinstance(data, dict):
        data = {}
    return resp, data


def _build_legacy_artifacts_from_req_data(
    data: dict[str, Any],
    device_id: str,
    flow: str,
    *,
    user_agent: str,
    observer_timeout_ms: int,
    sdk_url_override: str = "",
    status_code: int = 200,
) -> SentinelArtifacts:
    sdk_url = sdk_url_override or _extract_sdk_url(data)
    sdk_version = _extract_sdk_version(sdk_url)
    prepare_token = _requirements_prepare_token(user_agent, sdk_url)
    requirements = _nested_requirements(data)
    challenge_token = _extract_direct_token(data, "token", "c") or _extract_direct_token(requirements, "token", "c")
    pow_spec = _extract_pow_spec(requirements, "proofofwork", "proof_of_work", "pow")
    so_spec = _extract_pow_spec(requirements, "so", "so_token", "soToken")

    if status_code != 200 or not challenge_token:
        fallback = json.dumps(
            {"p": prepare_token, "t": "", "c": challenge_token, "id": device_id, "flow": flow},
            separators=(",", ":"),
        )
        return SentinelArtifacts(
            token=fallback,
            oai_sc_value=("0" + challenge_token) if challenge_token else "",
            sdk_url=sdk_url,
            sdk_version=sdk_version,
            flow=flow,
            observer_timeout_ms=max(0, int(observer_timeout_ms or DEFAULT_SENTINEL_FLOW_TIMEOUT_MS)),
            raw=data,
        )

    solved_p = _solve_requirement_token(pow_spec, user_agent, sdk_url) or prepare_token
    so_token = (
        _extract_direct_token(data, "so_token", "soToken")
        or _extract_direct_token(requirements, "so_token", "soToken", "so")
        or _solve_requirement_token(so_spec, user_agent, sdk_url)
    )
    sentinel_value = json.dumps(
        {"p": solved_p, "t": "", "c": challenge_token, "id": device_id, "flow": flow},
        separators=(",", ":"),
    )
    return SentinelArtifacts(
        token=sentinel_value,
        oai_sc_value="0" + challenge_token,
        so_token=so_token,
        sdk_url=sdk_url,
        sdk_version=sdk_version,
        flow=flow,
        observer_timeout_ms=max(0, int(observer_timeout_ms or DEFAULT_SENTINEL_FLOW_TIMEOUT_MS)),
        raw=data,
    )


def _load_sentinel_sdk_assets(session: "Session", *, user_agent: str, sec_ch_ua: str) -> tuple[str, str]:
    now = time.time()
    cached_url = str(_sentinel_sdk_asset_cache.get("sdk_url") or "").strip()
    cached_source = str(_sentinel_sdk_asset_cache.get("sdk_source") or "")
    fetched_at = float(_sentinel_sdk_asset_cache.get("fetched_at") or 0.0)
    if cached_url and cached_source and (now - fetched_at) < DEFAULT_SENTINEL_ASSET_CACHE_TTL_SECS:
        return cached_url, cached_source

    frame_headers = {
        "User-Agent": user_agent,
        "sec-ch-ua": sec_ch_ua,
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }
    frame_resp = session.get(
        DEFAULT_SENTINEL_FRAME_URL,
        headers=frame_headers,
        timeout=20,
        verify=False,
    )
    frame_html = str(getattr(frame_resp, "text", "") or "")
    sdk_url = _extract_sdk_url_from_frame_html(frame_html)
    if frame_resp.status_code != 200 or not sdk_url:
        if cached_url and cached_source:
            return cached_url, cached_source
        raise RuntimeError(f"sentinel_frame_http_{getattr(frame_resp, 'status_code', 'unknown')}")

    source_resp = session.get(
        sdk_url,
        headers={
            "User-Agent": user_agent,
            "sec-ch-ua": sec_ch_ua,
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
            "Referer": DEFAULT_SENTINEL_FRAME_URL,
            "Origin": "https://sentinel.openai.com",
        },
        timeout=20,
        verify=False,
    )
    sdk_source = str(getattr(source_resp, "text", "") or "")
    if source_resp.status_code != 200 or "SentinelSDK" not in sdk_source:
        if cached_url and cached_source:
            return cached_url, cached_source
        raise RuntimeError(f"sentinel_sdk_http_{getattr(source_resp, 'status_code', 'unknown')}")

    _sentinel_sdk_asset_cache.update({"sdk_url": sdk_url, "sdk_source": sdk_source, "fetched_at": now})
    return sdk_url, sdk_source


def _run_sentinel_sdk_runner(payload: dict[str, Any]) -> dict[str, Any]:
    node_bin = shutil.which("node")
    if not node_bin:
        raise RuntimeError("node_not_found")
    if not _SENTINEL_SDK_RUNNER.exists():
        raise RuntimeError("sentinel_sdk_runner_missing")
    proc = subprocess.run(
        [node_bin, str(_SENTINEL_SDK_RUNNER)],
        input=json.dumps(payload, ensure_ascii=False),
        text=True,
        capture_output=True,
        timeout=120,
        check=False,
    )
    if proc.returncode != 0:
        stderr = str(proc.stderr or "").strip()
        stdout = str(proc.stdout or "").strip()
        detail = stderr or stdout or f"exit_{proc.returncode}"
        raise RuntimeError(f"sentinel_sdk_runner_failed: {detail[:500]}")
    output = str(proc.stdout or "").strip()
    data = json.loads(output) if output else {}
    return data if isinstance(data, dict) else {}


def build_sentinel_artifacts(
    session: "Session",
    device_id: str,
    flow: str,
    *,
    user_agent: str = "",
    sec_ch_ua: str = "",
    observer_timeout_ms: int = DEFAULT_SENTINEL_FLOW_TIMEOUT_MS,
) -> SentinelArtifacts:
    """请求 sentinel req，并生成 create_account / verify 等流程所需令牌。"""
    ua = user_agent or DEFAULT_SENTINEL_USER_AGENT
    ch_ua = sec_ch_ua or DEFAULT_SENTINEL_SEC_CH_UA
    timeout_ms = max(0, int(observer_timeout_ms or DEFAULT_SENTINEL_FLOW_TIMEOUT_MS))

    try:
        sdk_url, sdk_source = _load_sentinel_sdk_assets(session, user_agent=ua, sec_ch_ua=ch_ua)
        sdk_version = _extract_sdk_version(sdk_url)
        prepare_data = _run_sentinel_sdk_runner(
            {
                "mode": "prepare",
                "sdk_source": sdk_source,
                "sdk_url": sdk_url,
                "device_id": device_id,
                "flow": flow,
                "user_agent": ua,
            }
        )
        prepare_token = str(prepare_data.get("prepare_token") or "").strip()
        if not prepare_token:
            raise RuntimeError("missing_prepare_token")

        resp, data = _request_sentinel_requirements(
            session,
            device_id,
            flow,
            prepare_token,
            user_agent=ua,
            sec_ch_ua=ch_ua,
        )
        challenge_token = str(data.get("token") or "").strip()
        if resp.status_code != 200 or not challenge_token:
            return _build_legacy_artifacts_from_req_data(
                data,
                device_id,
                flow,
                user_agent=ua,
                observer_timeout_ms=timeout_ms,
                sdk_url_override=sdk_url,
                status_code=getattr(resp, "status_code", 0) or 0,
            )

        sdk_data = _run_sentinel_sdk_runner(
            {
                "mode": "artifacts",
                "sdk_source": sdk_source,
                "sdk_url": sdk_url,
                "device_id": device_id,
                "flow": flow,
                "user_agent": ua,
                "prepare_token": prepare_token,
                "req_data": data,
                "observer_timeout_ms": timeout_ms,
            }
        )
        token = str(sdk_data.get("token") or "").strip()
        so_token = str(sdk_data.get("so_token") or "").strip()
        if not token:
            return _build_legacy_artifacts_from_req_data(
                data,
                device_id,
                flow,
                user_agent=ua,
                observer_timeout_ms=timeout_ms,
                sdk_url_override=sdk_url,
                status_code=getattr(resp, "status_code", 0) or 0,
            )
        return SentinelArtifacts(
            token=token,
            oai_sc_value="0" + challenge_token,
            so_token=so_token,
            sdk_url=sdk_url,
            sdk_version=sdk_version,
            flow=flow,
            observer_timeout_ms=timeout_ms,
            raw=data,
        )
    except Exception:
        prepare_token = _requirements_prepare_token(ua, DEFAULT_POW_SCRIPT)
        resp, data = _request_sentinel_requirements(
            session,
            device_id,
            flow,
            prepare_token,
            user_agent=ua,
            sec_ch_ua=ch_ua,
        )
        return _build_legacy_artifacts_from_req_data(
            data,
            device_id,
            flow,
            user_agent=ua,
            observer_timeout_ms=timeout_ms,
            status_code=getattr(resp, "status_code", 0) or 0,
        )


def build_sentinel_token(
    session: "Session",
    device_id: str,
    flow: str,
    *,
    user_agent: str = "",
    sec_ch_ua: str = "",
) -> tuple[str, str]:
    """兼容旧接口：返回 (OpenAI-Sentinel-Token, oai-sc cookie)。"""
    artifacts = build_sentinel_artifacts(
        session,
        device_id,
        flow,
        user_agent=user_agent,
        sec_ch_ua=sec_ch_ua,
    )
    return artifacts.token, artifacts.oai_sc_value

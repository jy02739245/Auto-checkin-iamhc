"""站点（new-api 分支）的接口语义、响应判定与额度格式化。

接口约束来自站点开源的同一份源码（yangqi1309134997-coder/new-api-hcnsec）：
    POST /api/user/login?turnstile=<token>   TurnstileCheck + 返回 data.access_token
    GET  /api/user/self                      Authorization: Bearer <access_token>
    GET  /api/user/checkin?month=YYYY-MM     签到状态
    POST /api/user/checkin?turnstile=<token> TurnstileCheck + 签到
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Optional
from urllib.parse import quote

from . import page_api

DEFAULT_BASE_URL = "https://api.hcnsec.cn"
DEFAULT_QUOTA_PER_UNIT = 500000

STATUS_PATH = "/api/status"
LOGIN_PATH = "/api/user/login"
SELF_PATH = "/api/user/self"
CHECKIN_PATH = "/api/user/checkin"

BEIJING_TZ = timezone(timedelta(hours=8))

# 服务端在「今天已经签到过」时的固定文案
ALREADY_CHECKED_MARKERS = (
    "already checked in today",
    "已签到",
    "重复签到",
)

VERIFICATION_REQUIRED = "verification_required"


class SiteError(Exception):
    """站点接口返回了非预期的结果。"""


class LoginFailed(SiteError):
    """账号密码没通过。"""


class LoginVerificationRequired(SiteError):
    """账号开了 2FA / Passkey 等二次验证，脚本没法自动完成。"""


class CheckinFailed(SiteError):
    """签到接口明确失败。"""


@dataclass
class LoginResult:
    access_token: str
    user: dict


def base_url() -> str:
    """站点地址，可用 IAMHC_BASE_URL 覆盖（站点换过域名）。"""
    return (os.environ.get("IAMHC_BASE_URL") or DEFAULT_BASE_URL).rstrip("/")


def beijing_now() -> str:
    return datetime.now(BEIJING_TZ).strftime("%Y-%m-%d %H:%M:%S")


def current_month() -> str:
    return datetime.now(BEIJING_TZ).strftime("%Y-%m")


def classify_login(payload: dict) -> tuple[str, Any]:
    """判定登录响应：("ok", data) / ("verification", data) / ("failed", message)。"""
    if not isinstance(payload, dict):
        return "failed", "登录响应不是 JSON"

    if payload.get("success"):
        data = payload.get("data") or {}
        if data.get("require_verification"):
            return "verification", data
        if not data.get("access_token"):
            return "failed", "登录成功但响应里没有 access_token"
        return "ok", data

    return "failed", _message_of(payload) or "登录失败"


def classify_checkin(payload: dict) -> tuple[str, Any]:
    """判定签到响应：("ok", data) / ("already", None) / ("failed", message)。"""
    if not isinstance(payload, dict):
        return "failed", "签到响应不是 JSON"

    if payload.get("success"):
        return "ok", payload.get("data") or {}

    message = _message_of(payload)
    lowered = message.lower()
    if any(marker in lowered or marker in message for marker in ALREADY_CHECKED_MARKERS):
        return "already", None
    return "failed", message or "签到失败"


def _message_of(payload: dict) -> str:
    return str(payload.get("message") or payload.get("message_key") or "")


def status(sb: Any) -> dict:
    """读取公开配置：Turnstile 是否开启、site key、额度换算方式。"""
    result = _get_json(sb, STATUS_PATH)
    data = result.get("data") if isinstance(result.get("data"), dict) else result
    if not isinstance(data, dict) or "turnstile_check" not in data:
        raise SiteError(f"/api/status 返回不符合预期: {result}")
    return data


def login(sb: Any, username: str, password: str, turnstile_token: str = "") -> LoginResult:
    path = LOGIN_PATH
    if turnstile_token:
        path = f"{path}?turnstile={quote(turnstile_token)}"

    result = page_api.request(
        sb,
        "POST",
        path,
        body={"username": username, "password": password},
    )
    if not result.ok():
        raise LoginFailed(f"登录请求失败: {result.describe()}")

    kind, value = classify_login(result.payload or {})
    if kind == "verification":
        methods = value.get("methods") or []
        names = "、".join(str(m.get("method") or m.get("type") or "") for m in methods)
        raise LoginVerificationRequired(
            f"账号开启了二次验证（{names or '2FA/Passkey'}），脚本无法自动完成"
        )
    if kind == "failed":
        raise LoginFailed(str(value))

    data = value
    user = data.get("user") or {}
    return LoginResult(access_token=str(data["access_token"]), user=user)


def self_info(sb: Any, access_token: str) -> dict:
    result = page_api.request(sb, "GET", SELF_PATH, token=access_token)
    if not result.ok():
        raise SiteError(f"获取用户信息失败: {result.describe()}")
    payload = result.payload or {}
    if not payload.get("success"):
        raise SiteError(f"获取用户信息失败: {_message_of(payload)}")
    data = payload.get("data")
    if not isinstance(data, dict):
        raise SiteError("用户信息里没有 data")
    return data


def checkin_overview(sb: Any, access_token: str, month: Optional[str] = None) -> dict:
    path = f"{CHECKIN_PATH}?month={month or current_month()}"
    result = page_api.request(sb, "GET", path, token=access_token)
    if not result.ok():
        raise SiteError(f"获取签到状态失败: {result.describe()}")
    payload = result.payload or {}
    if not payload.get("success"):
        raise SiteError(f"获取签到状态失败: {_message_of(payload)}")
    data = payload.get("data")
    if not isinstance(data, dict):
        raise SiteError("签到状态里没有 data")
    return data


def checked_in_today(overview: dict) -> bool:
    stats = overview.get("stats") or {}
    return bool(stats.get("checked_in_today"))


def do_checkin(sb: Any, access_token: str, turnstile_token: str = "") -> Optional[dict]:
    """执行签到。返回 data（含 quota_awarded）；今日已签到返回 None。"""
    path = CHECKIN_PATH
    if turnstile_token:
        path = f"{path}?turnstile={quote(turnstile_token)}"

    result = page_api.request(sb, "POST", path, token=access_token, body={})
    if not result.ok():
        raise CheckinFailed(f"签到请求失败: {result.describe()}")

    kind, value = classify_checkin(result.payload or {})
    if kind == "already":
        return None
    if kind == "failed":
        raise CheckinFailed(str(value))
    return value


def format_quota(quota: Any, settings: dict) -> str:
    """把内部 quota 按站点配置换算成展示金额。

    站点默认 display_in_currency + CNY + usd_exchange_rate，1 美元 = quota_per_unit。
    """
    try:
        amount = int(quota or 0)
    except (TypeError, ValueError):
        amount = 0

    if settings.get("display_in_currency") is False:
        return f"{amount:,}"

    per_unit = _as_float(settings.get("quota_per_unit"), DEFAULT_QUOTA_PER_UNIT)
    if per_unit <= 0:
        per_unit = DEFAULT_QUOTA_PER_UNIT
    usd = amount / per_unit

    display = str(settings.get("quota_display_type") or "USD").upper()
    if display == "TOKENS":
        return f"{amount:,}"

    rate = _as_float(settings.get("usd_exchange_rate"), 1.0) or 1.0
    if display == "CNY":
        return f"¥{usd * rate:,.2f}"
    if display == "CUSTOM":
        symbol = str(settings.get("custom_currency_symbol") or "¤")
        return f"{symbol}{usd * rate:,.2f}"
    return f"${usd:,.2f}"


def _as_float(value: Any, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _get_json(sb: Any, path: str) -> dict:
    result = page_api.request(sb, "GET", path)
    if not result.ok():
        raise SiteError(f"{path} 请求失败: {result.describe()}")
    return result.payload or {}

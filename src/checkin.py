"""iamhc（api.hcnsec.cn）自动签到主流程。

站点改版后登录和签到都要过 Cloudflare Turnstile（登录被 401 挡掉就是这个原因），
所以流程跑在真实浏览器里：SeleniumBase UC 模式打开站点 → 过盾拿 token →
在页面上下文里调站内 API（登录 / 查余额 / 签到）。

环境变量：
    EMAIL / IAMHC_EMAIL         登录邮箱（必填）
    PASSWORD / IAMHC_PASSWORD   登录密码（必填）
    NODE_LINK                   节点分享链接（可选，经 sing-box 转成本地代理）
    TG_BOT_TOKEN / TG_CHAT_ID   Telegram 推送（可选）
    IAMHC_BASE_URL              站点地址，默认 https://api.hcnsec.cn

退出码：
    0 - 签到成功，或本日已签到
    1 - 重试 3 次后仍失败
    2 - 配置错误
"""

from __future__ import annotations

import os
import sys
import time
import traceback
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Iterator, Optional

from . import browser, notify, proxy_node, site
from .env import load_local_env

MAX_ATTEMPTS = 3
RETRY_INTERVAL_SECONDS = 30
PAGE_READY_TIMEOUT_SECONDS = 45

STATUS_SUCCESS = "签到成功"
STATUS_ALREADY = "本日已签到"


@dataclass
class Result:
    status: str
    username: str
    awarded: int = 0
    balance_before: int = 0
    balance_after: int = 0
    settings: dict = field(default_factory=dict)


def _get_env(*names: str) -> str:
    for name in names:
        value = (os.environ.get(name) or "").strip()
        if value:
            return value
    return ""


def _turnstile_token(sb, settings: dict, screenshot_name: str) -> str:
    """按站点配置决定是否要过盾，要的话渲染 widget 并拿一个 token。"""
    if not settings.get("turnstile_check"):
        return ""

    site_key = str(settings.get("turnstile_site_key") or "").strip()
    if not site_key:
        raise site.SiteError("站点开启了 Turnstile，但 /api/status 没有返回 site key")

    token = browser.obtain_turnstile_token(sb, site_key)
    browser.screenshot(sb, screenshot_name)
    return token


def _open_site(sb) -> dict:
    base = site.base_url()
    browser.open_url(sb, base)

    if not browser.wait_app_ready(sb, timeout=PAGE_READY_TIMEOUT_SECONDS):
        browser.screenshot(sb, "01-site-not-ready")
        raise site.SiteError(
            f"站点 {PAGE_READY_TIMEOUT_SECONDS}s 内未就绪"
            f"（当前 {browser.current_url(sb)}），可能是 WAF 拦截页"
        )

    browser.screenshot(sb, "01-site-ready")
    settings = site.status(sb)
    print(
        "[checkin] 站点配置 | "
        f"name={settings.get('system_name')} version={settings.get('version')} "
        f"checkin={settings.get('checkin_enabled')} turnstile={settings.get('turnstile_check')}"
    )

    if settings.get("checkin_enabled") is False:
        raise site.SiteError("站点已关闭签到功能")
    return settings


def _run_once(sb, email: str, password: str) -> Result:
    settings = _open_site(sb)

    if settings.get("password_login_encryption_enabled"):
        # 站点若打开「密码加密登录」，登录请求要带 RSA-OAEP + AES-GCM 的密文，
        # 当前脚本只发明文密码，这里显式报错，免得只看到一个 Invalid parameters。
        raise site.SiteError(
            "站点启用了密码加密登录（password_login_encryption_enabled），当前脚本不支持；"
            "需要在 src/site.py 里按站点 /api/user/login/encryption-key 补加密逻辑"
        )

    login_token = _turnstile_token(sb, settings, "02-login-turnstile")
    login = site.login(sb, email, password, login_token)
    user = login.user
    username = str(user.get("username") or email)
    print(f"✅ 登录成功 | 账户: {username} | ID: {user.get('id')}")

    access_token = login.access_token
    info_before = site.self_info(sb, access_token)
    balance_before = int(info_before.get("quota") or 0)

    overview = site.checkin_overview(sb, access_token)
    if site.checked_in_today(overview):
        print(f"✅ 今日已签到 | 当前余额: {site.format_quota(balance_before, settings)}")
        return Result(
            status=STATUS_ALREADY,
            username=username,
            balance_before=balance_before,
            balance_after=balance_before,
            settings=settings,
        )

    checkin_data = site.do_checkin(
        sb, access_token, _turnstile_token(sb, settings, "03-checkin-turnstile")
    )

    if checkin_data is None:
        print(f"✅ 今日已签到（签到接口判定）| 当前余额: {site.format_quota(balance_before, settings)}")
        return Result(
            status=STATUS_ALREADY,
            username=username,
            balance_before=balance_before,
            balance_after=balance_before,
            settings=settings,
        )

    awarded = int(checkin_data.get("quota_awarded") or 0)

    # 签到后重新拉一次余额；失败也不影响签到结论
    balance_after = balance_before + awarded
    try:
        info_after = site.self_info(sb, access_token)
        balance_after = int(info_after.get("quota") or balance_after)
    except site.SiteError as exc:
        print(f"[checkin] 获取签到后余额失败，按签到金额估算: {exc}")

    print(f"✅ 签到成功 | 获得: {site.format_quota(awarded, settings)}")
    return Result(
        status=STATUS_SUCCESS,
        username=username,
        awarded=awarded,
        balance_before=balance_before,
        balance_after=balance_after,
        settings=settings,
    )


def _build_message(result: Result) -> str:
    settings = result.settings
    if result.status == STATUS_ALREADY:
        head = "✅ 今日你已经签到过了！"
    else:
        head = f"✅ 签到成功，本次获得 {site.format_quota(result.awarded, settings)}"

    return (
        "🎁 iamhc 签到通知\n\n"
        f"{head}\n"
        f"👤 登录账户: {result.username}\n"
        f"💰 签到前余额: {site.format_quota(result.balance_before, settings)}\n"
        f"💰 当前余额: {site.format_quota(result.balance_after, settings)}\n"
        f"⏱️ 签到时间: {site.beijing_now()}"
    )


@contextmanager
def _browser_proxy(proxy_url: Optional[str]) -> Iterator[None]:
    """让节点代理只影响浏览器，不改 Telegram 等其他 requests 的出口。"""
    old_value = os.environ.get(browser.BROWSER_PROXY_ENV)
    try:
        if proxy_url:
            os.environ[browser.BROWSER_PROXY_ENV] = proxy_url
            print(f"[node] 浏览器使用本地代理: {proxy_url}")
        yield
    finally:
        if old_value is None:
            os.environ.pop(browser.BROWSER_PROXY_ENV, None)
        else:
            os.environ[browser.BROWSER_PROXY_ENV] = old_value


def _run_attempts(email: str, password: str, proxy_url: Optional[str]) -> int:
    last_error: Optional[Exception] = None

    with _browser_proxy(proxy_url):
        for attempt in range(1, MAX_ATTEMPTS + 1):
            print(f"\n========== 尝试 {attempt}/{MAX_ATTEMPTS} ==========")
            try:
                with browser.open_browser() as sb:
                    try:
                        result = _run_once(sb, email, password)
                    except Exception:
                        browser.screenshot(sb, f"failure-attempt-{attempt}")
                        raise
                    browser.screenshot(sb, "06-result")

                notify.send(_build_message(result))
                print("[main] 任务完成")
                return 0
            except Exception as exc:
                last_error = exc
                print(f"[main] 第 {attempt} 次失败: {type(exc).__name__}: {exc}")
                traceback.print_exc()

            if attempt < MAX_ATTEMPTS:
                print(f"[main] {RETRY_INTERVAL_SECONDS}s 后重试...")
                time.sleep(RETRY_INTERVAL_SECONDS)

    summary = f"{type(last_error).__name__}: {last_error}" if last_error else "未知错误"
    print(f"\n[main] {MAX_ATTEMPTS} 次尝试均失败: {summary}")
    notify.send_failure(summary, MAX_ATTEMPTS)
    return 1


def _smoke_turnstile() -> int:
    """只验证「能不能过盾」：不登录，拿到一个 Turnstile token 就退出。"""
    browser.clean_screenshots()
    try:
        with proxy_node.maybe_launch() as proxy_url:
            with _browser_proxy(proxy_url):
                with browser.open_browser() as sb:
                    settings = _open_site(sb)
                    if not settings.get("turnstile_check"):
                        print("[smoke] 站点当前未开启 Turnstile，无需过盾")
                        return 0
                    token = _turnstile_token(sb, settings, "smoke-turnstile")
                    print(f"[smoke] Turnstile token 已拿到，长度 {len(token)}")
        return 0
    except Exception as exc:
        print(f"[smoke] 失败: {type(exc).__name__}: {exc}")
        traceback.print_exc()
        return 1


def main() -> int:
    loaded = load_local_env()
    if loaded:
        print(f"[env] 已从本地 env 文件加载: {', '.join(loaded)}")

    if "--smoke-turnstile" in sys.argv:
        return _smoke_turnstile()

    email = _get_env("EMAIL", "IAMHC_EMAIL", "IAMHC_USERNAME")
    password = _get_env("PASSWORD", "IAMHC_PASSWORD")
    if not email or not password:
        print("[fatal] 请设置 EMAIL 和 PASSWORD 环境变量")
        return 2

    browser.clean_screenshots()

    try:
        with proxy_node.maybe_launch() as proxy_url:
            return _run_attempts(email, password, proxy_url)
    except Exception as exc:
        # 节点解析、sing-box 启动失败属于任务失败，也要通知并给出清晰日志
        summary = f"{type(exc).__name__}: {exc}"
        print(f"[main] 节点代理初始化失败: {summary}")
        traceback.print_exc()
        notify.send_failure(summary, 0)
        return 1


if __name__ == "__main__":
    sys.exit(main())

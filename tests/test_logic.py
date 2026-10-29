"""不依赖浏览器的判定逻辑测试。

覆盖：登录/签到响应判定、额度格式化、页面内 fetch 桥的轮询、代理环境变量。
运行：python -m pytest
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src import browser, page_api, proxy_node, site  # noqa: E402


# ---------------------------------------------------------------- 登录响应判定


def test_classify_login_success():
    kind, data = site.classify_login(
        {"success": True, "data": {"access_token": "tok", "user": {"id": 1}}}
    )
    assert kind == "ok"
    assert data["access_token"] == "tok"


def test_classify_login_requires_verification():
    kind, data = site.classify_login(
        {
            "success": True,
            "data": {"require_verification": True, "flow_token": "flow"},
        }
    )
    assert kind == "verification"
    assert data["flow_token"] == "flow"


def test_classify_login_failure_uses_message():
    kind, message = site.classify_login(
        {"success": False, "message": "Turnstile verification failed"}
    )
    assert kind == "failed"
    assert "Turnstile" in message


def test_classify_login_without_access_token_is_failure():
    kind, message = site.classify_login({"success": True, "data": {"user": {}}})
    assert kind == "failed"
    assert "access_token" in message


def test_classify_login_with_html_body():
    kind, message = site.classify_login({"not": "json"})
    assert kind == "failed"
    assert message


# ---------------------------------------------------------------- 签到响应判定


def test_classify_checkin_success():
    kind, data = site.classify_checkin(
        {"success": True, "data": {"quota_awarded": 12345}}
    )
    assert kind == "ok"
    assert data["quota_awarded"] == 12345


@pytest.mark.parametrize(
    "message",
    ["Already checked in today", "今天已签到", "重复签到"],
)
def test_classify_checkin_already(message):
    kind, data = site.classify_checkin({"success": False, "message": message})
    assert kind == "already"
    assert data is None


def test_classify_checkin_turnstile_failure_is_not_already():
    kind, message = site.classify_checkin(
        {"success": False, "message": "Turnstile token is empty"}
    )
    assert kind == "failed"
    assert "Turnstile" in message


# ---------------------------------------------------------------- 签到状态


@pytest.mark.parametrize(
    "stats, expected",
    [
        ({"checked_in_today": True}, True),
        ({"checked_in_today": False}, False),
        ({}, False),
    ],
)
def test_checked_in_today(stats, expected):
    assert site.checked_in_today({"stats": stats}) is expected


# ---------------------------------------------------------------- 额度格式化


CNY_SETTINGS = {
    "quota_per_unit": 500000,
    "display_in_currency": True,
    "quota_display_type": "CNY",
    "usd_exchange_rate": 7.3,
}


def test_format_quota_cny():
    assert site.format_quota(500000, CNY_SETTINGS) == "¥7.30"


def test_format_quota_usd():
    settings = dict(CNY_SETTINGS, quota_display_type="USD")
    assert site.format_quota(1000000, settings) == "$2.00"


def test_format_quota_tokens():
    settings = dict(CNY_SETTINGS, quota_display_type="TOKENS")
    assert site.format_quota(1234567, settings) == "1,234,567"


def test_format_quota_without_currency_display():
    settings = dict(CNY_SETTINGS, display_in_currency=False)
    assert site.format_quota(1234567, settings) == "1,234,567"


def test_format_quota_falls_back_to_defaults():
    assert site.format_quota(500000, {"quota_display_type": "USD"}) == "$1.00"
    assert site.format_quota(None, {}) == "$0.00"


# ---------------------------------------------------------------- 页面内请求桥


class FakeApiSB:
    """按脚本内容返回预设结果，模拟页面内 fetch 的完成态。"""

    def __init__(self, result=None, never_finishes=False):
        self.result = result or {}
        self.never_finishes = never_finishes
        self.scripts: list[str] = []
        self.calls: list[tuple] = []

    def execute_script(self, script, *args):
        self.scripts.append(script)
        self.calls.append(args)
        if "window.__iamhcApiResults" in script and "fetch(" in script:
            return 7
        if "return results[arguments[0]]" in script:
            if self.never_finishes:
                return {"pending": True}
            return dict(self.result, pending=False)
        raise AssertionError(f"未预期的脚本: {script[:60]}")


def test_page_api_returns_payload():
    sb = FakeApiSB({"status": 200, "json": {"success": True}, "text": "", "error": ""})
    result = page_api.request(sb, "GET", "/api/status")
    assert result.ok()
    assert result.payload == {"success": True}


def test_page_api_raises_on_timeout():
    sb = FakeApiSB(never_finishes=True)
    with pytest.raises(page_api.PageApiError):
        page_api.request(sb, "GET", "/api/status", timeout=0.1)


def test_page_api_serializes_dict_body():
    sb = FakeApiSB({"status": 200, "json": {}, "text": "", "error": ""})
    page_api.request(sb, "POST", "/api/user/login", body={"username": "a"})
    method, path, token, body = sb.calls[0]
    assert (method, path, token) == ("POST", "/api/user/login", "")
    assert body == '{"username": "a"}'


def test_page_api_passes_bearer_token():
    sb = FakeApiSB({"status": 200, "json": {}, "text": "", "error": ""})
    page_api.request(sb, "GET", "/api/user/self", token="abc")
    assert sb.calls[0][2] == "abc"


# ---------------------------------------------------------------- 浏览器参数


def test_gui_click_can_be_disabled_by_env(monkeypatch):
    monkeypatch.setenv(browser.DISABLE_GUI_CLICK_ENV, "1")
    assert browser._gui_click_enabled() is False
    monkeypatch.setenv(browser.DISABLE_GUI_CLICK_ENV, "")
    assert browser._gui_click_enabled() is True


def test_browser_proxy_prefers_dedicated_env(monkeypatch):
    monkeypatch.setenv(browser.BROWSER_PROXY_ENV, "http://127.0.0.1:7890")
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:1080")
    assert browser._resolve_browser_proxy() == "http://127.0.0.1:7890"


def test_browser_proxy_falls_back_to_shell_env(monkeypatch):
    monkeypatch.delenv(browser.BROWSER_PROXY_ENV, raising=False)
    monkeypatch.delenv("HTTPS_PROXY", raising=False)
    monkeypatch.delenv("https_proxy", raising=False)
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:1080")
    assert browser._resolve_browser_proxy() == "http://127.0.0.1:1080"


# ---------------------------------------------------------------- 节点链接


@pytest.mark.parametrize(
    "link, outbound_type",
    [
        (
            "vless://11111111-2222-3333-4444-555555555555@example.com:443"
            "?security=tls&sni=example.com&type=ws&path=%2Fws",
            "vless",
        ),
        ("trojan://password@example.com:443?sni=example.com", "trojan"),
        (
            "tuic://11111111-2222-3333-4444-555555555555:pass@example.com:443"
            "?sni=example.com",
            "tuic",
        ),
        ("hysteria2://pass@example.com:443?sni=example.com", "hysteria2"),
        ("anytls://pass@example.com:443?sni=example.com", "anytls"),
        ("anttls://pass@example.com:443?sni=example.com", "anytls"),
        ("socks5://127.0.0.1:1080", "socks"),
    ],
)
def test_proxy_node_protocols(link, outbound_type):
    assert proxy_node.parse_link(link)["type"] == outbound_type


def test_chrome_native_proxy_is_left_alone():
    link = "socks5://127.0.0.1:1080"
    assert proxy_node.chrome_native_proxy(link) == link


def test_complex_proxy_uses_sing_box():
    link = "vless://11111111-2222-3333-4444-555555555555@example.com:443"
    assert proxy_node.chrome_native_proxy(link) is None
    config = proxy_node.build_config(link, 1081)
    assert config["inbounds"][0]["type"] == "mixed"
    assert config["route"]["final"] == "node"


def test_node_link_env_prefers_iamhc_alias(monkeypatch):
    monkeypatch.setenv("NODE_LINK", "trojan://a@b:443")
    monkeypatch.setenv("IAMHC_NODE_LINK", "trojan://c@d:443")
    assert proxy_node.node_link_from_env() == "trojan://c@d:443"

    monkeypatch.delenv("IAMHC_NODE_LINK")
    assert proxy_node.node_link_from_env() == "trojan://a@b:443"

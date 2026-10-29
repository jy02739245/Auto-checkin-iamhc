"""Telegram 通知（可选）。

读取 TG_BOT_TOKEN / TG_CHAT_ID（兼容 TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID）。
任意一个未设置时静默跳过；任何网络异常都被吃掉，不影响主流程。
"""

from __future__ import annotations

import os

import requests

from . import site


def _config() -> tuple[str, str]:
    token = (os.environ.get("TG_BOT_TOKEN") or os.environ.get("TELEGRAM_BOT_TOKEN") or "").strip()
    chat_id = (os.environ.get("TG_CHAT_ID") or os.environ.get("TELEGRAM_CHAT_ID") or "").strip()
    return token, chat_id


def is_configured() -> bool:
    token, chat_id = _config()
    return bool(token and chat_id)


def send(text: str) -> bool:
    """发送一条纯文本消息。返回是否发送成功（未配置时返回 False 但不报错）。"""
    print("\n" + "=" * 25)
    print(text)
    print("=" * 25)

    if not is_configured():
        print("[notify] TG_BOT_TOKEN / TG_CHAT_ID 未配置，跳过 Telegram 推送")
        return False

    token, chat_id = _config()
    url = f"https://api.telegram.org/bot{token}/sendMessage"

    try:
        resp = requests.post(
            url,
            data={
                "chat_id": chat_id,
                "text": text,
                "disable_web_page_preview": "true",
            },
            timeout=10,
        )
        if resp.status_code != 200:
            print(f"[notify] Telegram 返回 {resp.status_code}: {_sanitize(resp.text[:200])}")
            return False
        print("[notify] Telegram 推送成功")
        return True
    except Exception as exc:
        print(f"[notify] Telegram 推送异常: {type(exc).__name__}: {_sanitize(str(exc))}")
        return False


def send_failure(summary: str, attempts: int) -> bool:
    run_url = os.environ.get("GITHUB_RUN_URL", "(本地运行)")
    lines = [
        "🎁 iamhc 签到通知",
        "",
        f"❌ 签到失败: {summary}",
        f"🔁 重试次数: {attempts}",
        f"⏱️ 时间: {site.beijing_now()}",
        f"🔗 日志: {run_url}",
    ]
    return send("\n".join(lines))


def _sanitize(text: str) -> str:
    """避免把 bot token / chat id 带进日志。"""
    token, chat_id = _config()
    message = text
    for secret in (token, chat_id):
        if secret:
            message = message.replace(secret, "<redacted>")
    return message

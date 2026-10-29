"""在页面上下文里调站内 API。

为什么不用 requests：站点的登录和签到都要求 `?turnstile=<token>`，而 token 只能在
同源页面里由 Turnstile 发出来；另外请求从浏览器里发出时，Cookie、Origin、Referer
和风控指纹都是原生的，比脚本拼 headers 稳。

做法：注入一个 fetch，把结果挂到 window.__iamhcApiResults[seq] 上，再轮询取回。
（不用 execute_async_script，是因为轮询更好排查：超时了还能看到请求卡在哪一步。）
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any, Optional

from . import browser

FETCH_JS = r"""
const method = arguments[0];
const path = arguments[1];
const token = arguments[2];
const body = arguments[3];
const seq = (window.__iamhcSeq = (window.__iamhcSeq || 0) + 1);
const results = window.__iamhcApiResults = window.__iamhcApiResults || {};
results[seq] = {pending: true};

const headers = {Accept: 'application/json'};
if (body !== null && body !== undefined) {
  headers['Content-Type'] = 'application/json';
}
if (token) {
  headers['Authorization'] = 'Bearer ' + token;
}

fetch(path, {
  method: method,
  headers: headers,
  body: (body === null || body === undefined) ? undefined : body,
  credentials: 'include',
  cache: 'no-store',
}).then(async (response) => {
  const text = await response.text();
  let parsed = null;
  try {
    parsed = JSON.parse(text);
  } catch (e) {
    parsed = null;
  }
  results[seq] = {
    pending: false,
    status: response.status,
    json: parsed,
    text: parsed === null ? text.slice(0, 500) : '',
    error: '',
  };
}).catch((e) => {
  results[seq] = {pending: false, status: 0, json: null, text: '', error: String(e)};
});
return seq;
"""

RESULT_JS = r"""
const results = window.__iamhcApiResults || {};
return results[arguments[0]] || null;
"""


class PageApiError(Exception):
    """页面内请求失败（网络错误、超时、非 JSON 响应）。"""


@dataclass
class ApiResult:
    status: int
    payload: Optional[dict]
    text: str
    error: str

    def ok(self) -> bool:
        return self.status == 200 and isinstance(self.payload, dict)

    def describe(self) -> str:
        if self.error:
            return f"请求异常: {self.error}"
        if self.payload is not None:
            return f"HTTP {self.status}: {json.dumps(self.payload, ensure_ascii=False)[:300]}"
        return f"HTTP {self.status}: {self.text[:300]}"


def request(
    sb: Any,
    method: str,
    path: str,
    *,
    token: Optional[str] = None,
    body: Optional[dict | str] = None,
    timeout: float = 30,
) -> ApiResult:
    """在页面里发一个同源请求，等它返回。

    body 传 dict 会自动序列化成 JSON；传 None 表示没有请求体。
    """
    if isinstance(body, (dict, list)):
        body_text: Optional[str] = json.dumps(body, ensure_ascii=False)
    else:
        body_text = body

    seq = browser.run_js_with_args(sb, FETCH_JS, method, path, token or "", body_text)
    if not isinstance(seq, int):
        raise PageApiError(f"{method} {path} 注入请求失败: {seq!r}")

    deadline = time.time() + timeout
    while time.time() < deadline:
        state = browser.run_js_with_args(sb, RESULT_JS, seq)
        if isinstance(state, dict) and not state.get("pending"):
            return ApiResult(
                status=int(state.get("status") or 0),
                payload=state.get("json") if isinstance(state.get("json"), dict) else None,
                text=str(state.get("text") or ""),
                error=str(state.get("error") or ""),
            )
        time.sleep(0.25)

    raise PageApiError(f"{method} {path} {timeout}s 内没有返回")

"""SeleniumBase UC 模式浏览器：登录 / 签到用的真实浏览器 + Turnstile 过盾 + 截图。

约定：
- 用 UC 模式（打过补丁的 uc_driver + disconnect/reconnect）启动有头 Chrome
- Linux 上不开 headless，由 Xvfb 提供虚拟显示（SeleniumBase 会自行拉起）
- 站点把 Turnstile 渲染进 closed shadow DOM，document 里查不到 iframe，
  所以自己建一个固定位置的容器，按容器坐标发真实系统级鼠标点击
- 截图统一保存到项目根目录的 screenshots/ 下
"""

from __future__ import annotations

import os
import platform
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, Optional

from seleniumbase import SB

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SCREENSHOT_DIR = PROJECT_ROOT / "screenshots"
SCREENSHOT_DIR.mkdir(exist_ok=True)

USER_AGENT_ENV = "IAMHC_USER_AGENT"
BROWSER_PROXY_ENV = "IAMHC_BROWSER_PROXY"
DISABLE_GUI_CLICK_ENV = "IAMHC_DISABLE_GUI_CLICK"
CHROME_PATH_ENV = "CHROME_PATH"

# 浏览器窗口要明显小于虚拟屏幕，否则 PyAutoGUI 的点击坐标可能落到屏幕外
WINDOW_SIZE = "1280,860"
XVFB_METRICS = "1920,1080"

TURNSTILE_CONTAINER_ID = "iamhc-turnstile"
# 复选框圆心相对容器左上角的位置。widget 本体固定 300x72（CSS 像素），
# 实测圆形复选框中心在 (24, 30) 附近，点这里比点边缘稳。
TURNSTILE_CHECKBOX_OFFSET_X = 24
TURNSTILE_CHECKBOX_OFFSET_Y = 30
# 先给 Turnstile 一点自己通过的时间，再动手点
TURNSTILE_GRACE_SECONDS = 10
TURNSTILE_CLICK_WAIT_SECONDS = 8

# 整站验证 / 拦截页的标题特征；只匹配标题，避免误伤正文里出现的普通词
INTERSTITIAL_TITLE_MARKERS = (
    "Just a moment",
    "请稍候",
    "稍候",
    "Attention Required",
    "Verify you are human",
    "验证您是真人",
    "验证你是真人",
    "安全验证",
    "Access denied",
)

CHALLENGE_DOM_JS = r"""
return !!document.querySelector(
  '#challenge-form, #challenge-stage, #challenge-running, #cf-please-wait, #cf-challenge-running'
);
"""

PAGE_STATE_JS = r"""
return {
  ready: document.readyState === 'complete' && typeof window.fetch === 'function',
  title: document.title || '',
};
"""

TURNSTILE_INSTALL_JS = r"""
const sitekey = arguments[0];
const containerId = arguments[1];
let container = document.getElementById(containerId);
if (!container) {
  container = document.createElement('div');
  container.id = containerId;
  container.style.cssText = [
    'position:fixed',
    'left:24px',
    'top:24px',
    'z-index:2147483647',
    'background:#ffffff',
    'padding:0',
    'border-radius:6px',
    'box-shadow:0 0 0 2px #ff4d4f, 0 6px 16px rgba(0,0,0,0.25)'
  ].join(';');
  document.body.appendChild(container);
}

const state = window.__iamhcTurnstile = window.__iamhcTurnstile || {};
state.token = '';
state.error = '';
state.rendered = false;

const render = () => {
  if (!window.turnstile) {
    return false;
  }
  try {
    if (state.widgetId !== undefined && state.widgetId !== null) {
      window.turnstile.remove(state.widgetId);
    }
  } catch (e) {
    /* 上一个 widget 可能已经不在了 */
  }
  container.innerHTML = '';
  try {
    state.widgetId = window.turnstile.render(container, {
      sitekey: sitekey,
      callback: (token) => { state.token = token; },
      'error-callback': (code) => { state.error = String(code); },
      'expired-callback': () => { state.token = ''; },
    });
    state.rendered = true;
    return true;
  } catch (e) {
    state.error = String(e);
    return false;
  }
};

if (render()) {
  return 'rendered';
}

const scriptId = 'iamhc-turnstile-script';
let script = document.getElementById(scriptId);
if (!script) {
  script = document.createElement('script');
  script.id = scriptId;
  script.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit';
  script.async = true;
  script.defer = true;
  script.onload = render;
  script.onerror = () => {
    // 移除失败的 script 标签，下一次 install 才会重新拉取
    state.error = 'script-load-failed';
    script.remove();
  };
  document.head.appendChild(script);
}
return 'loading';
"""

TURNSTILE_STATE_JS = r"""
const state = window.__iamhcTurnstile || {};
return {
  token: state.token || '',
  error: state.error || '',
  rendered: !!state.rendered,
};
"""


def _is_linux() -> bool:
    return platform.system() == "Linux"


def _gui_click_enabled() -> bool:
    """本地调试时可以关掉真实鼠标点击，避免脚本抢走物理鼠标。"""
    flag = os.environ.get(DISABLE_GUI_CLICK_ENV, "").strip().lower()
    return flag not in ("1", "true", "yes", "on")


def _resolve_browser_proxy() -> Optional[str]:
    """优先读专用变量，再回落到 shell 里已有的 HTTP(S) 代理。"""
    candidates = (
        os.environ.get(BROWSER_PROXY_ENV, ""),
        os.environ.get("HTTPS_PROXY", ""),
        os.environ.get("https_proxy", ""),
        os.environ.get("HTTP_PROXY", ""),
        os.environ.get("http_proxy", ""),
        os.environ.get("ALL_PROXY", ""),
        os.environ.get("all_proxy", ""),
    )
    for raw in candidates:
        proxy = (raw or "").strip()
        if proxy:
            return proxy
    return None


def _sb_kwargs() -> dict[str, Any]:
    """组装 SeleniumBase 启动参数。"""
    kwargs: dict[str, Any] = {
        "uc": True,
        "test": False,
        "locale": "zh-CN",
        "window_size": WINDOW_SIZE,
        # UC 模式默认想占用固定的 9222 调试端口，本机已有 Chrome 开着调试端口时会直接起不来。
        # multi_proxy 会让它改用随机空闲端口，除此之外对我们没有影响。
        "multi_proxy": True,
    }

    if _is_linux():
        # 不用 headless：Cloudflare 会直接识别；改用 Xvfb 提供的虚拟显示
        kwargs["xvfb"] = True
        kwargs["xvfb_metrics"] = XVFB_METRICS

    proxy = _resolve_browser_proxy()
    if proxy:
        kwargs["proxy"] = proxy
        print(f"[browser] 使用代理: {proxy}")

    user_agent = os.environ.get(USER_AGENT_ENV, "").strip()
    if user_agent:
        # 默认不改 UA：UC 模式下真实 Chrome UA 才是最安全的选择
        kwargs["agent"] = user_agent
        print(f"[browser] 使用自定义 User-Agent: {user_agent}")

    chrome_path = os.environ.get(CHROME_PATH_ENV, "").strip()
    if chrome_path and os.path.exists(chrome_path):
        kwargs["binary_location"] = chrome_path
        print(f"[browser] 使用 Chrome: {chrome_path}")

    return kwargs


class TurnstileFailed(Exception):
    """Turnstile 超时未通过。"""


@contextmanager
def open_browser() -> Iterator[Any]:
    """启动 UC 模式浏览器，退出时自动关闭。"""
    kwargs = _sb_kwargs()
    print(f"[browser] 启动 SeleniumBase UC 模式 (DISPLAY={os.environ.get('DISPLAY')})")
    with SB(**kwargs) as sb:
        yield sb


def clean_screenshots() -> int:
    """删除上一次运行留下的 PNG 截图，返回删除数量。"""
    removed = 0
    for path in SCREENSHOT_DIR.glob("*.png"):
        if not path.is_file():
            continue
        try:
            path.unlink()
            removed += 1
        except Exception as exc:
            print(f"[browser] 清理截图失败 ({path}): {exc}")

    if removed:
        print(f"[browser] 已清理旧截图: {removed} 个")
    return removed


def screenshot(sb: Any, name: str) -> Optional[Path]:
    """保存截图到 screenshots/<name>.png，失败返回 None。"""
    target = SCREENSHOT_DIR / f"{name}.png"
    try:
        sb.save_screenshot(f"{name}.png", folder=str(SCREENSHOT_DIR))
        print(f"[browser] 截图已保存: {target}")
        return target
    except Exception as exc:
        print(f"[browser] 截图失败 ({name}): {exc}")
        return None


def run_js(sb: Any, script: str, default: Any = None) -> Any:
    try:
        return sb.execute_script(script)
    except Exception as exc:
        print(f"[browser] 执行 JS 失败: {exc}")
        return default


def run_js_with_args(sb: Any, script: str, *args: Any, default: Any = None) -> Any:
    """带参数执行 JS，脚本里用 arguments[0]、arguments[1] 取值。

    走参数而不是把值拼进脚本，密码之类的内容就不会出现在脚本文本里。
    """
    try:
        return sb.execute_script(script, *args)
    except Exception as exc:
        print(f"[browser] 执行 JS 失败: {exc}")
        return default


def visible_text(sb: Any) -> str:
    text = run_js(
        sb, "return document.body ? document.body.innerText : '';", default=""
    )
    return (text or "").replace("\u00a0", " ")


def current_url(sb: Any) -> str:
    try:
        return sb.get_current_url() or ""
    except Exception as exc:
        print(f"[browser] 读取当前 URL 失败: {exc}")
        return ""


def open_url(sb: Any, url: str, reconnect_time: float = 4.0) -> None:
    """打开新页面。

    UC 模式下用 uc_open_with_reconnect：新标签页打开 + 断开 chromedriver 一段时间，
    这样风控首屏检测抓不到自动化痕迹。
    """
    print(f"[browser] 打开页面: {url}")
    sb.uc_open_with_reconnect(url, reconnect_time)


def page_state(sb: Any) -> dict[str, Any]:
    state = run_js(sb, PAGE_STATE_JS, default=None)
    return state if isinstance(state, dict) else {}


def is_interstitial_page(sb: Any, state: Optional[dict[str, Any]] = None) -> bool:
    """是否停在验证 / 拦截页（整站挑战、WAF 挡板等）。"""
    state = state if state is not None else page_state(sb)
    title = state.get("title") or ""
    if any(marker in title for marker in INTERSTITIAL_TITLE_MARKERS):
        return True
    return bool(run_js(sb, CHALLENGE_DOM_JS, default=False))


def wait_app_ready(sb: Any, timeout: int = 30) -> bool:
    """等到页面自身 JS 起来（文档加载完成 + fetch 可用）。

    如果在验证/拦截页上，先给它时间自己放行；多数 WAF 挑战几秒内会跳回正常页面。
    """
    deadline = time.time() + timeout
    last_title = ""

    while time.time() < deadline:
        state = page_state(sb)
        title = state.get("title") or ""

        if state.get("ready") and not is_interstitial_page(sb, state):
            print(f"[browser] 页面已就绪: {title}")
            return True

        if title and title != last_title:
            print(f"[browser] 页面尚未就绪: {title}")
            last_title = title
        time.sleep(1)

    return False


def install_turnstile(sb: Any, sitekey: str) -> str:
    """在页面里渲染一个自己的 Turnstile widget，返回 JS 结果（rendered / loading）。"""
    result = run_js_with_args(
        sb, TURNSTILE_INSTALL_JS, sitekey, TURNSTILE_CONTAINER_ID, default="js-error"
    )
    print(f"[turnstile] 渲染验证组件: {result}")
    return result


def turnstile_state(sb: Any) -> dict[str, Any]:
    state = run_js(sb, TURNSTILE_STATE_JS, default=None)
    if not isinstance(state, dict):
        return {"token": "", "error": "", "rendered": False}
    return state


def _wait_for_token(sb: Any, timeout: float) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if turnstile_state(sb).get("token"):
            return True
        time.sleep(0.5)
    return False


def click_turnstile_checkbox(sb: Any) -> bool:
    """按自己容器的屏幕坐标点复选框。

    Turnstile 把 iframe 渲染进 closed shadow DOM，`document.querySelector('iframe')`
    拿不到它，所以只能量外层容器（在 light DOM 里）再按固定偏移点。
    """
    if not _gui_click_enabled():
        print(f"[turnstile] {DISABLE_GUI_CLICK_ENV} 已设置，跳过真实鼠标点击")
        return False

    try:
        rect = sb.get_gui_element_rect(f"#{TURNSTILE_CONTAINER_ID}")
    except Exception as exc:
        first_line = str(exc).strip().splitlines()[:1]
        print(f"[turnstile] 拿不到验证组件坐标: {first_line[0] if first_line else exc}")
        return False

    if rect["width"] < 60 or rect["height"] < 30:
        # widget 还没排版完（容器尺寸是 0），坐标不可信，交给下一轮
        print(f"[turnstile] 验证组件尺寸异常，跳过本次点击: {rect}")
        return False

    x = rect["x"] + TURNSTILE_CHECKBOX_OFFSET_X
    y = rect["y"] + TURNSTILE_CHECKBOX_OFFSET_Y
    print(f"[turnstile] 点击复选框: ({x:.0f}, {y:.0f})")

    disconnected = False
    try:
        # 点击瞬间断开 chromedriver，避免 Cloudflare 采集到自动化痕迹
        sb.driver.disconnect()
        disconnected = True
        sb.uc_gui_click_x_y(x, y)
        return True
    except Exception as exc:
        print(f"[turnstile] 坐标点击失败: {exc}")
        return False
    finally:
        if disconnected:
            try:
                sb.reconnect(2.6)
            except Exception as exc:
                print(f"[turnstile] 重新连接 chromedriver 失败: {exc}")


def obtain_turnstile_token(sb: Any, sitekey: str, timeout: int = 90) -> str:
    """渲染 Turnstile 并拿到一个 token。

    干净 IP 上 widget 常常自己就过了，所以先留一段观察时间，真需要交互再点。
    组件报错（常见是 token 复用过 / 脚本重复加载）时重新渲染一个新的。
    """
    install_turnstile(sb, sitekey)

    if _wait_for_token(sb, min(TURNSTILE_GRACE_SECONDS, timeout)):
        print("[turnstile] 无需交互，验证已自动完成")
        return turnstile_state(sb)["token"]

    deadline = time.time() + timeout
    attempts = 0

    while time.time() < deadline:
        state = turnstile_state(sb)
        if state.get("token"):
            print(f"[turnstile] 已拿到验证 token（点击 {attempts} 次）")
            return state["token"]

        if state.get("error"):
            print(f"[turnstile] 组件报错 {state['error']}，重新渲染")
            time.sleep(1)
            install_turnstile(sb, sitekey)
            if _wait_for_token(sb, TURNSTILE_CLICK_WAIT_SECONDS):
                print("[turnstile] 重新渲染后自动通过")
                return turnstile_state(sb)["token"]
            continue

        if not state.get("rendered"):
            # 脚本还在加载 / widget 还没排版出来，坐标不可信
            time.sleep(1)
            continue

        attempts += 1
        print(f"[turnstile] 第 {attempts} 次点击复选框")
        click_turnstile_checkbox(sb)

        if _wait_for_token(sb, TURNSTILE_CLICK_WAIT_SECONDS):
            print(f"[turnstile] 已拿到验证 token（点击 {attempts} 次）")
            return turnstile_state(sb)["token"]

    raise TurnstileFailed(f"Turnstile {timeout}s 内未通过（点击 {attempts} 次）")

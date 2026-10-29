# iamhc 自动签到脚本

自动登录 [api.hcnsec.cn](https://api.hcnsec.cn) 并执行每日签到，签到后通过 Telegram 推送通知（可选）。

站点改版后，**登录和签到都要过 Cloudflare Turnstile**：登录接口不带 token 会直接返回
`Turnstile token is empty`，旧的纯 `requests` 脚本因此失效。现在流程跑在真实浏览器里：

1. SeleniumBase 以 UC 模式启动有头 Chrome（Linux 上用 Xvfb 提供虚拟显示）
2. 打开站点 → 自己渲染一个 Turnstile widget → 用系统级鼠标点掉盾，拿到 token
3. 在页面上下文里调站内接口：`POST /api/user/login?turnstile=…` 拿 `access_token`
4. 查余额 / 签到状态 → 再拿一个新的 token → `POST /api/user/checkin?turnstile=…`
5. 结果通过 Telegram 推送（可选）

> 站点有需要过盾的代理场景时，配置 `NODE_LINK` 即可让浏览器走机场节点：复杂协议由
> sing-box 在本地开一个 HTTP 入口，Chrome 只认这个本地代理。

## 为什么是「浏览器里发请求」

- Turnstile token 只能在同源页面里由 Cloudflare 下发，`requests` 造不出来；
- 请求从浏览器里发出时，Cookie、Origin、Referer、风控指纹都是原生的，比脚本拼 headers 稳；
- 站点服务端是用 `remoteip` 校验 token 的，浏览器和请求走同一个出口 IP 最保险。

不需要依赖站点前端的具体 DOM（登录页 `/sign-in`、按钮文案、弹窗都不碰），也不关心前端路由
从 `/login` 改成 `/sign-in` 这类变化，只依赖这 4 个接口，所以前端改版时脚本不会跟着碎。
过盾用的是脚本自己渲染的 Turnstile widget（sitekey 从 `/api/status` 读），不依赖站点把
widget 渲染在哪。

## 目录结构

```
.
├── checkin.py                      # 入口（逻辑都在 src/ 下）
├── .github/workflows/checkin.yml   # GitHub Actions 工作流
├── src/
│   ├── checkin.py                  # 主流程：过盾 → 登录 → 签到 → 通知
│   ├── browser.py                  # SeleniumBase UC 模式 + Turnstile 过盾 + 截图
│   ├── page_api.py                 # 在页面上下文里发 fetch 并把结果取回
│   ├── site.py                     # 接口语义、响应判定、额度格式化
│   ├── proxy_node.py               # 节点链接 → sing-box 配置 → 本地 HTTP 代理
│   ├── notify.py                   # Telegram 通知
│   └── env.py                      # 本地 .env.local 加载
├── tests/                          # 不启浏览器的单元测试
├── requirements.txt
└── README.md
```

## 配置

### 在仓库 Settings → Secrets and variables → Actions 添加

| Secret 名称 | 必填 | 说明 |
|---|:---:|---|
| `EMAIL` | 是 | 登录邮箱 / 用户名 |
| `PASSWORD` | 是 | 登录密码 |
| `TG_BOT_TOKEN` | 否 | Telegram Bot Token |
| `TG_CHAT_ID` | 否 | Telegram Chat ID |
| `NODE_LINK` | 否 | 节点分享链接，见下文「节点代理」 |

不配置 Telegram 也能运行，只是不推送结果；失败时截图会作为 artifact 上传。

### 本地环境变量（可选）

| 变量 | 说明 |
|---|---|
| `EMAIL` / `PASSWORD` | 同 Secrets；也接受 `IAMHC_EMAIL` / `IAMHC_PASSWORD` |
| `NODE_LINK` | 节点链接；本地调试可用 `IAMHC_NODE_LINK`，优先级更高 |
| `IAMHC_BASE_URL` | 站点地址，默认 `https://api.hcnsec.cn`（站点换域名时用） |
| `IAMHC_BROWSER_PROXY` | 浏览器代理，如 `http://127.0.0.1:7890`；不配时自动读 `HTTPS_PROXY`/`HTTP_PROXY` |
| `IAMHC_USER_AGENT` | 覆盖浏览器 UA。默认留空，用 Chrome 真实 UA（改 UA 反而更容易被风控） |
| `IAMHC_DISABLE_GUI_CLICK` | 设为 `1` 时不发真实鼠标事件，只做流程调试（此时过不了盾） |
| `IAMHC_PROXY_PORT` | sing-box 本地 mixed 入口端口，默认 `1081` |
| `SING_BOX_PATH` | sing-box 可执行文件路径，默认从 PATH 找 |

## 节点代理（NODE_LINK）

Chrome 只支持 HTTP/SOCKS 代理，不认识 `vless://`、`vmess://`、`tuic://`、`hysteria2://`、
`anytls://`。配置 `NODE_LINK` 后：

1. Actions 里下载并校验官方 sing-box `v1.14.0`；
2. 把链接转成 sing-box 配置，在 `127.0.0.1:1081` 开一个 `mixed` 入站；
3. 浏览器走这个本地代理（登录、过盾、签到请求都在同一个出口上）；
4. 任务结束后自动关闭 sing-box。

`socks5://host:port`、`http://host:port` 这类 Chrome 原生支持的链接会直接交给 Chrome，
不额外启动 sing-box。支持的协议：`vless`、`vmess`、`trojan`、`ss`、`tuic`、`hysteria2`/`hy2`、
`anytls`/`anttls`、`http(s)`、`socks(4/5)`。

本地调试复杂节点需要先装 sing-box：

```bash
brew install sing-box
export NODE_LINK="vless://..."
python -m src.proxy_node --print-config   # 先确认链接能解析
```

不要把带密码的节点链接提交到仓库，只放在 Actions Secrets 里。

## 运行

### GitHub Actions

- 每天 UTC 23:17（北京时间次日 07:17）自动运行；
- 也可以在 Actions 页面选 `iamhc Daily Checkin` → **Run workflow** 手动触发；
- 运行结束后会清理旧的历史运行记录，失败时会保留截图 artifact。

### 本地

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# 可选：写 .env.local（已在 .gitignore 里，不会被提交）
# EMAIL="you@example.com"
# PASSWORD="***"

python checkin.py
```

先单独验证「能不能过盾」，不消耗登录：

```bash
python checkin.py --smoke-turnstile
```

它会打开浏览器、渲染 Turnstile、拿到 token 后退出，日志里会打印 token 长度和截图路径。

过盾靠 PyAutoGUI 发真实鼠标事件，所以本地运行时鼠标会被脚本短暂接管：

- macOS：第一次运行要在「系统设置 → 隐私与安全性 → 辅助功能」里给终端（或 IDE）授权；
- Linux 桌面：需要 `xvfb`、`python3-tk`、`scrot`；
- 只想跑通流程、不想被抢鼠标：`export IAMHC_DISABLE_GUI_CLICK=1`（此时过不了盾）。

## 截图

每次运行开始会清理 `screenshots/*.png`，运行过程中产出：

| 文件 | 时机 |
|---|---|
| `01-site-ready.png` | 站点首页就绪 |
| `01-site-not-ready.png` | 首页超时未就绪（可能是 WAF 拦截页） |
| `02-login-turnstile.png` | 登录前的 Turnstile |
| `03-checkin-turnstile.png` | 签到前的 Turnstile |
| `06-result.png` | 流程顺利完成 |
| `failure-attempt-{n}.png` | 第 n 次重试失败 |
| `smoke-turnstile.png` | `--smoke-turnstile` 模式 |

## 故障排查

| 现象 | 可能原因 | 处理 |
|---|---|---|
| `Turnstile token is empty` | 没拿到 token 就登录了 | 看 `02-login-turnstile.png`；本地先跑 `--smoke-turnstile` |
| `Turnstile … 内未通过` | 出口 IP 被风控，或 widget 被点歪 | 换一个 `NODE_LINK` 节点；或用 `IAMHC_BROWSER_PROXY` 换出口 |
| `站点 45s 内未就绪` | WAF 拦截页 / 代理不通 | 看 `01-site-not-ready.png`，先确认代理本身能打开站点 |
| `账号开启了二次验证` | 账号开了 2FA / Passkey | 关掉二次验证，或改成手动签到 |
| `站点启用了密码加密登录` | 站点打开了 `password_login_encryption_enabled` | 需要按 `/api/user/login/encryption-key` 补 RSA-OAEP + AES-GCM 加密 |
| `PyAutoGUI can't be used in headless mode` | 跑成了 headless | 别加 `--headless`，Linux 上确认 `xvfb` 已安装 |
| `import pyautogui` 直接退出 | 缺 tkinter | Linux 装 `python3-tk`；CI 的验证步骤会提前暴露 |
| 节点代理启动失败 | 链接格式不支持 / sing-box 缺失 / 节点不可用 | `python -m src.proxy_node --print-config`，再 `sing-box check` |
| 升级 Chrome 后启动失败 | 驱动版本不匹配 | `sbase get uc_driver` 重新拉一份 |

跑单元测试（不启浏览器）：

```bash
python -m pytest
```

## 风险声明

仅供学习与个人自动化使用。请遵守目标站点的服务条款，自负使用风险。

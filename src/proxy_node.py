"""把机场分享链接转成 sing-box 配置，并在本地拉一个 HTTP 代理入口。

Chrome 的 `--proxy-server` 只认 http / socks，vless、vmess、tuic、hysteria2、anytls
这些协议它一个都不懂。所以这里的做法是：用 sing-box 把节点链接接起来，在
127.0.0.1 上开一个 mixed 入口，再让浏览器走这个本地代理。

环境变量：
    IAMHC_NODE_LINK / NODE_LINK   节点分享链接（支持多条，按行或空格分隔，取第一条）
    IAMHC_PROXY_PORT              本地代理端口，默认 1081
    SING_BOX_PATH                 sing-box 可执行文件路径，默认从 PATH 找

也可以单独当命令行用，方便本地排查链接解析结果：
    python -m src.proxy_node --print-config
"""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, Optional
from urllib.parse import parse_qs, unquote, urlsplit

NODE_LINK_ENVS = ("IAMHC_NODE_LINK", "NODE_LINK")
PROXY_PORT_ENV = "IAMHC_PROXY_PORT"
SING_BOX_PATH_ENV = "SING_BOX_PATH"

DEFAULT_PROXY_PORT = 1081
OUTBOUND_TAG = "node"
READY_TIMEOUT_SECONDS = 20

# Chrome 能直接消化的协议；没有账号密码时不需要 sing-box 中转
# （Chrome 的 --proxy-server 不支持在 URL 里带用户名密码）
CHROME_NATIVE_SCHEMES = ("http", "https", "socks5", "socks5h", "socks4", "socks")


class UnsupportedNodeLink(Exception):
    """链接格式不认识，或缺少必要字段。"""


class SingBoxNotFound(Exception):
    """需要 sing-box 但没找到可执行文件。"""


def node_link_from_env() -> Optional[str]:
    """读取节点链接。允许一次贴多条，只用第一条。"""
    for name in NODE_LINK_ENVS:
        raw = os.environ.get(name, "").strip()
        if not raw:
            continue
        for line in raw.replace(",", "\n").split():
            link = line.strip().strip('"').strip("'")
            if link:
                return link
    return None


def proxy_port_from_env() -> int:
    raw = os.environ.get(PROXY_PORT_ENV, "").strip()
    if not raw:
        return DEFAULT_PROXY_PORT
    try:
        return int(raw)
    except ValueError:
        print(f"[node] {PROXY_PORT_ENV} 不是数字，使用默认端口 {DEFAULT_PROXY_PORT}")
        return DEFAULT_PROXY_PORT


def _b64decode(text: str) -> str:
    """容忍缺省 padding 和 urlsafe 变体的 base64 解码。"""
    cleaned = text.strip().replace("-", "+").replace("_", "/")
    cleaned += "=" * (-len(cleaned) % 4)
    try:
        return base64.b64decode(cleaned).decode("utf-8", "replace")
    except (binascii.Error, ValueError) as exc:
        raise UnsupportedNodeLink(f"base64 解码失败: {exc}") from exc


def _first(query: dict[str, list[str]], *names: str, default: str = "") -> str:
    for name in names:
        values = query.get(name)
        if values and values[0]:
            return unquote(values[0])
    return default


def _is_true(value: str) -> bool:
    return value.strip().lower() in ("1", "true", "yes", "on")


def _alpn_list(value: str) -> list[str]:
    return [item for item in (part.strip() for part in value.split(",")) if item]


def _require_port(raw: Optional[int], scheme: str) -> int:
    if not raw:
        raise UnsupportedNodeLink(f"{scheme} 链接缺少端口")
    return int(raw)


def _tls_block(
    query: dict[str, list[str]],
    server: str,
    *,
    enabled: bool,
) -> Optional[dict[str, Any]]:
    if not enabled:
        return None

    tls: dict[str, Any] = {
        "enabled": True,
        "server_name": _first(query, "sni", "peer", "host", default=server),
    }

    if _is_true(_first(query, "insecure", "allowInsecure", "allow_insecure")):
        tls["insecure"] = True

    alpn = _alpn_list(_first(query, "alpn"))
    if alpn:
        tls["alpn"] = alpn

    fingerprint = _first(query, "fp", "client-fingerprint")
    if fingerprint:
        tls["utls"] = {"enabled": True, "fingerprint": fingerprint}

    public_key = _first(query, "pbk", "public-key")
    if public_key:
        reality: dict[str, Any] = {"enabled": True, "public_key": public_key}
        short_id = _first(query, "sid", "short-id")
        if short_id:
            reality["short_id"] = short_id
        tls["reality"] = reality
        # reality 走 uTLS，没给指纹时补一个常见值，否则 sing-box 会拒绝
        tls.setdefault("utls", {"enabled": True, "fingerprint": "chrome"})

    return tls


def _transport_block(query: dict[str, list[str]]) -> Optional[dict[str, Any]]:
    kind = _first(query, "type", "net").lower()
    if kind in ("", "tcp", "none", "raw"):
        return None

    host = _first(query, "host")
    path = _first(query, "path", default="/")

    if kind == "ws":
        transport: dict[str, Any] = {"type": "ws", "path": path}
        if "?ed=" in path:
            # v2ray 的 early data 写法：path?ed=2048
            base_path, _, ed_value = path.partition("?ed=")
            transport["path"] = base_path or "/"
            transport["early_data_header_name"] = "Sec-WebSocket-Protocol"
            try:
                transport["max_early_data"] = int(ed_value)
            except ValueError:
                pass
        if host:
            transport["headers"] = {"Host": host}
        return transport

    if kind == "grpc":
        return {"type": "grpc", "service_name": _first(query, "serviceName", "path")}

    if kind == "httpupgrade":
        transport = {"type": "httpupgrade", "path": path}
        if host:
            transport["host"] = host
        return transport

    if kind in ("http", "h2"):
        transport = {"type": "http", "path": path}
        if host:
            transport["host"] = [host]
        return transport

    raise UnsupportedNodeLink(f"暂不支持的传输方式: {kind}")


def _parse_vless(parts, query) -> dict[str, Any]:
    if not parts.username:
        raise UnsupportedNodeLink("vless 链接缺少 uuid")

    security = _first(query, "security").lower()
    outbound: dict[str, Any] = {
        "type": "vless",
        "server": parts.hostname,
        "server_port": _require_port(parts.port, "vless"),
        "uuid": unquote(parts.username),
    }

    flow = _first(query, "flow")
    if flow:
        outbound["flow"] = flow

    tls = _tls_block(
        query,
        parts.hostname or "",
        enabled=security in ("tls", "reality", "xtls") or bool(_first(query, "pbk")),
    )
    if tls:
        outbound["tls"] = tls

    transport = _transport_block(query)
    if transport:
        outbound["transport"] = transport
    return outbound


def _parse_vmess(link: str) -> dict[str, Any]:
    payload = link[len("vmess://"):]
    try:
        config = json.loads(_b64decode(payload))
    except json.JSONDecodeError as exc:
        raise UnsupportedNodeLink(
            "vmess 链接不是 v2rayN 的 base64(JSON) 格式，无法解析"
        ) from exc
    if not isinstance(config, dict):
        raise UnsupportedNodeLink("vmess 链接内容不是 JSON 对象")

    server = str(config.get("add", ""))
    if not server:
        raise UnsupportedNodeLink("vmess 链接缺少服务器地址")

    outbound: dict[str, Any] = {
        "type": "vmess",
        "server": server,
        "server_port": _require_port(int(config.get("port") or 0), "vmess"),
        "uuid": str(config.get("id", "")),
        "security": str(config.get("scy") or "auto"),
        "alter_id": int(config.get("aid") or 0),
    }

    # 把 JSON 字段折成 query 形式，好复用 tls/transport 的构造逻辑
    query = {
        key: [str(config.get(key))]
        for key in ("sni", "host", "path", "alpn", "fp", "type", "net", "serviceName")
        if config.get(key)
    }
    if str(config.get("net", "")).lower() in ("ws", "grpc", "httpupgrade", "h2", "http"):
        query["type"] = [str(config["net"])]

    tls = _tls_block(query, server, enabled=str(config.get("tls", "")).lower() == "tls")
    if tls:
        outbound["tls"] = tls

    transport = _transport_block(query)
    if transport:
        outbound["transport"] = transport
    return outbound


def _parse_trojan(parts, query) -> dict[str, Any]:
    if not parts.username:
        raise UnsupportedNodeLink("trojan 链接缺少密码")

    outbound: dict[str, Any] = {
        "type": "trojan",
        "server": parts.hostname,
        "server_port": _require_port(parts.port, "trojan"),
        "password": unquote(parts.username),
    }

    # trojan 本身就是跑在 TLS 上的，除非显式写了 security=none
    tls = _tls_block(
        query,
        parts.hostname or "",
        enabled=_first(query, "security").lower() != "none",
    )
    if tls:
        outbound["tls"] = tls

    transport = _transport_block(query)
    if transport:
        outbound["transport"] = transport
    return outbound


def _parse_shadowsocks(link: str) -> dict[str, Any]:
    body = link[len("ss://"):]
    fragment_split = body.split("#", 1)[0]
    body, _, query_text = fragment_split.partition("?")

    if "@" in body:
        # SIP002: ss://base64(method:password)@host:port
        userinfo, _, hostport = body.rpartition("@")
        if ":" not in userinfo:
            userinfo = _b64decode(userinfo)
        else:
            userinfo = unquote(userinfo)
    else:
        # 旧格式：整体 base64
        decoded = _b64decode(body)
        userinfo, _, hostport = decoded.rpartition("@")

    method, _, password = userinfo.partition(":")
    host, _, port_text = hostport.rstrip("/").rpartition(":")
    if not method or not host or not port_text:
        raise UnsupportedNodeLink("ss 链接缺少加密方式/服务器/端口")

    outbound: dict[str, Any] = {
        "type": "shadowsocks",
        "server": host,
        "server_port": _require_port(int(port_text), "ss"),
        "method": method,
        "password": password,
    }

    query = parse_qs(query_text)
    plugin = _first(query, "plugin")
    if plugin:
        plugin_name, _, plugin_opts = plugin.partition(";")
        outbound["plugin"] = plugin_name
        if plugin_opts:
            outbound["plugin_opts"] = plugin_opts
    return outbound


def _parse_tuic(parts, query) -> dict[str, Any]:
    if not parts.username:
        raise UnsupportedNodeLink("tuic 链接缺少 uuid")

    outbound: dict[str, Any] = {
        "type": "tuic",
        "server": parts.hostname,
        "server_port": _require_port(parts.port, "tuic"),
        "uuid": unquote(parts.username),
        "password": unquote(parts.password or ""),
    }

    congestion = _first(query, "congestion_control", "congestion-control")
    if congestion:
        outbound["congestion_control"] = congestion
    relay_mode = _first(query, "udp_relay_mode", "udp-relay-mode")
    if relay_mode:
        outbound["udp_relay_mode"] = relay_mode

    tls = _tls_block(query, parts.hostname or "", enabled=True)
    if tls:
        tls.setdefault("alpn", ["h3"])
        outbound["tls"] = tls
    return outbound


def _parse_hysteria2(parts, query) -> dict[str, Any]:
    password = unquote(parts.username or "")
    if parts.password:
        password = f"{password}:{unquote(parts.password)}"
    if not password:
        raise UnsupportedNodeLink("hysteria2 链接缺少密码")

    outbound: dict[str, Any] = {
        "type": "hysteria2",
        "server": parts.hostname,
        "server_port": _require_port(parts.port or 443, "hysteria2"),
        "password": password,
    }

    obfs = _first(query, "obfs")
    if obfs and obfs.lower() != "none":
        outbound["obfs"] = {
            "type": obfs,
            "password": _first(query, "obfs-password", "obfs_password"),
        }

    for key, field in (("up", "up_mbps"), ("down", "down_mbps")):
        raw = _first(query, key)
        if raw.isdigit():
            outbound[field] = int(raw)

    tls = _tls_block(query, parts.hostname or "", enabled=True)
    if tls:
        outbound["tls"] = tls
    return outbound


def _parse_anytls(parts, query) -> dict[str, Any]:
    password = unquote(parts.username or "")
    if parts.password:
        password = f"{password}:{unquote(parts.password)}"
    if not password:
        raise UnsupportedNodeLink("anytls 链接缺少密码")

    outbound: dict[str, Any] = {
        "type": "anytls",
        "server": parts.hostname,
        "server_port": _require_port(parts.port, "anytls"),
        "password": password,
    }
    tls = _tls_block(query, parts.hostname or "", enabled=True)
    if tls:
        outbound["tls"] = tls
    return outbound


def _parse_socks_or_http(parts, scheme: str) -> dict[str, Any]:
    outbound: dict[str, Any] = {
        "type": "http" if scheme in ("http", "https") else "socks",
        "server": parts.hostname,
        "server_port": _require_port(parts.port, scheme),
    }
    if outbound["type"] == "socks":
        outbound["version"] = "4" if scheme == "socks4" else "5"
    if scheme == "https":
        outbound["tls"] = {"enabled": True, "server_name": parts.hostname}
    if parts.username:
        outbound["username"] = unquote(parts.username)
    if parts.password:
        outbound["password"] = unquote(parts.password)
    return outbound


def parse_link(link: str) -> dict[str, Any]:
    """把分享链接解析成一个 sing-box outbound。"""
    link = link.strip()
    scheme = link.split("://", 1)[0].lower() if "://" in link else ""
    if not scheme:
        raise UnsupportedNodeLink("链接缺少协议前缀（形如 vless:// hysteria2://）")

    if scheme == "vmess":
        outbound = _parse_vmess(link)
    else:
        parts = urlsplit(link)
        query = parse_qs(parts.query)
        if scheme == "vless":
            outbound = _parse_vless(parts, query)
        elif scheme == "trojan":
            outbound = _parse_trojan(parts, query)
        elif scheme == "ss":
            outbound = _parse_shadowsocks(link)
        elif scheme == "tuic":
            outbound = _parse_tuic(parts, query)
        elif scheme in ("hysteria2", "hy2"):
            outbound = _parse_hysteria2(parts, query)
        elif scheme in ("anytls", "anttls"):
            outbound = _parse_anytls(parts, query)
        elif scheme in CHROME_NATIVE_SCHEMES:
            outbound = _parse_socks_or_http(parts, scheme)
        else:
            raise UnsupportedNodeLink(f"暂不支持的协议: {scheme}")

    if not outbound.get("server"):
        raise UnsupportedNodeLink(f"{scheme} 链接缺少服务器地址")

    outbound["tag"] = OUTBOUND_TAG
    return outbound


def chrome_native_proxy(link: str) -> Optional[str]:
    """能直接交给 Chrome 的链接就别多绕一层 sing-box。

    带账号密码的不算：Chrome 的 --proxy-server 会忽略 URL 里的凭据。
    """
    scheme = link.split("://", 1)[0].lower() if "://" in link else ""
    if scheme not in CHROME_NATIVE_SCHEMES:
        return None

    parts = urlsplit(link)
    if parts.username or parts.password:
        return None
    if not parts.hostname or not parts.port:
        return None
    return f"{scheme}://{parts.hostname}:{parts.port}"


def build_config(link: str, port: int) -> dict[str, Any]:
    """生成一份只有「本地 mixed 入口 + 一个节点出口」的 sing-box 配置。"""
    return {
        "log": {"level": "warn", "timestamp": True},
        "inbounds": [
            {
                "type": "mixed",
                "tag": "local",
                "listen": "127.0.0.1",
                "listen_port": port,
            }
        ],
        "outbounds": [parse_link(link)],
        "route": {"final": OUTBOUND_TAG},
    }


def _find_sing_box() -> str:
    configured = os.environ.get(SING_BOX_PATH_ENV, "").strip()
    if configured:
        if not os.path.exists(configured):
            raise SingBoxNotFound(f"{SING_BOX_PATH_ENV} 指向的文件不存在: {configured}")
        return configured

    found = shutil.which("sing-box")
    if not found:
        raise SingBoxNotFound(
            "没找到 sing-box。macOS 可以 `brew install sing-box`，"
            "Linux 从 https://github.com/SagerNet/sing-box/releases 下载后放进 PATH"
        )
    return found


def _wait_until_listening(port: int, process: subprocess.Popen) -> bool:
    deadline = time.time() + READY_TIMEOUT_SECONDS
    while time.time() < deadline:
        if process.poll() is not None:
            return False
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.3)
    return False


@contextmanager
def launch(link: str, port: Optional[int] = None) -> Iterator[str]:
    """起一个 sing-box，yield 出浏览器该用的本地代理地址。"""
    port = port or proxy_port_from_env()
    binary = _find_sing_box()
    config = build_config(link, port)
    outbound_type = config["outbounds"][0]["type"]

    workdir = tempfile.mkdtemp(prefix="iamhc-node-")
    config_path = Path(workdir) / "sing-box.json"
    config_path.write_text(json.dumps(config, ensure_ascii=False, indent=2), "utf-8")

    print(f"[node] 启动 sing-box: {outbound_type} 节点 → 127.0.0.1:{port}")
    process = subprocess.Popen(
        [binary, "run", "-c", str(config_path)],
        cwd=workdir,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )

    try:
        if not _wait_until_listening(port, process):
            output = ""
            if process.poll() is not None and process.stdout:
                output = process.stdout.read()[-800:]
            raise RuntimeError(
                f"sing-box {READY_TIMEOUT_SECONDS}s 内没有监听 127.0.0.1:{port}"
                + (f"；输出: {output.strip()}" if output else "")
            )

        proxy_url = f"http://127.0.0.1:{port}"
        _log_egress_ip(proxy_url)
        yield proxy_url
    finally:
        _shutdown(process)
        shutil.rmtree(workdir, ignore_errors=True)


@contextmanager
def maybe_launch() -> Iterator[Optional[str]]:
    """配了节点链接就起 sing-box，否则什么都不做。"""
    link = node_link_from_env()
    if not link:
        yield None
        return

    native = chrome_native_proxy(link)
    if native:
        print(f"[node] 链接是 Chrome 原生支持的代理，直接使用: {native}")
        yield native
        return

    with launch(link) as proxy_url:
        yield proxy_url


def _log_egress_ip(proxy_url: str) -> None:
    """打一条出口 IP，方便确认节点是不是真的生效了。"""
    try:
        import requests

        resp = requests.get(
            "https://api.ip.sb/ip",
            proxies={"http": proxy_url, "https": proxy_url},
            timeout=15,
            headers={"User-Agent": "curl/8"},
        )
        if resp.ok:
            print(f"[node] 当前出口 IP: {resp.text.strip()}")
        else:
            print(f"[node] 查询出口 IP 失败: HTTP {resp.status_code}")
    except Exception as exc:
        print(f"[node] 查询出口 IP 失败: {type(exc).__name__}: {exc}")


def _shutdown(process: subprocess.Popen) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
    print("[node] sing-box 已退出")


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="节点链接 → sing-box 配置")
    parser.add_argument("--link", help="节点分享链接，默认读环境变量")
    parser.add_argument("--port", type=int, help="本地代理端口")
    parser.add_argument(
        "--print-config",
        action="store_true",
        help="只打印生成的 sing-box 配置（密码等字段会原样出现，注意别贴到公开地方）",
    )
    args = parser.parse_args(argv)

    link = args.link or node_link_from_env()
    if not link:
        print(f"[node] 未配置 {' / '.join(NODE_LINK_ENVS)}")
        return 2

    port = args.port or proxy_port_from_env()
    try:
        config = build_config(link, port)
    except UnsupportedNodeLink as exc:
        print(f"[node] 链接解析失败: {exc}")
        return 1

    if args.print_config:
        print(json.dumps(config, ensure_ascii=False, indent=2))
        return 0

    outbound = config["outbounds"][0]
    print(
        f"[node] 解析成功: type={outbound['type']} "
        f"server={outbound['server']}:{outbound['server_port']}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

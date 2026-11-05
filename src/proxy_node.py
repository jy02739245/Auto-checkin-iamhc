"""把机场分享链接转成本地 HTTP 代理入口。

Chrome 的 `--proxy-server` 只认 http / socks，vless、vmess、tuic、hysteria2、anytls
这些协议它一个都不懂。所以这里的做法是：用 sing-box 或 Xray 把节点链接接起来，在
127.0.0.1 上开一个 HTTP 入口，再让浏览器走这个本地代理。

默认按传输方式自动选后端：
    xhttp / splithttp  → Xray（sing-box 至今没有 XHTTP 传输）
    其他协议           → sing-box（保留 tuic / hysteria2 / anytls / ss 插件）

环境变量：
    IAMHC_NODE_LINK / NODE_LINK   节点分享链接（支持多条，按行或空格分隔，取第一条）
    IAMHC_PROXY_PORT              本地代理端口，默认 1081
    IAMHC_PROXY_BACKEND           后端：auto（默认）/ xray / sing-box
    SING_BOX_PATH                 sing-box 可执行文件路径，默认从 PATH 找
    XRAY_PATH                     Xray 可执行文件路径，默认从 PATH 找

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
BACKEND_ENV = "IAMHC_PROXY_BACKEND"
SING_BOX_PATH_ENV = "SING_BOX_PATH"
XRAY_PATH_ENV = "XRAY_PATH"

DEFAULT_PROXY_PORT = 1081
OUTBOUND_TAG = "node"
READY_TIMEOUT_SECONDS = 20

BACKEND_AUTO = "auto"
BACKEND_XRAY = "xray"
BACKEND_SING_BOX = "sing-box"
XHTTP_TRANSPORTS = ("xhttp", "splithttp")

# Chrome 能直接消化的协议；没有账号密码时不需要本地中转
# （Chrome 的 --proxy-server 不支持在 URL 里带用户名密码）
CHROME_NATIVE_SCHEMES = ("http", "https", "socks5", "socks5h", "socks4", "socks")


class UnsupportedNodeLink(Exception):
    """链接格式不认识，或缺少必要字段。"""


class SingBoxNotFound(Exception):
    """需要 sing-box 但没找到可执行文件。"""


class XrayNotFound(Exception):
    """需要 Xray 但没找到可执行文件。"""


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


def link_transport(link: str) -> str:
    """取分享链接的传输方式（ws / grpc / xhttp / ...），取不到时返回空串。"""
    link = link.strip()
    scheme = link.split("://", 1)[0].lower() if "://" in link else ""
    if scheme == "vmess":
        try:
            config = json.loads(_b64decode(link[len("vmess://"):]))
        except (UnsupportedNodeLink, json.JSONDecodeError):
            return ""
        if isinstance(config, dict):
            return str(config.get("net") or config.get("type") or "").strip().lower()
        return ""
    if not scheme:
        return ""
    return _first(parse_qs(urlsplit(link).query), "type", "net").lower()


def backend_for_link(link: str) -> str:
    """选后端：xhttp 交给 Xray，其余交给 sing-box；可用环境变量强制。"""
    forced = os.environ.get(BACKEND_ENV, "").strip().lower()
    if forced in (BACKEND_XRAY, "singbox", BACKEND_SING_BOX):
        return BACKEND_XRAY if forced == BACKEND_XRAY else BACKEND_SING_BOX
    if forced and forced != BACKEND_AUTO:
        print(f"[node] {BACKEND_ENV}={forced} 不是有效值，按 auto 处理")

    if link_transport(link) in XHTTP_TRANSPORTS:
        return BACKEND_XRAY
    return BACKEND_SING_BOX


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


def _xray_network(query: dict[str, list[str]]) -> str:
    """把链接里的 type/net 映射成 Xray 的 streamSettings.network。"""
    kind = _first(query, "type", "net").lower()
    if kind in ("", "tcp", "none", "raw"):
        return "tcp"
    if kind in XHTTP_TRANSPORTS:
        return "xhttp"
    if kind in ("ws", "websocket"):
        return "ws"
    if kind == "grpc":
        return "grpc"
    if kind == "httpupgrade":
        return "httpupgrade"
    # 当前 Xray 已移除 http / h2 / h3 / quic 传输，并建议改用 XHTTP
    raise UnsupportedNodeLink(f"Xray 后端不支持的传输方式: {kind}")


def _xray_transport_block(query: dict[str, list[str]]) -> dict[str, Any]:
    network = _xray_network(query)
    if network == "xhttp":
        path = _first(query, "path", default="/") or "/"
        mode = (_first(query, "mode", default="auto") or "auto").lower()
        host = _first(query, "host")
        xhttp: dict[str, Any] = {"path": path, "mode": mode}
        if host:
            xhttp["host"] = host

        # v2rayN 把 XHTTP 的高级参数塞在 extra=<urlencoded JSON> 里。
        raw_extra = _first(query, "extra")
        if raw_extra:
            try:
                extra = json.loads(raw_extra)
            except json.JSONDecodeError as exc:
                raise UnsupportedNodeLink(f"xhttp extra 不是合法 JSON: {exc}") from exc
            if not isinstance(extra, dict):
                raise UnsupportedNodeLink("xhttp extra 必须是 JSON 对象")
            xhttp.update(extra)
            # 链接顶层的 host/path/mode 优先级更高
            if host:
                xhttp["host"] = host
            xhttp["path"] = path
            xhttp["mode"] = mode
        return {"network": "xhttp", "xhttpSettings": xhttp}

    if network == "ws":
        transport: dict[str, Any] = {"path": _first(query, "path", default="/")}
        host = _first(query, "host")
        if host:
            transport["headers"] = {"Host": host}
        return {"network": "ws", "wsSettings": transport}

    if network == "grpc":
        return {
            "network": "grpc",
            "grpcSettings": {"serviceName": _first(query, "serviceName", "path")},
        }

    if network == "httpupgrade":
        transport = {"path": _first(query, "path", default="/")}
        host = _first(query, "host")
        if host:
            transport["host"] = host
        return {"network": "httpupgrade", "httpupgradeSettings": transport}

    return {"network": "tcp"}


def _xray_security_block(
    query: dict[str, list[str]],
    server: str,
    *,
    default_tls: bool = False,
) -> dict[str, Any]:
    security = _first(query, "security").lower()
    public_key = _first(query, "pbk", "public-key")

    if security == "reality" or public_key:
        if not public_key:
            raise UnsupportedNodeLink("Xray REALITY 链接缺少 pbk（公钥）")
        return {
            "security": "reality",
            "realitySettings": {
                "serverName": _first(query, "sni", "peer", default=server),
                "fingerprint": _first(query, "fp", "client-fingerprint", default="chrome"),
                "publicKey": public_key,
                "shortId": _first(query, "sid", "short-id"),
                "spiderX": _first(query, "spx", "spider-x", default="/"),
            },
        }

    # 旧链接可能写 security=xtls；Xray 已移除旧 XTLS，按普通 TLS 处理
    if security in ("tls", "xtls") or default_tls:
        tls: dict[str, Any] = {
            "serverName": _first(query, "sni", "peer", default=server),
        }
        if _is_true(_first(query, "insecure", "allowInsecure", "allow_insecure")):
            tls["allowInsecure"] = True
        alpn = _alpn_list(_first(query, "alpn"))
        if alpn:
            tls["alpn"] = alpn
        fingerprint = _first(query, "fp", "client-fingerprint")
        if fingerprint:
            tls["fingerprint"] = fingerprint
        return {"security": "tls", "tlsSettings": tls}

    return {"security": "none"}


def _xray_stream_settings(
    query: dict[str, list[str]],
    server: str,
    *,
    default_tls: bool = False,
) -> dict[str, Any]:
    stream = _xray_transport_block(query)
    stream.update(_xray_security_block(query, server, default_tls=default_tls))
    return stream


def _parse_xray_vless(parts, query) -> dict[str, Any]:
    if not parts.username:
        raise UnsupportedNodeLink("vless 链接缺少 uuid")

    user: dict[str, Any] = {
        "id": unquote(parts.username),
        "encryption": _first(query, "encryption", default="none") or "none",
    }
    # Vision 只适用于 TCP + TLS/REALITY；XHTTP 带了 flow 会被 Xray 拒绝
    flow = _first(query, "flow")
    if flow and _xray_network(query) == "tcp":
        user["flow"] = flow

    return {
        "protocol": "vless",
        "settings": {
            "vnext": [
                {
                    "address": parts.hostname,
                    "port": _require_port(parts.port, "vless"),
                    "users": [user],
                }
            ]
        },
        "streamSettings": _xray_stream_settings(query, parts.hostname or ""),
    }


def _parse_xray_vmess(link: str) -> dict[str, Any]:
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

    query: dict[str, list[str]] = {
        key: [str(config[key])]
        for key in ("sni", "host", "path", "alpn", "fp", "serviceName")
        if config.get(key)
    }
    query["type"] = [str(config.get("net") or config.get("type") or "tcp")]
    if str(config.get("tls", "")).lower() == "tls":
        query["security"] = ["tls"]
    if _is_true(str(config.get("allowInsecure", ""))):
        query["allowInsecure"] = ["1"]

    return {
        "protocol": "vmess",
        "settings": {
            "vnext": [
                {
                    "address": server,
                    "port": _require_port(int(config.get("port") or 0), "vmess"),
                    "users": [
                        {
                            "id": str(config.get("id", "")),
                            "alterId": int(config.get("aid") or 0),
                            "security": str(config.get("scy") or "auto"),
                        }
                    ],
                }
            ]
        },
        "streamSettings": _xray_stream_settings(query, server),
    }


def _parse_xray_trojan(parts, query) -> dict[str, Any]:
    if not parts.username:
        raise UnsupportedNodeLink("trojan 链接缺少密码")

    return {
        "protocol": "trojan",
        "settings": {
            "servers": [
                {
                    "address": parts.hostname,
                    "port": _require_port(parts.port, "trojan"),
                    "password": unquote(parts.username),
                }
            ]
        },
        # trojan 默认跑在 TLS 上，除非显式写了 security=none
        "streamSettings": _xray_stream_settings(
            query,
            parts.hostname or "",
            default_tls=_first(query, "security").lower() != "none",
        ),
    }


def _parse_xray_shadowsocks(link: str) -> dict[str, Any]:
    outbound = _parse_shadowsocks(link)
    if outbound.get("plugin"):
        raise UnsupportedNodeLink("Xray 后端不支持 ss 插件，请改用 sing-box（IAMHC_PROXY_BACKEND=sing-box）")
    return {
        "protocol": "shadowsocks",
        "settings": {
            "servers": [
                {
                    "address": outbound["server"],
                    "port": outbound["server_port"],
                    "method": outbound["method"],
                    "password": outbound["password"],
                }
            ]
        },
    }


def parse_link_xray(link: str) -> dict[str, Any]:
    """把分享链接解析成一个 Xray outbound。"""
    link = link.strip()
    scheme = link.split("://", 1)[0].lower() if "://" in link else ""
    if not scheme:
        raise UnsupportedNodeLink("链接缺少协议前缀（形如 vless:// hysteria2://）")

    if scheme == "vmess":
        outbound = _parse_xray_vmess(link)
    else:
        parts = urlsplit(link)
        query = parse_qs(parts.query)
        if scheme == "vless":
            outbound = _parse_xray_vless(parts, query)
        elif scheme == "trojan":
            outbound = _parse_xray_trojan(parts, query)
        elif scheme == "ss":
            outbound = _parse_xray_shadowsocks(link)
        else:
            raise UnsupportedNodeLink(
                f"Xray 后端不支持协议: {scheme}（tuic / hysteria2 / anytls 请用 sing-box）"
            )

    outbound["tag"] = OUTBOUND_TAG
    return outbound


def build_xray_config(link: str, port: int) -> dict[str, Any]:
    """生成一份「本地 HTTP 入口 + 一个节点出口」的 Xray 配置。

    Xray 没有 sing-box 的 mixed 入站；Chrome 拿到的是 http:// 代理，
    所以这里只开 HTTP 入站就够了。
    """
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "listen": "127.0.0.1",
                "port": port,
                "protocol": "http",
                "settings": {},
            }
        ],
        "outbounds": [parse_link_xray(link)],
    }


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


def build_singbox_config(link: str, port: int) -> dict[str, Any]:
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


def build_config(
    link: str,
    port: int,
    backend: Optional[str] = None,
) -> dict[str, Any]:
    """按链接的传输方式生成对应后端的配置。"""
    if not backend or backend == BACKEND_AUTO:
        backend = backend_for_link(link)
    if backend == BACKEND_XRAY:
        return build_xray_config(link, port)
    return build_singbox_config(link, port)


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


def _find_xray() -> str:
    configured = os.environ.get(XRAY_PATH_ENV, "").strip()
    if configured:
        if not os.path.exists(configured):
            raise XrayNotFound(f"{XRAY_PATH_ENV} 指向的文件不存在: {configured}")
        return configured

    found = shutil.which("xray")
    if not found:
        raise XrayNotFound(
            "没找到 Xray。macOS 可以 `brew install xray`，"
            "Linux 从 https://github.com/XTLS/Xray-core/releases 下载后放进 PATH"
        )
    return found


def _outbound_summary(config: dict[str, Any], backend: str) -> tuple[str, Any, Any]:
    """打印用：统一取出协议、服务器、端口。"""
    outbound = config["outbounds"][0]
    if backend == BACKEND_XRAY:
        protocol = str(outbound.get("protocol", ""))
        settings = outbound.get("settings", {})
        if protocol in ("vless", "vmess"):
            target = (settings.get("vnext") or [{}])[0]
        else:
            target = (settings.get("servers") or [{}])[0]
        return protocol, target.get("address"), target.get("port")

    return (
        str(outbound.get("type", "")),
        outbound.get("server"),
        outbound.get("server_port"),
    )


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
def launch(
    link: str,
    port: Optional[int] = None,
    backend: Optional[str] = None,
) -> Iterator[str]:
    """起 Xray 或 sing-box，yield 出浏览器该用的本地代理地址。"""
    port = port or proxy_port_from_env()
    if not backend or backend == BACKEND_AUTO:
        backend = backend_for_link(link)
    config = build_config(link, port, backend)
    label = "Xray" if backend == BACKEND_XRAY else "sing-box"
    outbound_type = _outbound_summary(config, backend)[0]

    binary = _find_xray() if backend == BACKEND_XRAY else _find_sing_box()

    workdir = tempfile.mkdtemp(prefix="iamhc-node-")
    config_path = Path(workdir) / f"{backend}.json"
    config_path.write_text(json.dumps(config, ensure_ascii=False, indent=2), "utf-8")

    print(f"[node] 启动 {label}: {outbound_type} 节点 → 127.0.0.1:{port}")
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
                f"{label} {READY_TIMEOUT_SECONDS}s 内没有监听 127.0.0.1:{port}"
                + (f"；输出: {output.strip()}" if output else "")
            )

        proxy_url = f"http://127.0.0.1:{port}"
        _log_egress_ip(proxy_url)
        yield proxy_url
    finally:
        _shutdown(process, label)
        shutil.rmtree(workdir, ignore_errors=True)


@contextmanager
def maybe_launch() -> Iterator[Optional[str]]:
    """配了节点链接就起对应后端，否则什么都不做。"""
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


def _shutdown(process: subprocess.Popen, label: str = "节点进程") -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
    print(f"[node] {label} 已退出")


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="节点链接 → Xray / sing-box 配置")
    parser.add_argument("--link", help="节点分享链接，默认读环境变量")
    parser.add_argument("--port", type=int, help="本地代理端口")
    parser.add_argument(
        "--backend",
        choices=(BACKEND_AUTO, BACKEND_XRAY, BACKEND_SING_BOX),
        default=BACKEND_AUTO,
        help="代理后端，默认按传输方式自动选择",
    )
    parser.add_argument(
        "--print-config",
        action="store_true",
        help="只打印生成的配置（密码等字段会原样出现，注意别贴到公开地方）",
    )
    args = parser.parse_args(argv)

    link = args.link or node_link_from_env()
    if not link:
        print(f"[node] 未配置 {' / '.join(NODE_LINK_ENVS)}")
        return 2

    port = args.port or proxy_port_from_env()
    backend = args.backend
    if backend == BACKEND_AUTO:
        backend = backend_for_link(link)

    try:
        config = build_config(link, port, backend)
    except UnsupportedNodeLink as exc:
        print(f"[node] 链接解析失败: {exc}")
        return 1

    if args.print_config:
        print(json.dumps(config, ensure_ascii=False, indent=2))
        return 0

    outbound_type, server, server_port = _outbound_summary(config, backend)
    print(
        f"[node] 解析成功: backend={backend} type={outbound_type} "
        f"server={server}:{server_port}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

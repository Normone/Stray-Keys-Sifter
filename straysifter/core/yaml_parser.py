"""Clash-style YAML → list[ProxyInfo].

Поддерживает типы: vless, vmess, trojan, ss, socks5, http.
hysteria/hysteria2/anytls — пропускаются (нужен sing-box).
"""
from __future__ import annotations

import base64
import json
import logging
import urllib.parse

from .parsers import ProxyInfo, parse_any

log = logging.getLogger(__name__)

try:
    import yaml as _yaml
except ImportError:
    _yaml = None


def parse_clash_yaml(text: str) -> list[ProxyInfo] | None:
    """Возвращает list[ProxyInfo] или None, если это не YAML."""
    if _yaml is None:
        log.warning("yaml_parser: pyyaml не установлен, YAML пропущен "
                    "(pip install pyyaml)")
        return None
    if "proxies:" not in text and "proxy-providers:" not in text:
        return None
    try:
        data = _yaml.safe_load(text)
    except Exception as e:
        log.debug("yaml safe_load error: %s", e)
        return None
    if not isinstance(data, dict):
        return None

    proxies = data.get("proxies")
    if not isinstance(proxies, list):
        return None

    out: list[ProxyInfo] = []
    seen: set[str] = set()
    for entry in proxies:
        if not isinstance(entry, dict):
            continue
        info = _entry_to_info(entry)
        if info is None:
            continue
        if info.dedup_key in seen:
            continue
        seen.add(info.dedup_key)
        out.append(info)
    return out


def _entry_to_info(entry: dict) -> ProxyInfo | None:
    ptype = str(entry.get("type", "")).lower().strip()
    server = str(entry.get("server", "")).strip()
    try:
        port = int(entry.get("port", 0) or 0)
    except (TypeError, ValueError):
        return None
    if not server or not port:
        return None
    name = str(entry.get("name", "") or "")

    if ptype == "ss":
        method = str(entry.get("cipher", "") or "")
        password = str(entry.get("password", "") or "")
        creds = base64.b64encode(
            f"{method}:{password}".encode("utf-8")
        ).decode("ascii").rstrip("=")
        uri = f"ss://{creds}@{server}:{port}"
        if name:
            uri += f"#{urllib.parse.quote(name)}"
        return parse_any(uri)

    if ptype == "vmess":
        uuid = str(entry.get("uuid", "") or "")
        alter = str(entry.get("alterId", 0) or 0)
        cipher = str(entry.get("cipher", "auto") or "auto")
        network = str(entry.get("network", "tcp") or "tcp").lower()
        tls_on = bool(entry.get("tls", False))
        ws_opts = entry.get("ws-opts") or {}
        headers = (ws_opts.get("headers") or {}) if isinstance(ws_opts, dict) else {}
        host = str(headers.get("Host") or "")
        path = str((ws_opts.get("path") if isinstance(ws_opts, dict) else "") or "/")
        sni = str(entry.get("servername") or entry.get("sni") or "")
        data = {
            "v": "2", "ps": name, "add": server, "port": str(port),
            "id": uuid, "aid": alter, "scy": cipher,
            "net": network, "type": "none",
            "host": host, "path": path,
            "tls": "tls" if tls_on else "",
            "sni": sni, "alpn": "", "fp": "",
        }
        blob = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
        b64 = base64.b64encode(blob.encode("utf-8")).decode("ascii")
        return parse_any(f"vmess://{b64}")

    if ptype == "vless":
        uuid = str(entry.get("uuid", "") or "")
        network = str(entry.get("network", "tcp") or "tcp").lower()
        tls_on = bool(entry.get("tls", False))
        reality = entry.get("reality-opts") or {}
        ws_opts = entry.get("ws-opts") or {}
        xhttp_opts = entry.get("xhttp-opts") or {}
        headers = (ws_opts.get("headers") or {}) if isinstance(ws_opts, dict) else {}

        params: dict[str, str] = {
            "type": network,
            "encryption": str(entry.get("encryption", "none") or "none"),
        }
        if reality:
            params["security"] = "reality"
            params["pbk"] = str(reality.get("public-key", "") or "")
            params["sid"] = str(reality.get("short-id", "") or "")
        elif tls_on:
            params["security"] = "tls"
        else:
            params["security"] = "none"

        if entry.get("servername"):
            params["sni"] = str(entry["servername"])
        if entry.get("flow"):
            params["flow"] = str(entry["flow"])
        if entry.get("client-fingerprint"):
            params["fp"] = str(entry["client-fingerprint"])
        if ws_opts:
            params["path"] = str(ws_opts.get("path", "/") or "/")
            if headers.get("Host"):
                params["host"] = str(headers["Host"])
        if xhttp_opts:
            params["path"] = str(xhttp_opts.get("path", "/") or "/")
            if xhttp_opts.get("host"):
                params["host"] = str(xhttp_opts["host"])
        if entry.get("skip-cert-verify"):
            params["allowInsecure"] = "1"

        qs = urllib.parse.urlencode(params)
        uri = f"vless://{uuid}@{server}:{port}?{qs}"
        if name:
            uri += f"#{urllib.parse.quote(name)}"
        return parse_any(uri)

    if ptype == "trojan":
        password = str(entry.get("password", "") or "")
        params: dict[str, str] = {}
        if entry.get("sni"):
            params["sni"] = str(entry["sni"])
        if entry.get("skip-cert-verify"):
            params["allowInsecure"] = "1"
        if str(entry.get("network", "")).lower() == "ws":
            ws_opts = entry.get("ws-opts") or {}
            params["type"] = "ws"
            params["path"] = str(ws_opts.get("path", "/") or "/")
            headers = (ws_opts.get("headers") or {}) if isinstance(ws_opts, dict) else {}
            if headers.get("Host"):
                params["host"] = str(headers["Host"])
        qs = urllib.parse.urlencode(params)
        uri = f"trojan://{urllib.parse.quote(password)}@{server}:{port}"
        if qs:
            uri += f"?{qs}"
        if name:
            uri += f"#{urllib.parse.quote(name)}"
        return parse_any(uri)

    if ptype == "socks5":
        user = str(entry.get("username", "") or "")
        password = str(entry.get("password", "") or "")
        creds = ""
        if user or password:
            creds = f"{urllib.parse.quote(user)}:{urllib.parse.quote(password)}@"
        uri = f"socks5://{creds}{server}:{port}"
        if name:
            uri += f"#{urllib.parse.quote(name)}"
        return parse_any(uri)

    if ptype == "http":
        user = str(entry.get("username", "") or "")
        password = str(entry.get("password", "") or "")
        creds = ""
        if user and user.lower() not in ("null", "none"):
            creds = f"{urllib.parse.quote(user)}:{urllib.parse.quote(password)}@"
        tls_on = bool(entry.get("tls", False))
        scheme = "https" if tls_on else "http"
        uri = f"{scheme}://{creds}{server}:{port}"
        if name:
            uri += f"#{urllib.parse.quote(name)}"
        return parse_any(uri)

    # hysteria, hysteria2, anytls, ...
    return None
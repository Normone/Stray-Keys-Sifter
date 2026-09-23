"""CSV и plain host:port → list[ProxyInfo].

Поддерживает:
    * CSV с заголовком: ip,port,type,user,pass,sni,method,uuid,...
    * CSV без заголовка — эвристика по числу и содержимому колонок
    * plain host:port построчно
    * base64-обёртку делает parsers.py — он вызывает нас после декода

Строит валидный URI и отдаёт его в общий parse_any, чтобы дальше
работал обычный ProxyInfo (dedup, storage, export).
"""
from __future__ import annotations

import base64
import csv
import io
import logging
import re
import urllib.parse

from .parsers import parse_any

log = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────────────────────
#  Маппинг колонок
# ──────────────────────────────────────────────────────────────────────

_HEADER_ALIASES = {
    "host": "host", "ip": "host", "server": "host",
    "address": "host", "addr": "host", "hostname": "host",
    "h": "host",

    "port": "port", "p": "port",

    "type": "scheme", "protocol": "scheme", "scheme": "scheme",
    "proxy_type": "scheme", "proxytype": "scheme", "kind": "scheme",

    "user": "user", "username": "user", "login": "user", "user_name": "user",
    "pass": "pass", "password": "pass", "pwd": "pass",

    "sni": "sni", "servername": "sni", "server_name": "sni",
    "tls": "tls", "https": "tls", "ssl": "tls",

    "method": "method", "cipher": "method", "encryption": "method",
    "uuid": "uuid", "id": "uuid",

    "country": "country", "cc": "country",
    "name": "name", "label": "name", "title": "name",
}

_SCHEME_NAMES = {
    "http", "https", "socks", "socks4", "socks5",
    "ss", "shadowsocks", "vless", "vmess", "trojan",
}

_NULL_VALUES = {"", "null", "none", "nil", "n/a", "-", "unknown", "na"}

_PLAIN_HOSTPORT = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}:\d+$")


def _norm(v: str) -> str:
    return (v or "").strip().strip('"').strip("'")


def _is_null(v: str) -> bool:
    return _norm(v).lower() in _NULL_VALUES


# ──────────────────────────────────────────────────────────────────────
#  Детектор
# ──────────────────────────────────────────────────────────────────────

def looks_like_csv(text: str) -> bool:
    if "://" in text[:2000]:
        return False
    lines = [l.strip() for l in text.splitlines()
             if l.strip() and not l.lstrip().startswith("#")]
    if not lines:
        return False
    sample = lines[:20]
    n = len(sample)

    for d in (",", ";", "\t", "|"):
        hits = sum(1 for l in sample if d in l)
        if hits >= max(2, int(n * 0.6)):
            return True

    plain = sum(1 for l in sample if _PLAIN_HOSTPORT.match(l))
    if plain >= max(2, int(n * 0.6)):
        return True

    return False


# ──────────────────────────────────────────────────────────────────────
#  Парсер
# ──────────────────────────────────────────────────────────────────────

def parse_csv(text: str) -> list:
    lines = [l for l in text.splitlines()
             if l.strip() and not l.lstrip().startswith("#")]
    if not lines:
        return []

    plain_hits = sum(1 for l in lines[:20] if _PLAIN_HOSTPORT.match(l.strip()))
    if plain_hits >= max(2, int(min(len(lines), 20) * 0.6)):
        return _parse_plain_hostport(lines)

    return _parse_csv_rows(lines)


def _parse_plain_hostport(lines: list[str]) -> list:
    seen: set[str] = set()
    out = []
    for line in lines:
        hostport = line.strip()
        if not _PLAIN_HOSTPORT.match(hostport):
            continue
        uri = f"http://{hostport}"
        if uri in seen:
            continue
        seen.add(uri)
        info = parse_any(uri)
        if info:
            out.append(info)
    return out


def _parse_csv_rows(lines: list[str]) -> list:
    sample = "\n".join(lines[:20])
    delimiter = None
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
        delimiter = dialect.delimiter
    except csv.Error:
        first = lines[0]
        delimiter = max((",", ";", "\t", "|"), key=first.count)
        if first.count(delimiter) == 0:
            return []

    reader = csv.reader(io.StringIO("\n".join(lines)), delimiter=delimiter)
    rows = [row for row in reader if row and any(c.strip() for c in row)]
    if not rows:
        return []

    header = [_norm(c).lower() for c in rows[0]]
    has_header = sum(1 for c in header if c in _HEADER_ALIASES) >= 2

    if has_header:
        col_map = {i: _HEADER_ALIASES[c] for i, c in enumerate(header)
                   if c in _HEADER_ALIASES}
        data_rows = rows[1:]
    else:
        col_map = _guess_columns(rows[0])
        data_rows = rows

    if "host" not in col_map.values() or "port" not in col_map.values():
        return []

    seen_uris: set[str] = set()
    out = []
    for row in data_rows:
        uri = _row_to_uri(row, col_map)
        if uri is None or uri in seen_uris:
            continue
        seen_uris.add(uri)
        info = parse_any(uri)
        if info:
            out.append(info)
    return out


def _guess_columns(first_row: list[str]) -> dict[int, str]:
    n = len(first_row)
    cells = [_norm(c) for c in first_row]
    col_map: dict[int, str] = {}

    if n < 2:
        return col_map

    col_map[0] = "host"
    if cells[1].isdigit():
        col_map[1] = "port"

    if n == 2:
        return col_map

    for i in range(2, n):
        c = cells[i].lower()
        if _is_null(c):
            continue
        if c in _SCHEME_NAMES and "scheme" not in col_map.values():
            col_map[i] = "scheme"
        elif "user" not in col_map.values() and i == 2 and n >= 4:
            col_map[i] = "user"
        elif "pass" not in col_map.values() and i == 3 and n >= 4:
            col_map[i] = "pass"
        elif "country" not in col_map.values() and len(c) == 2 and c.isalpha():
            col_map[i] = "country"
        elif "scheme" not in col_map.values():
            col_map[i] = "scheme"
    return col_map


def _row_to_uri(row: list[str], col_map: dict[int, str]) -> str | None:
    fields: dict[str, str] = {}
    for i, role in col_map.items():
        if i < len(row):
            fields[role] = _norm(row[i])

    host = fields.get("host", "")
    port_s = fields.get("port", "")
    if not host or not port_s.isdigit():
        return None
    port = int(port_s)
    if not (1 <= port <= 65535):
        return None

    scheme = (fields.get("scheme") or "http").lower()
    if scheme == "shadowsocks":
        scheme = "ss"
    if scheme == "socks4":
        scheme = "socks5"

    tls_flag = (fields.get("tls") or "").lower()
    tls_on = tls_flag in ("1", "true", "yes", "on")
    if scheme == "http" and tls_on:
        scheme = "https"

    user = fields.get("user", "")
    pass_ = fields.get("pass", "")
    sni = fields.get("sni", "")
    method = fields.get("method", "")
    uuid = fields.get("uuid", "")

    def _auth() -> str:
        if not user:
            return ""
        return f"{urllib.parse.quote(user)}:{urllib.parse.quote(pass_)}@"

    def _sni_qs() -> str:
        if not sni:
            return ""
        return f"sni={urllib.parse.quote(sni)}"

    if scheme == "ss":
        if not method or not pass_:
            return None
        creds = base64.b64encode(
            f"{method}:{pass_}".encode("utf-8")
        ).decode("ascii").rstrip("=")
        return f"ss://{creds}@{host}:{port}"

    if scheme == "trojan":
        if not pass_:
            return None
        qs_parts = [p for p in (_sni_qs(),) if p]
        qs = ("?" + "&".join(qs_parts)) if qs_parts else ""
        return f"trojan://{urllib.parse.quote(pass_)}@{host}:{port}{qs}"

    if scheme == "vless":
        if not uuid:
            return None
        qs_parts = ["encryption=none"]
        if sni:
            qs_parts.append(f"sni={urllib.parse.quote(sni)}")
        return f"vless://{uuid}@{host}:{port}?" + "&".join(qs_parts)

    if scheme == "vmess":
        if not uuid:
            return None
        qs_parts = ["type=tcp", "encryption=none"]
        if sni:
            qs_parts.append(f"sni={urllib.parse.quote(sni)}")
        return f"vmess://{uuid}@{host}:{port}?" + "&".join(qs_parts)

    if scheme in ("socks5", "socks"):
        return f"socks5://{_auth()}{host}:{port}"

    if scheme == "https":
        return f"https://{_auth()}{host}:{port}"

    if scheme == "http":
        return f"http://{_auth()}{host}:{port}"

    return None
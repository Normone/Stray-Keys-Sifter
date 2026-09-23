"""Парсеры прокси-ключей: vless, vmess, trojan, ss, socks5, http, mtproto.

Единый тип ProxyInfo. Схема определяется по префиксу URL.
Поддерживает plaintext, base64, Clash YAML, CSV, plain host:port.
"""
from __future__ import annotations

import base64
import json
import logging
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Iterable

log = logging.getLogger(__name__)


SUPPORTED_SCHEMES = {
    "vless", "vmess", "trojan", "ss", "socks", "socks5", "http", "https",
    "mtproto",
}
KNOWN_UNSUPPORTED = {
    "hysteria2", "hy2", "hysteria", "tuic", "wireguard", "wg", "anytls",
}

_SCHEME_ALT = "|".join(sorted(
    SUPPORTED_SCHEMES | KNOWN_UNSUPPORTED | {"mtproto"},
    key=len, reverse=True,
))

KEY_RE = re.compile(
    rf'(?:{_SCHEME_ALT})://[^\s"\'<>]+'
    r'|(?:tg://proxy\?|https://t\.me/proxy\?)[^\s"\'<>]+',
    re.IGNORECASE,
)

_HAS_SCHEME_RE = re.compile(
    r'(?:vless|vmess|trojan|ss|socks5|socks|http|https|hysteria2|hy2'
    r'|hysteria|tuic|wireguard|wg|anytls)://',
    re.IGNORECASE,
)

# Разделители между ключами (запятая, точка с запятой) — если после них
# сразу идёт <scheme>://, значит это склейка, а не часть URL.
_GLUE_RE = re.compile(
    rf'(?<=[^\s])([,;])(?=(?:{_SCHEME_ALT})://)',
    re.IGNORECASE,
)


# ──────────────────────────────────────────────────────────────────────
#  Тип
# ──────────────────────────────────────────────────────────────────────

@dataclass
class ProxyInfo:
    raw: str
    scheme: str
    host: str
    port: int
    uuid: str = ""
    name: str = ""
    params: dict[str, str] = field(default_factory=dict)

    method: str = ""
    password: str = ""

    alter_id: int = 0
    cipher: str = "auto"

    @property
    def security(self) -> str:
        return self.params.get("security", "none").lower()

    @property
    def network(self) -> str:
        return self.params.get("type", self.params.get("network", "tcp")).lower()

    @property
    def sni(self) -> str:
        return (self.params.get("sni")
                or self.params.get("serverName")
                or self.params.get("host")
                or self.host)

    @property
    def flow(self) -> str:
        return self.params.get("flow", "")

    @property
    def fp(self) -> str:
        return self.params.get("fp", "")

    @property
    def pbk(self) -> str:
        return self.params.get("pbk", "")

    @property
    def endpoint(self) -> tuple[str, int]:
        return (self.host, self.port)

    @property
    def dedup_key(self) -> str:
        ident = self.uuid or self.password or self.method or ""
        return f"{self.scheme}://{ident}@{self.host}:{self.port}"

    @property
    def display_name(self) -> str:
        return self.name or f"{self.host}:{self.port}"

    @property
    def protocol_label(self) -> str:
        s = self.scheme
        if s == "vless":
            if self.pbk or self.security == "reality":
                return "Reality"
            if self.security in ("tls", "xtls"):
                if self.network == "xhttp":
                    return "XHTTP+TLS"
                if self.network == "ws":
                    return "WS+TLS"
                if self.network == "grpc":
                    return "gRPC+TLS"
                if self.network == "httpupgrade":
                    return "HU+TLS"
                return "TLS"
            if self.network == "xhttp":
                return "XHTTP"
            if self.network == "ws":
                return "WS"
            if self.network == "grpc":
                return "gRPC"
            return "TCP"
        if s == "vmess":
            return f"VMess/{self.network.upper()}"
        if s == "trojan":
            return "Trojan"
        if s == "ss":
            return f"SS/{self.method or '?'}"
        if s == "socks":
            return "SOCKS"
        if s == "http":
            return "HTTPS" if self.security == "tls" else "HTTP"
        if s == "mtproto":
            return "MTProto"
        return s.upper()


VlessInfo = ProxyInfo


# ──────────────────────────────────────────────────────────────────────
#  Статистика по тексту
# ──────────────────────────────────────────────────────────────────────

@dataclass
class TextStats:
    kind: str = "uri"                    # uri / yaml / csv / base64-uri / base64-csv
    total_lines: int = 0                 # строк в исходнике
    raw_uris: int = 0                    # найдено <scheme>:// (всего)
    supported: int = 0                   # из них с поддерживаемой схемой
    unsupported: int = 0                 # hysteria2 / tuic / anytls / ...
    parsed_ok: int = 0                   # успешно распарсено
    parse_fail: int = 0                  # регексп нашёл, парсер вернул None
    unique: int = 0                      # после дедупа по dedup_key
    by_scheme: dict[str, int] = field(default_factory=dict)
    unsupported_schemes: dict[str, int] = field(default_factory=dict)

    def merge_from(self, other: "TextStats") -> None:
        self.total_lines += other.total_lines
        self.raw_uris += other.raw_uris
        self.supported += other.supported
        self.unsupported += other.unsupported
        self.parsed_ok += other.parsed_ok
        self.parse_fail += other.parse_fail
        for k, v in other.by_scheme.items():
            self.by_scheme[k] = self.by_scheme.get(k, 0) + v
        for k, v in other.unsupported_schemes.items():
            self.unsupported_schemes[k] = \
                self.unsupported_schemes.get(k, 0) + v


# ──────────────────────────────────────────────────────────────────────
#  Base64
# ──────────────────────────────────────────────────────────────────────

def _maybe_decode_base64(text: str) -> str:
    text = text.lstrip("\ufeff")
    if _HAS_SCHEME_RE.search(text):
        return text
    if "proxies:" in text or "proxy-providers:" in text:
        return text

    compact = re.sub(r"[^A-Za-z0-9+/=_-]", "", text)
    if len(compact) < 32:
        return text

    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            padded = compact + "=" * (-len(compact) % 4)
            decoded = decoder(padded).decode("utf-8", errors="replace")
        except Exception:
            continue
        if (_HAS_SCHEME_RE.search(decoded)
                or "tg://proxy" in decoded
                or "proxies:" in decoded):
            log.debug("base64 decoded (%d -> %d chars)",
                      len(text), len(decoded))
            return decoded
    return text


def _normalize_separators(text: str) -> str:
    """'vless://...,vless://...' → 'vless://...\\nvless://...'.

    Склейка ключей через запятую/точку с запятой без пробелов ломает regex:
    он захватывает оба ключа как один. Разбиваем заранее, но только там,
    где после разделителя идёт новая схема — тогда запятая внутри query
    (например `alpn=h2,http/1.1`) останется целой.
    """
    return _GLUE_RE.sub("\n", text)


# ──────────────────────────────────────────────────────────────────────
#  Вспомогательные
# ──────────────────────────────────────────────────────────────────────

def _split_remark(s: str) -> tuple[str, str]:
    if "#" in s:
        body, frag = s.split("#", 1)
        return body, urllib.parse.unquote(frag).strip()
    return s, ""


def _split_params(s: str) -> tuple[str, dict[str, str]]:
    if "?" not in s:
        return s, {}
    body, qs = s.split("?", 1)
    return body, {k: v[0] for k, v in urllib.parse.parse_qs(qs).items()}


def _hostport(s: str, default_port: int = 443) -> tuple[str, int]:
    if s.startswith("["):
        end = s.find("]")
        if end == -1:
            return s.lower(), default_port
        host = s[1:end].lower()
        rest = s[end + 1:]
        port_s = rest[1:] if rest.startswith(":") else ""
    elif ":" in s:
        host, port_s = s.rsplit(":", 1)
        host = host.lower()
    else:
        host, port_s = s.lower(), ""
    port = int(port_s) if port_s.isdigit() else default_port
    return host, port


def _scheme_of(url: str) -> str:
    low = url.lower()
    if low.startswith("tg://") or low.startswith("https://t.me/proxy"):
        return "mtproto"
    return low.split("://", 1)[0]


# ──────────────────────────────────────────────────────────────────────
#  Парсеры
# ──────────────────────────────────────────────────────────────────────

def parse_vless(url: str) -> ProxyInfo | None:
    try:
        body = url[len("vless://"):]
        body, name = _split_remark(body)
        body, params = _split_params(body)
        if "@" not in body:
            return None
        uuid, hostport = body.rsplit("@", 1)
        host, port = _hostport(hostport)
        if not host:
            return None
        return ProxyInfo(
            raw=url, scheme="vless", host=host, port=port,
            uuid=uuid, name=name, params=params,
        )
    except Exception as e:
        log.debug("parse_vless error: %s", e)
        return None


def _vmess_build_canonical(data: dict) -> str:
    canonical = {
        "v": str(data.get("v", "2")),
        "ps": str(data.get("ps", "")),
        "add": str(data.get("add", "")),
        "port": str(data.get("port", 443)),
        "id": str(data.get("id", "")),
        "aid": str(data.get("aid", 0)),
        "scy": str(data.get("scy", "auto")),
        "net": str(data.get("net", "tcp")),
        "type": str(data.get("type", "none")),
        "host": str(data.get("host", "")),
        "path": str(data.get("path", "")),
        "tls": str(data.get("tls", "")),
        "sni": str(data.get("sni", "")),
        "alpn": str(data.get("alpn", "")),
        "fp": str(data.get("fp", "")),
    }
    blob = json.dumps(canonical, ensure_ascii=False, separators=(",", ":"))
    b64 = base64.b64encode(blob.encode("utf-8")).decode("ascii")
    return f"vmess://{b64}"


def parse_vmess(url: str) -> ProxyInfo | None:
    try:
        body = url[len("vmess://"):]
        body, name = _split_remark(body)
        body, params = _split_params(body)

        data: dict = {}

        if "@" in body and ":" in body.split("@", 1)[1]:
            uuid, hostport = body.rsplit("@", 1)
            host, port = _hostport(hostport)
            data = {
                "v": "2", "ps": name, "add": host, "port": str(port),
                "id": uuid, "aid": "0", "scy": "auto",
                "net": params.get("type", "tcp"),
                "type": params.get("headerType", "none"),
                "host": params.get("host", ""),
                "path": params.get("path", ""),
                "tls": params.get("security", ""),
                "sni": params.get("sni", ""),
                "alpn": params.get("alpn", ""),
                "fp": params.get("fp", ""),
            }
        else:
            compact = re.sub(r"\s+", "", body)
            padded = compact + "=" * (-len(compact) % 4)
            decoded = base64.b64decode(padded, validate=False).decode("utf-8")
            data = json.loads(decoded)
            for k in ("v", "ps", "add", "port", "id", "aid", "scy",
                      "net", "type", "host", "path", "tls", "sni",
                      "alpn", "fp"):
                if k in data and not isinstance(data[k], str):
                    data[k] = str(data[k])

        host = str(data.get("add", "")).lower()
        if not host:
            return None
        port = int(str(data.get("port", 443)) or 443)
        net = str(data.get("net", "tcp")).lower()
        tls = str(data.get("tls", "")).lower()
        security = "tls" if tls in ("tls", "reality") else "none"

        raw_canonical = _vmess_build_canonical({
            **data, "add": host, "port": port,
            "net": net, "tls": tls,
            "ps": name or data.get("ps", ""),
        })

        parsed_params = {
            "type": net,
            "security": security,
            "sni": str(data.get("sni") or data.get("host") or ""),
            "host": str(data.get("host") or ""),
            "path": str(data.get("path") or "/"),
            "serviceName": str(data.get("path") or ""),
            "fp": str(data.get("fp") or ""),
            "alpn": str(data.get("alpn") or ""),
        }
        return ProxyInfo(
            raw=raw_canonical, scheme="vmess",
            host=host, port=port,
            uuid=str(data.get("id", "")),
            alter_id=int(str(data.get("aid", 0)) or 0),
            cipher=str(data.get("scy", "auto") or "auto"),
            name=name or str(data.get("ps", "")),
            params={k: v for k, v in parsed_params.items() if v},
        )
    except Exception as e:
        log.debug("parse_vmess skip: %s", e)
        return None


def parse_trojan(url: str) -> ProxyInfo | None:
    try:
        body = url[len("trojan://"):]
        body, name = _split_remark(body)
        body, params = _split_params(body)
        if "@" not in body:
            return None
        password, hostport = body.rsplit("@", 1)
        host, port = _hostport(hostport)
        if not host:
            return None
        return ProxyInfo(
            raw=url, scheme="trojan", host=host, port=port,
            password=urllib.parse.unquote(password),
            name=name, params=params,
        )
    except Exception as e:
        log.debug("parse_trojan error: %s", e)
        return None


def parse_ss(url: str) -> ProxyInfo | None:
    try:
        body = url[len("ss://"):]
        body, name = _split_remark(body)
        body, params = _split_params(body)

        if "@" not in body:
            padded = body + "=" * (-len(body) % 4)
            decoded = base64.b64decode(padded).decode("utf-8")
            if "@" not in decoded or ":" not in decoded.split("@", 1)[0]:
                return None
            creds, hostport = decoded.rsplit("@", 1)
            method, password = creds.split(":", 1)
            host, port = _hostport(hostport, default_port=8388)
            return ProxyInfo(
                raw=url, scheme="ss", host=host, port=port,
                method=method, password=password, name=name, params=params,
            )

        creds_b64, hostport = body.rsplit("@", 1)
        try:
            padded = creds_b64 + "=" * (-len(creds_b64) % 4)
            decoded = base64.b64decode(padded).decode("utf-8")
            if ":" in decoded:
                method, password = decoded.split(":", 1)
            else:
                method, password = "", decoded
        except Exception:
            if ":" in creds_b64:
                method, password = creds_b64.split(":", 1)
            else:
                return None

        host, port = _hostport(hostport, default_port=8388)
        return ProxyInfo(
            raw=url, scheme="ss", host=host, port=port,
            method=method, password=password, name=name, params=params,
        )
    except Exception as e:
        log.debug("parse_ss error: %s", e)
        return None


def parse_socks(url: str) -> ProxyInfo | None:
    try:
        scheme = "socks5" if url.startswith("socks5://") else "socks"
        body = url[len(scheme + "://"):]
        body, name = _split_remark(body)
        body, params = _split_params(body)

        if "@" in body:
            creds, hostport = body.rsplit("@", 1)
            if ":" in creds:
                user, password = creds.split(":", 1)
            else:
                user, password = creds, ""
        else:
            hostport = body
            user = password = ""

        host, port = _hostport(hostport, default_port=1080)
        if not host:
            return None
        info = ProxyInfo(
            raw=url, scheme="socks", host=host, port=port,
            name=name, params=params,
        )
        if user:
            info.params["user"] = user
        if password:
            info.params["pass"] = password
        return info
    except Exception as e:
        log.debug("parse_socks error: %s", e)
        return None


def parse_http(url: str) -> ProxyInfo | None:
    try:
        if url.startswith("https://"):
            body = url[len("https://"):]
            security = "tls"
            default_port = 443
        elif url.startswith("http://"):
            body = url[len("http://"):]
            security = "none"
            default_port = 80
        else:
            return None

        body, name = _split_remark(body)
        body, params = _split_params(body)

        if "@" in body:
            creds, hostport = body.rsplit("@", 1)
            if ":" in creds:
                user, password = creds.split(":", 1)
            else:
                user, password = creds, ""
        else:
            hostport = body
            user = password = ""

        host, port = _hostport(hostport, default_port=default_port)
        if not host:
            return None

        params = dict(params)
        params["security"] = security
        if user:
            params["user"] = urllib.parse.unquote(user)
        if password:
            params["pass"] = urllib.parse.unquote(password)

        return ProxyInfo(
            raw=url, scheme="http", host=host, port=port,
            name=name, params=params,
        )
    except Exception as e:
        log.debug("parse_http error: %s", e)
        return None


def parse_mtproto(url: str) -> ProxyInfo | None:
    try:
        u = url.replace("tg://", "http://").replace("https://t.me/", "http://")
        parsed = urllib.parse.urlparse(u)
        q = urllib.parse.parse_qs(parsed.query)
        server = (q.get("server") or [None])[0]
        port_s = (q.get("port") or [None])[0]
        if not server or not port_s or not port_s.isdigit():
            return None
        return ProxyInfo(
            raw=url, scheme="mtproto",
            host=server, port=int(port_s),
            password=(q.get("secret") or [""])[0],
        )
    except Exception as e:
        log.debug("parse_mtproto error: %s", e)
        return None


_PARSERS = {
    "vless": parse_vless,
    "vmess": parse_vmess,
    "trojan": parse_trojan,
    "ss": parse_ss,
    "socks": parse_socks,
    "socks5": parse_socks,
    "http": parse_http,
    "https": parse_http,
    "mtproto": parse_mtproto,
}


def parse_any(url: str) -> ProxyInfo | None:
    scheme = _scheme_of(url)
    fn = _PARSERS.get(scheme)
    if fn is None:
        return None
    return fn(url)


# ──────────────────────────────────────────────────────────────────────
#  Анализ текста
# ──────────────────────────────────────────────────────────────────────

def extract_keys(text: str) -> list[str]:
    return KEY_RE.findall(text or "")


def analyze_text(text: str) -> tuple[TextStats, list[ProxyInfo]]:
    """Возвращает (TextStats, list[ProxyInfo] после дедупа)."""
    stats = TextStats()
    text = (text or "").lstrip("\ufeff")
    if not text:
        return stats, []

    stats.total_lines = len(text.splitlines())

    # 1. YAML
    if "proxies:" in text or "proxy-providers:" in text:
        from .yaml_parser import parse_clash_yaml
        yaml_infos = parse_clash_yaml(text) or []
        stats.kind = "yaml"
        stats.raw_uris = len(yaml_infos)
        stats.supported = len(yaml_infos)
        stats.parsed_ok = len(yaml_infos)
        seen: set[str] = set()
        unique: list[ProxyInfo] = []
        for p in yaml_infos:
            if p.dedup_key in seen:
                continue
            seen.add(p.dedup_key)
            unique.append(p)
            stats.by_scheme[p.scheme] = stats.by_scheme.get(p.scheme, 0) + 1
        stats.unique = len(unique)
        return stats, unique

    # 2. CSV
    from .csv_parser import looks_like_csv, parse_csv
    if looks_like_csv(text):
        csv_infos = parse_csv(text)
        stats.kind = "csv"
        stats.raw_uris = len(csv_infos)
        stats.supported = len(csv_infos)
        stats.parsed_ok = len(csv_infos)
        seen: set[str] = set()
        unique: list[ProxyInfo] = []
        for p in csv_infos:
            if p.dedup_key in seen:
                continue
            seen.add(p.dedup_key)
            unique.append(p)
            stats.by_scheme[p.scheme] = stats.by_scheme.get(p.scheme, 0) + 1
        stats.unique = len(unique)
        return stats, unique

    # 3. base64
    decoded = _maybe_decode_base64(text)
    if decoded != text:
        stats.kind = "base64-"
        if looks_like_csv(decoded):
            csv_infos = parse_csv(decoded)
            stats.kind = "base64-csv"
            stats.raw_uris = len(csv_infos)
            stats.supported = len(csv_infos)
            stats.parsed_ok = len(csv_infos)
            seen: set[str] = set()
            unique: list[ProxyInfo] = []
            for p in csv_infos:
                if p.dedup_key in seen:
                    continue
                seen.add(p.dedup_key)
                unique.append(p)
                stats.by_scheme[p.scheme] = \
                    stats.by_scheme.get(p.scheme, 0) + 1
            stats.unique = len(unique)
            return stats, unique
        text = decoded

    stats.kind = stats.kind + "uri" if stats.kind else "uri"

    # 4. Обычный URI-список
    text = _normalize_separators(text)

    seen: set[str] = set()
    out: list[ProxyInfo] = []
    for url in KEY_RE.findall(text):
        scheme = _scheme_of(url)
        stats.raw_uris += 1
        if scheme not in SUPPORTED_SCHEMES:
            stats.unsupported += 1
            stats.unsupported_schemes[scheme] = \
                stats.unsupported_schemes.get(scheme, 0) + 1
            continue
        stats.supported += 1
        info = parse_any(url)
        if info is None:
            stats.parse_fail += 1
            continue
        stats.parsed_ok += 1
        if info.dedup_key in seen:
            continue
        seen.add(info.dedup_key)
        out.append(info)
        stats.by_scheme[info.scheme] = stats.by_scheme.get(info.scheme, 0) + 1
    stats.unique = len(out)
    return stats, out


def parse_all_text(text: str, *, quiet: bool = False) -> list[ProxyInfo]:
    stats, infos = analyze_text(text)
    if not quiet and infos:
        log.info("  parsed(%s): %s", stats.kind,
                 " ".join(f"{k}={v}" for k, v in sorted(stats.by_scheme.items())))
    return infos


def parse_vless_text(text: str) -> list[ProxyInfo]:
    return [p for p in parse_all_text(text, quiet=True) if p.scheme == "vless"]


def dedup_vless(infos: Iterable[ProxyInfo]) -> list[ProxyInfo]:
    seen: set[str] = set()
    out: list[ProxyInfo] = []
    for info in infos:
        if info.dedup_key in seen:
            continue
        seen.add(info.dedup_key)
        out.append(info)
    return out


MTProtoInfo = ProxyInfo


def parse_mtproto_text(text: str) -> list[ProxyInfo]:
    return [p for p in parse_all_text(text, quiet=True) if p.scheme == "mtproto"]
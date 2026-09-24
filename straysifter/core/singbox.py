"""Проверка ключей через sing-box.

Альтернатива core.checks.run_check. Поднимает один процесс sing-box
с Clash API, регистрирует все ключи как outbounds, и параллельно
дёргает /proxies/{tag}/delay для каждого. Результат — реальная
работоспособность туннеля через HTTP-запрос, а не просто открытый порт.

sing-box поддерживает все наши схемы, кроме mtproto. Hysteria2 тоже
проверяется (sing-box умеет её нативно, в отличие от голого TCP).

Если sing-box падает на конкретном outbound — парсим индекс из stderr,
выкидываем его и перезапускаем batch. Так один битый ключ не уносит
с собой остальные 4999.

Бинарник sing-box НЕ идёт с pip-пакетом. Его нужно положить в
bin/sing-box/sing-box.exe (Windows) или bin/sing-box/sing-box (Linux/macOS).
Путь можно переопределить через checks.singbox_path.
"""
from __future__ import annotations

import base64
import binascii
import json
import logging
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid as _uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Callable, Iterable

from .config import ChecksConfig
from .parsers import ProxyInfo

log = logging.getLogger(__name__)

ProgressCb = Callable[[str, int, int, int], None]

BATCH_SIZE = 5000
API_WORKERS = 100
CHECK_URL = "http://www.gstatic.com/generate_204"
MAX_DROP_RETRIES = 100

SINGBOX_SCHEMES = {
    "vless", "vmess", "trojan", "ss", "socks", "http", "https",
    "hysteria", "hysteria2",
}

SUPPORTED_NETWORKS = {
    "", "tcp", "raw", "ws", "grpc", "httpupgrade", "http", "quic",
}

_VALID_FP = {
    "chrome", "firefox", "edge", "safari", "360", "qq",
    "ios", "android", "random", "randomized",
    "hellochrome", "hellofirefox", "hellosafari", "helloios",
}

_VALID_FLOWS = {"xtls-rprx-vision"}

_VALID_VMESS_SECURITY = {
    "auto", "aes-128-gcm", "chacha20-poly1305", "none", "zero",
}

_SS_METHOD_ALIASES = {
    "aes-128-gcm": "aes-128-gcm",
    "aes-192-gcm": "aes-192-gcm",
    "aes-256-gcm": "aes-256-gcm",
    "chacha20-poly1305": "chacha20-ietf-poly1305",
    "chacha20-ietf-poly1305": "chacha20-ietf-poly1305",
    "xchacha20-poly1305": "xchacha20-ietf-poly1305",
    "xchacha20-ietf-poly1305": "xchacha20-ietf-poly1305",
    "2022-blake3-aes-128-gcm": "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm": "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305": "2022-blake3-chacha20-poly1305",
}

_OUTBOUND_IDX_RE = re.compile(r"outbound\[(\d+)\]")


def find_binary(cfg_path: str = "") -> Path | None:
    from .paths import find_home

    if cfg_path:
        p = Path(cfg_path)
        if p.exists():
            return p
        log.warning("singbox: указанный путь не найден: %s", p)

    exe = "sing-box.exe" if sys.platform.startswith("win") else "sing-box"
    local = find_home() / "bin" / "sing-box" / exe
    if local.exists():
        return local

    which = shutil.which("sing-box")
    if which:
        return Path(which)

    return None


def _pick_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# ──────────────────────────────────────────────────────────────────────
#  Валидация полей
# ──────────────────────────────────────────────────────────────────────

def _normalize_flow(flow: str) -> str:
    if not flow:
        return ""
    f = flow.strip().lower()
    if f.endswith("-udp443"):
        f = f[:-7]
    return f if f in _VALID_FLOWS else ""


def _is_valid_pbk(pbk: str) -> bool:
    """Reality public key: base64url без padding, ~43-44 символа.

    base64.b64decode с validate=True обязателен — иначе невалидные
    символы молча игнорируются, и мусорная строка проходит как валидная.
    """
    if not pbk or not (40 <= len(pbk) <= 60):
        return False
    try:
        pad = pbk + "=" * (-len(pbk) % 4)
        base64.b64decode(pad, altchars=b"-_", validate=True)
    except (binascii.Error, ValueError):
        return False
    return True


def _is_valid_sid(sid: str) -> bool:
    if not sid:
        return True
    s = sid.strip()
    if len(s) > 16:
        return False
    try:
        int(s, 16)
    except ValueError:
        return False
    return True


def _is_valid_uuid(u: str) -> bool:
    if not u:
        return False
    try:
        _uuid.UUID(u)
        return True
    except Exception:
        pass
    if len(u) == 32:
        try:
            _uuid.UUID(u)
            return True
        except Exception:
            return False
    return False


def _normalize_fp(fp: str) -> str:
    if not fp:
        return "chrome"
    f = fp.strip().lower()
    return f if f in _VALID_FP else "chrome"


def _normalize_vmess_security(sec: str) -> str:
    if not sec:
        return "auto"
    s = sec.strip().lower()
    return s if s in _VALID_VMESS_SECURITY else "auto"


def _normalize_ss_method(method: str) -> str | None:
    if not method:
        return None
    return _SS_METHOD_ALIASES.get(method.strip().lower())


def _is_valid_ss_password(method: str, password: str) -> bool:
    if not password:
        return False
    if not method.startswith("2022-blake3"):
        return True
    try:
        pad = password + "=" * (-len(password) % 4)
        base64.b64decode(pad, validate=True)
        return True
    except (binascii.Error, ValueError):
        return False


def _reality_ok(info: ProxyInfo) -> bool:
    """Если security=reality — pbk и sid должны быть валидны.

    Без этого _tls_block вернёт None, и мы молча соберём plain vless
    без TLS — нерабочий ключ, который зря съест слот в batch'е.
    """
    if info.security != "reality":
        return True
    if not _is_valid_pbk(info.pbk):
        return False
    sid = (info.params.get("sid") or "").strip()
    return _is_valid_sid(sid)


# ──────────────────────────────────────────────────────────────────────
#  ProxyInfo → sing-box outbound
# ──────────────────────────────────────────────────────────────────────

def _tls_block(info: ProxyInfo) -> dict | None:
    sec = info.security
    if sec in ("", "none"):
        return None

    tls: dict = {"enabled": True}

    server_name = info.params.get("sni") or info.params.get("peer") or ""
    if not server_name:
        server_name = info.params.get("host") or ""
    if server_name:
        tls["server_name"] = server_name

    if info.params.get("allowInsecure") in ("1", "true", "True"):
        tls["insecure"] = True

    if info.scheme in ("vless", "vmess", "trojan"):
        tls["utls"] = {
            "enabled": True,
            "fingerprint": _normalize_fp(info.fp),
        }

    if sec == "reality":
        # _reality_ok гарантирует, что pbk и sid валидны.
        sid = (info.params.get("sid") or "").strip()
        tls["reality"] = {
            "enabled": True,
            "public_key": info.pbk,
            "short_id": sid,
        }
    return tls


def _transport_block(info: ProxyInfo) -> dict | None:
    net = info.network
    if net in ("", "tcp", "raw"):
        return None

    if net == "ws":
        t: dict = {"type": "ws", "path": info.params.get("path", "/")}
        host = info.params.get("host", "")
        if host:
            t["headers"] = {"Host": host}
        return t

    if net == "grpc":
        return {
            "type": "grpc",
            "service_name": info.params.get("serviceName", ""),
        }

    if net == "httpupgrade":
        t = {"type": "httpupgrade", "path": info.params.get("path", "/")}
        host = info.params.get("host", "")
        if host:
            t["host"] = host
        return t

    if net == "http":
        t = {"type": "http", "path": info.params.get("path", "/")}
        host = info.params.get("host", "")
        if host:
            t["host"] = [host]
        return t

    if net == "quic":
        return {"type": "quic"}

    return None


def _build_outbound_inner(info: ProxyInfo, tag: str) -> dict | None:
    if info.scheme not in SINGBOX_SCHEMES:
        return None
    if not info.host or not (1 <= info.port <= 65535):
        return None
    if info.network not in SUPPORTED_NETWORKS:
        return None
    if not _reality_ok(info):
        return None

    base: dict = {
        "tag": tag,
        "server": info.host,
        "server_port": info.port,
    }
    scheme = info.scheme
    transport = _transport_block(info)
    tls = _tls_block(info)

    if scheme == "vless":
        if not _is_valid_uuid(info.uuid):
            return None
        base["type"] = "vless"
        base["uuid"] = info.uuid
        flow = _normalize_flow(info.flow)
        if flow:
            base["flow"] = flow
        if transport:
            base["transport"] = transport
        if tls:
            base["tls"] = tls
        return base

    if scheme == "vmess":
        if not _is_valid_uuid(info.uuid):
            return None
        base["type"] = "vmess"
        base["uuid"] = info.uuid
        base["alter_id"] = int(info.alter_id or 0)
        base["security"] = _normalize_vmess_security(info.cipher)
        if transport:
            base["transport"] = transport
        if tls:
            base["tls"] = tls
        return base

    if scheme == "trojan":
        if not info.password:
            return None
        base["type"] = "trojan"
        base["password"] = info.password
        if transport:
            base["transport"] = transport
        base["tls"] = tls or {"enabled": True}
        return base

    if scheme == "ss":
        method = _normalize_ss_method(info.method)
        if not method:
            return None
        if not _is_valid_ss_password(method, info.password):
            return None
        base["type"] = "shadowsocks"
        base["method"] = method
        base["password"] = info.password
        return base

    if scheme == "socks":
        base["type"] = "socks"
        base["version"] = "5"
        user = info.params.get("user")
        pw = info.params.get("pass")
        if user:
            base["username"] = user
            base["password"] = pw or ""
        return base

    if scheme in ("http", "https"):
        base["type"] = "http"
        user = info.params.get("user")
        pw = info.params.get("pass")
        if user:
            base["username"] = user
            base["password"] = pw or ""
        if scheme == "https":
            base["tls"] = {"enabled": True}
        return base

    if scheme == "hysteria2":
        if not info.password:
            return None
        base["type"] = "hysteria2"
        base["password"] = info.password
        t = tls or {"enabled": True}
        t["enabled"] = True
        if info.params.get("insecure") in ("1", "true"):
            t["insecure"] = True
        if info.params.get("obfs-password"):
            base["obfs"] = {
                "type": "salamander",
                "password": info.params["obfs-password"],
            }
        base["tls"] = t
        return base

    if scheme == "hysteria":
        if not info.password:
            return None
        base["type"] = "hysteria"
        base["auth_str"] = info.password
        base["tls"] = tls or {"enabled": True}
        base["up_mbps"] = 50
        base["down_mbps"] = 100
        return base

    return None


def build_outbound(info: ProxyInfo, tag: str) -> dict | None:
    try:
        return _build_outbound_inner(info, tag)
    except Exception as e:
        log.debug("singbox: build_outbound skip (%s://%s:%s): %s",
                  info.scheme, info.host, info.port, e)
        return None


# ──────────────────────────────────────────────────────────────────────
#  sing-box процесс
# ──────────────────────────────────────────────────────────────────────

def _extract_outbound_index(stderr: str) -> int | None:
    m = _OUTBOUND_IDX_RE.search(stderr)
    if not m:
        return None
    try:
        return int(m.group(1))
    except ValueError:
        return None


def _build_config(outbounds: list[dict], api_port: int) -> dict:
    return {
        "log": {"level": "error"},
        "outbounds": outbounds + [
            {"type": "direct", "tag": "direct"},
            {"type": "block", "tag": "block"},
        ],
        "experimental": {
            "clash_api": {
                "external_controller": f"127.0.0.1:{api_port}",
            }
        },
    }


def _wait_for_api(proc: subprocess.Popen, port: int,
                  timeout: float = 20.0) -> bool:
    deadline = time.monotonic() + timeout
    url = f"http://127.0.0.1:{port}/"
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            return False
        try:
            with urllib.request.urlopen(url, timeout=0.5) as r:
                r.read(64)
                return True
        except urllib.error.HTTPError:
            return True
        except Exception:
            time.sleep(0.2)
    return False


def _delay_via_api(port: int, tag: str, timeout_ms: int) -> int | None:
    qs = urllib.parse.urlencode({"url": CHECK_URL, "timeout": timeout_ms})
    url = f"http://127.0.0.1:{port}/proxies/{tag}/delay?{qs}"
    try:
        with urllib.request.urlopen(url, timeout=timeout_ms / 1000 + 2) as r:
            data = json.loads(r.read())
            d = data.get("delay")
            if isinstance(d, int) and d > 0:
                return d
            return None
    except Exception:
        return None


def _try_start(binary: Path, outbounds: list[dict]):
    api_port = _pick_free_port()
    config = _build_config(outbounds, api_port)

    with tempfile.NamedTemporaryFile(
        "w", suffix=".json", delete=False, encoding="utf-8"
    ) as fh:
        json.dump(config, fh)
        cfg_path = fh.name

    err_fh = tempfile.NamedTemporaryFile(
        "w", suffix=".err", delete=False, encoding="utf-8"
    )
    err_path = err_fh.name
    err_fh.close()

    err_f = open(err_path, "w", encoding="utf-8")
    proc = subprocess.Popen(
        [str(binary), "run", "-c", cfg_path],
        stdout=subprocess.DEVNULL,
        stderr=err_f,
    )
    err_f.close()

    if not _wait_for_api(proc, api_port, timeout=20.0):
        return None, api_port, cfg_path, err_path

    return proc, api_port, cfg_path, err_path


def _read_err(err_path: str) -> str:
    try:
        return Path(err_path).read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""


def _do_url_tests(
    api_port: int,
    tag_to_info: dict[str, ProxyInfo],
    cfg: ChecksConfig,
    on_progress: ProgressCb | None,
    done_offset: int,
    total: int,
    static_skipped: int,
) -> list[tuple[ProxyInfo, int]]:
    timeout_ms = int(cfg.singbox_timeout * 1000)
    results: list[tuple[ProxyInfo, int]] = []
    done = static_skipped
    total_in_batch = len(tag_to_info) + static_skipped
    with ThreadPoolExecutor(max_workers=API_WORKERS) as ex:
        fmap = {
            ex.submit(_delay_via_api, api_port, tag, timeout_ms): tag
            for tag in tag_to_info
        }
        for fut in as_completed(fmap):
            tag = fmap[fut]
            ping = fut.result()
            info = tag_to_info[tag]
            done += 1
            if ping is not None:
                results.append((info, ping))
            if on_progress and (done % 50 == 0 or done == total_in_batch):
                on_progress("singbox", done_offset + done, total,
                            len(results))
    return results


def _check_batch(
    infos: list[ProxyInfo],
    binary: Path,
    cfg: ChecksConfig,
    on_progress: ProgressCb | None,
    done_offset: int,
    total: int,
) -> tuple[list[tuple[ProxyInfo, int]], int]:
    pairs: list[tuple[str, ProxyInfo, dict]] = []
    skipped = 0
    for i, info in enumerate(infos):
        tag = f"p{i}"
        ob = build_outbound(info, tag)
        if ob is None:
            skipped += 1
            continue
        pairs.append((tag, info, ob))

    if not pairs:
        return [], skipped

    for attempt in range(MAX_DROP_RETRIES):
        outbounds = [ob for _, _, ob in pairs]
        tag_to_info = {tag: info for tag, info, _ in pairs}

        proc, api_port, cfg_path, err_path = _try_start(binary, outbounds)

        try:
            if proc is not None:
                static_skipped = len(infos) - len(pairs)
                results = _do_url_tests(
                    api_port, tag_to_info, cfg, on_progress,
                    done_offset, total, static_skipped,
                )
                return results, skipped

            err_text = _read_err(err_path)
            bad_idx = _extract_outbound_index(err_text)
            if bad_idx is None or bad_idx >= len(pairs):
                log.warning("singbox: cannot recover batch: %s",
                            err_text[:400])
                return [], skipped

            bad_info = pairs[bad_idx][1]
            log.info("singbox: dropping bad outbound[%d] %s://%s:%s",
                     bad_idx, bad_info.scheme,
                     bad_info.host, bad_info.port)
            pairs.pop(bad_idx)
            skipped += 1
            if not pairs:
                return [], skipped
        finally:
            if proc is not None:
                try:
                    proc.terminate()
                    proc.wait(timeout=3)
                except Exception:
                    try:
                        proc.kill()
                    except Exception:
                        pass
            for p in (cfg_path, err_path):
                try:
                    os.unlink(p)
                except Exception:
                    pass

    log.warning("singbox: max drop retries (%d) exceeded", MAX_DROP_RETRIES)
    return [], skipped


# ──────────────────────────────────────────────────────────────────────
#  Публичный вход
# ──────────────────────────────────────────────────────────────────────

def run_singbox_check(
    infos: Iterable[ProxyInfo],
    cfg: ChecksConfig,
    on_progress: ProgressCb | None = None,
) -> list:
    from .checks import CheckResult

    infos = [i for i in infos if i.scheme in SINGBOX_SCHEMES]
    if not infos:
        return []

    binary = find_binary(cfg.singbox_path)
    if binary is None:
        log.error("singbox: бинарник не найден. Положи в bin/sing-box/ "
                  "или укажи checks.singbox_path в config.json")
        return []

    log.info("singbox: binary=%s, keys=%d, batch=%d, api_workers=%d",
             binary, len(infos), BATCH_SIZE, API_WORKERS)

    batches = [infos[i:i + BATCH_SIZE]
               for i in range(0, len(infos), BATCH_SIZE)]
    all_results: list[tuple[ProxyInfo, int]] = []
    total_skipped = 0
    done = 0

    for bi, batch in enumerate(batches, 1):
        log.info("singbox: batch %d/%d (%d keys)",
                 bi, len(batches), len(batch))
        try:
            res, skipped = _check_batch(batch, binary, cfg, on_progress,
                                        done, len(infos))
            all_results.extend(res)
            total_skipped += skipped
            done += len(batch)
            if skipped:
                log.info("singbox: batch %d skipped/dropped %d",
                         bi, skipped)
        except Exception:
            log.exception("singbox: batch %d failed", bi)

    if total_skipped:
        log.info("singbox: total skipped/dropped: %d", total_skipped)
    results = [CheckResult(info=info, ping=ping) for info, ping in all_results]
    results.sort(key=lambda r: r.ping)
    log.info("singbox: done — %d/%d alive", len(results), len(infos))
    return results
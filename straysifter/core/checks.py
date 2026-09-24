"""Проверки ключей — TCP для stream-схем.

vless/vmess/trojan/ss/socks/http/mtproto — TCP через asyncio.
DNS резолвится заранее (все A/AAAA-записи). Прокси не используется:
проверки идут напрямую.

Hysteria/hysteria2 не проверяются. Это UDP-протоколы, TCP-connect к ним
провалится; полноценная проверка через QUIC требует валидного Initial
с шифрованным ClientHello. Pipeline сохраняет такие ключи отдельным
файлом кандидатов для ручной проверки в клиенте.

Ретраи не применяются к RST-ответам: ConnectionRefusedError означает,
что порт закрыт, повтор бессмыслен. На практике на Windows + российский
ISP такие ответы редки (ISP блокирует через DROP), но для хостов без
блокировок это даёт экономию.
"""
from __future__ import annotations

import asyncio
import logging
import random
import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Callable, Iterable

from .config import ChecksConfig
from .parsers import ProxyInfo

log = logging.getLogger(__name__)

ProgressCb = Callable[[str, int, int, int], None]

TCP_SCHEMES = {"vless", "vmess", "trojan", "ss", "socks", "http", "mtproto"}
UDP_SCHEMES = {"hysteria", "hysteria2"}

# errno для Windows WSAECONNREFUSED — на случай, если asyncio не
# конвертирует его в ConnectionRefusedError.
_WSA_CONNREFUSED = 10061
_ECONNREFUSED = 111  # Linux


# ──────────────────────────────────────────────────────────────────────
#  DNS
# ──────────────────────────────────────────────────────────────────────

def _is_ip(s: str) -> bool:
    try:
        socket.inet_pton(socket.AF_INET, s)
        return True
    except OSError:
        pass
    try:
        socket.inet_pton(socket.AF_INET6, s)
        return True
    except OSError:
        return False


def _resolve_one(host: str) -> tuple[str, list[str]]:
    if _is_ip(host):
        return host, [host]
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except Exception:
        return host, []
    v4: list[str] = []
    v6: list[str] = []
    seen: set[str] = set()
    for family, _, _, _, sockaddr in infos:
        ip = sockaddr[0]
        if ip in seen:
            continue
        seen.add(ip)
        if family == socket.AF_INET:
            v4.append(ip)
        else:
            v6.append(ip)
    return host, v4 + v6


def resolve_hosts(
    hosts: list[str],
    workers: int = 128,
    on_progress: ProgressCb | None = None,
) -> dict[str, list[str]]:
    if not hosts:
        return {}

    total = len(hosts)
    ip_hosts: list[str] = []
    domains: list[str] = []
    for h in hosts:
        if _is_ip(h):
            ip_hosts.append(h)
        else:
            domains.append(h)

    out: dict[str, list[str]] = {h: [h] for h in ip_hosts}

    log.info(
        "check: DNS start — %d hosts (%d IP, %d domains, %d workers)",
        total, len(ip_hosts), len(domains), workers,
    )

    if not domains:
        log.info("check: DNS done — %d hosts (all IPs)", len(out))
        return out

    t0 = time.perf_counter()
    done = 0
    failed: list[str] = []
    d_total = len(domains)

    with ThreadPoolExecutor(max_workers=min(workers, d_total)) as ex:
        fmap = {ex.submit(_resolve_one, h): h for h in domains}
        for fut in as_completed(fmap):
            h, ips = fut.result()
            done += 1
            if ips:
                out[h] = ips
            else:
                failed.append(h)
            if on_progress and (done % 25 == 0 or done == d_total):
                on_progress("DNS", done, d_total, done - len(failed))

    dt = time.perf_counter() - t0
    n_ips = sum(len(v) for v in out.values())
    log.info(
        "check: DNS done — %d/%d hosts in %.1fs "
        "(%d IP, %d domains ok, %d failed, %d IPs total)",
        len(out), total, dt,
        len(ip_hosts), d_total - len(failed), len(failed), n_ips,
    )
    if failed:
        log.info("check: DNS failed for %d domains (примеры: %s)",
                 len(failed), ", ".join(failed[:5]))
    return out


# ──────────────────────────────────────────────────────────────────────
#  TCP
# ──────────────────────────────────────────────────────────────────────

def _classify_exception(e: BaseException) -> str:
    """Сводит разные исключения к одному из статусов.

    Windows может кидать OSError с errno 10061 вместо ConnectionRefusedError,
    поэтому проверяем и то и другое.
    """
    if isinstance(e, ConnectionRefusedError):
        return "refused"
    if isinstance(e, asyncio.TimeoutError):
        return "timeout"
    if isinstance(e, OSError):
        err = getattr(e, "errno", None)
        if err in (_WSA_CONNREFUSED, _ECONNREFUSED):
            return "refused"
        # WSAETIMEDOUT = 10060 (Windows), ETIMEDOUT = 110 (Linux)
        if err in (10060, 110):
            return "timeout"
        return "fail"
    return "fail"


async def _try_one_ip(ip: str, port: int, timeout: float) -> tuple[str, int | None]:
    """Возвращает (status, ping_ms). status ∈ {"ok","refused","timeout","fail"}."""
    try:
        t0 = time.perf_counter()
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        ping = int((time.perf_counter() - t0) * 1000)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return ("ok", ping)
    except asyncio.CancelledError:
        raise
    except BaseException as e:
        return (_classify_exception(e), None)


async def _try_ips_parallel(
    ips: list[str], port: int, timeout: float,
) -> tuple[int | None, bool]:
    """Пробует все IP параллельно.

    Возвращает (ping_or_None, all_refused):
        ping — если хоть один IP ответил;
        all_refused=True — все IP ответили RST, endpoint мёртв, ретрай не нужен.
    """
    if not ips:
        return (None, True)
    tasks = [asyncio.create_task(_try_one_ip(ip, port, timeout)) for ip in ips]
    refused = 0
    try:
        pending: set[asyncio.Task] = set(tasks)
        while pending:
            done, pending = await asyncio.wait(
                pending, return_when=asyncio.FIRST_COMPLETED,
            )
            for t in done:
                try:
                    status, ping = t.result()
                except Exception:
                    status, ping = "fail", None
                if status == "ok":
                    for x in pending:
                        x.cancel()
                    return (ping, False)
                if status == "refused":
                    refused += 1
        return (None, refused == len(ips))
    finally:
        for t in tasks:
            if not t.done():
                t.cancel()


async def _try_ips_sequential(
    ips: list[str], port: int, timeout: float,
) -> tuple[int | None, bool]:
    if not ips:
        return (None, True)
    refused = 0
    for ip in ips:
        status, ping = await _try_one_ip(ip, port, timeout)
        if status == "ok":
            return (ping, False)
        if status == "refused":
            refused += 1
    return (None, refused == len(ips))


async def _tcp_batch_async(
    tasks: list[tuple[str, int, list[str]]],
    cfg: ChecksConfig,
    on_progress: ProgressCb | None,
) -> tuple[dict[tuple[str, int], int], dict[str, int]]:
    sem = asyncio.Semaphore(cfg.tcp_workers)
    result: dict[tuple[str, int], int] = {}
    total = len(tasks)
    done = 0
    lock = asyncio.Lock()
    counters = {
        "budget_hits": 0,
        "ok": 0,
        "refused": 0,
        "timeout": 0,
        "fail": 0,
        "all_refused_early": 0,   # endpoint'ы, которые вышли после RST без ретраев
    }

    async def one(host: str, port: int, ips: list[str]) -> None:
        nonlocal done
        async with sem:
            # Классификация финального статуса: ok / refused / timeout / fail.
            status_holder = {"final": "unknown"}

            async def _inner_with_status() -> int | None:
                n_ips = len(ips)
                use_seq_allowed = n_ips <= cfg.tcp_sequential_max_ips

                for attempt in range(1, cfg.tcp_attempts + 1):
                    if attempt > 1:
                        await asyncio.sleep(random.uniform(0, cfg.tcp_retry_jitter))

                    t = min(
                        cfg.tcp_timeout + (attempt - 1) * cfg.tcp_timeout_step,
                        cfg.tcp_timeout_max,
                    )
                    use_seq = use_seq_allowed and attempt >= cfg.tcp_sequential_after

                    if use_seq:
                        ping, all_refused = await _try_ips_sequential(ips, port, t)
                    else:
                        ping, all_refused = await _try_ips_parallel(ips, port, t)

                    if ping is not None:
                        status_holder["final"] = "ok"
                        return ping
                    if all_refused:
                        status_holder["final"] = "refused"
                        if attempt == 1:
                            counters["all_refused_early"] += 1
                        return None
                status_holder["final"] = "timeout"
                return None

            if cfg.tcp_endpoint_budget <= 0:
                ping = await _inner_with_status()
            else:
                try:
                    ping = await asyncio.wait_for(
                        _inner_with_status(),
                        timeout=cfg.tcp_endpoint_budget,
                    )
                except asyncio.TimeoutError:
                    counters["budget_hits"] += 1
                    if counters["budget_hits"] <= 10:
                        log.info("check: endpoint budget hit: %s:%d (%d IPs)",
                                 host, port, len(ips))
                    ping = None
                    status_holder["final"] = "timeout"

            async with lock:
                done += 1
                if ping is not None:
                    result[(host, port)] = ping
                    counters["ok"] += 1
                else:
                    st = status_holder["final"]
                    if st in counters:
                        counters[st] += 1
                    else:
                        counters["fail"] += 1
                if on_progress and (done % 50 == 0 or done == total):
                    on_progress("TCP", done, total, len(result))

    await asyncio.gather(*(one(h, p, ips) for h, p, ips in tasks))
    return result, counters


def _tcp_batch(
    endpoints: list[tuple[str, int]],
    cfg: ChecksConfig,
    on_progress: ProgressCb | None,
    host_to_ips: dict[str, list[str]],
) -> dict[tuple[str, int], int]:
    tasks: list[tuple[str, int, list[str]]] = []
    for h, p in endpoints:
        ips = host_to_ips.get(h, [])
        if not ips:
            continue
        tasks.append((h, p, ips))

    if not tasks:
        return {}

    log.info(
        "check: TCP start — %d endpoints | timeout %.1f→%.1f | attempts=%d "
        "| budget=%.0fs | workers=%d",
        len(endpoints), cfg.tcp_timeout, cfg.tcp_timeout_max,
        cfg.tcp_attempts, cfg.tcp_endpoint_budget, cfg.tcp_workers,
    )

    result, counters = asyncio.run(_tcp_batch_async(tasks, cfg, on_progress))

    log.info("check: TCP done — %d/%d alive, %d budget-cut",
             len(result), len(endpoints), counters["budget_hits"])
    log.info(
        "check: statuses — ok=%d refused=%d timeout=%d fail=%d "
        "(early-exit on refused: %d)",
        counters["ok"], counters["refused"], counters["timeout"],
        counters["fail"], counters["all_refused_early"],
    )
    return result


# ──────────────────────────────────────────────────────────────────────
#  TLS (опция)
# ──────────────────────────────────────────────────────────────────────

def _tls_handshake(host: str, port: int, server_name: str | None,
                   timeout: float) -> int | None:
    if not host or not port:
        return None
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        t0 = time.perf_counter()
        with socket.create_connection((host, int(port)), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=server_name or host) as s:
                s.do_handshake()
                return int((time.perf_counter() - t0) * 1000)
    except Exception:
        return None


def _tls_batch(
    targets: list[tuple[str, int, str]],
    timeout: float,
    workers: int,
    on_progress: ProgressCb | None,
) -> set[tuple[str, int, str]]:
    if not targets:
        return set()

    ok: set[tuple[str, int, str]] = set()
    total = len(targets)
    done = 0
    log.info("check: TLS start — %d targets", total)
    with ThreadPoolExecutor(max_workers=workers) as ex:
        fmap = {
            ex.submit(_tls_handshake, h, p, sni, timeout): (h, p, sni)
            for h, p, sni in targets
        }
        for fut in as_completed(fmap):
            done += 1
            if fut.result() is not None:
                ok.add(fmap[fut])
            if on_progress and (done % 25 == 0 or done == total):
                on_progress("TLS", done, total, len(ok))
    log.info("check: TLS done — %d/%d", len(ok), total)
    return ok


# ──────────────────────────────────────────────────────────────────────
#  Публичный вход
# ──────────────────────────────────────────────────────────────────────

@dataclass
class CheckResult:
    info: ProxyInfo
    ping: int

    @property
    def key(self) -> str:
        return self.info.raw


def run_check(
    infos: Iterable[ProxyInfo],
    cfg: ChecksConfig,
    on_progress: ProgressCb | None = None,
) -> list[CheckResult]:
    infos = [i for i in infos if i.scheme in TCP_SCHEMES]
    if not infos:
        return []

    mode = (cfg.mode or "tcp").lower()
    do_tls = mode == "tcp+tls"

    endpoints = sorted({i.endpoint for i in infos})
    hosts = sorted({h for h, _ in endpoints})

    log.info("check: %d tcp keys, %d endpoints, %d unique hosts",
             len(infos), len(endpoints), len(hosts))

    host_to_ips = resolve_hosts(hosts, on_progress=on_progress)

    ping_by_ep = _tcp_batch(endpoints, cfg, on_progress, host_to_ips)
    after_tcp = [i for i in infos if i.endpoint in ping_by_ep]

    if not do_tls:
        results = [CheckResult(info=i, ping=ping_by_ep[i.endpoint])
                   for i in after_tcp]
        results.sort(key=lambda r: r.ping)
        return results

    need_tls = [i for i in after_tcp
                if i.security in ("tls", "reality", "xtls")]
    passthrough = [i for i in after_tcp
                   if i.security not in ("tls", "reality", "xtls")]
    tls_targets = sorted({(i.host, i.port, i.sni) for i in need_tls})
    tls_ok = _tls_batch(
        tls_targets, cfg.tls_timeout, cfg.tls_workers, on_progress,
    )
    after_tls = passthrough + [
        i for i in need_tls if (i.host, i.port, i.sni) in tls_ok
    ]

    results = [CheckResult(info=i, ping=ping_by_ep[i.endpoint])
               for i in after_tls]
    results.sort(key=lambda r: r.ping)
    return results


run_tcp_check = run_check
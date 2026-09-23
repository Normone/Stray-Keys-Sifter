"""Проверки ключей — TCP (+ опционально TLS).

Ключевое:
    * DNS через getaddrinfo — ВСЕ A/AAAA-записи, а не только первая.
    * Прогрессивный таймаут 3→6→9с: медленные сервера доживают до 3-й попытки.
    * Sequential для хостов с <= N IP, иначе parallel — не съедаем бюджет.
    * Жёсткий бюджет на endpoint (по умолчанию 30с), с логом обрезанных.
    * Никаких прокси — TCP всегда напрямую.
"""
from __future__ import annotations

import asyncio
import logging
import random
import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Callable, Iterable

from .config import ChecksConfig
from .parsers import ProxyInfo

log = logging.getLogger(__name__)

ProgressCb = Callable[[str, int, int, int], None]


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

async def _try_one_ip(ip: str, port: int, timeout: float) -> int | None:
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
        return ping
    except Exception:
        return None


async def _try_ips_parallel(ips: list[str], port: int, timeout: float) -> int | None:
    if not ips:
        return None
    tasks = [asyncio.create_task(_try_one_ip(ip, port, timeout)) for ip in ips]
    try:
        pending: set[asyncio.Task] = set(tasks)
        while pending:
            done, pending = await asyncio.wait(
                pending, return_when=asyncio.FIRST_COMPLETED,
            )
            for t in done:
                try:
                    r = t.result()
                except Exception:
                    continue
                if r is not None:
                    return r
        return None
    finally:
        for t in tasks:
            if not t.done():
                t.cancel()


async def _try_ips_sequential(ips: list[str], port: int, timeout: float) -> int | None:
    for ip in ips:
        r = await _try_one_ip(ip, port, timeout)
        if r is not None:
            return r
    return None


async def _try_endpoint_inner(
    ips: list[str],
    port: int,
    cfg: ChecksConfig,
) -> int | None:
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
            r = await _try_ips_sequential(ips, port, t)
        else:
            r = await _try_ips_parallel(ips, port, t)

        if r is not None:
            return r
    return None


async def _try_endpoint(
    host: str,
    ips: list[str],
    port: int,
    cfg: ChecksConfig,
    counters: dict,
) -> int | None:
    if cfg.tcp_endpoint_budget <= 0:
        return await _try_endpoint_inner(ips, port, cfg)
    try:
        return await asyncio.wait_for(
            _try_endpoint_inner(ips, port, cfg),
            timeout=cfg.tcp_endpoint_budget,
        )
    except asyncio.TimeoutError:
        counters["budget_hits"] += 1
        if counters["budget_hits"] <= 10:
            log.info("check: endpoint budget hit: %s:%d (%d IPs)",
                     host, port, len(ips))
        return None


async def _tcp_batch_async(
    tasks: list[tuple[str, int, list[str]]],
    cfg: ChecksConfig,
    on_progress: ProgressCb | None,
) -> dict[tuple[str, int], int]:
    sem = asyncio.Semaphore(cfg.tcp_workers)
    result: dict[tuple[str, int], int] = {}
    total = len(tasks)
    done = 0
    lock = asyncio.Lock()
    counters = {"budget_hits": 0}

    async def one(host: str, port: int, ips: list[str]) -> None:
        nonlocal done
        async with sem:
            ping = await _try_endpoint(host, ips, port, cfg, counters)
            async with lock:
                done += 1
                if ping is not None:
                    result[(host, port)] = ping
                if on_progress and (done % 50 == 0 or done == total):
                    on_progress("TCP", done, total, len(result))

    await asyncio.gather(*(one(h, p, ips) for h, p, ips in tasks))

    result["__budget_hits__"] = counters["budget_hits"]  # type: ignore[assignment]
    return result


def tcp_batch(
    endpoints: list[tuple[str, int]],
    cfg: ChecksConfig,
    on_progress: ProgressCb | None,
    host_to_ips: dict[str, list[str]] | None = None,
) -> dict[tuple[str, int], int]:
    if not endpoints:
        return {}

    hosts = sorted({h for h, _ in endpoints})
    if host_to_ips is None:
        host_to_ips = resolve_hosts(hosts, on_progress=on_progress)

    tasks: list[tuple[str, int, list[str]]] = []
    for h, p in endpoints:
        ips = host_to_ips.get(h, [])
        if not ips:
            continue
        tasks.append((h, p, ips))

    if not tasks:
        log.warning("tcp_batch: ни один хост не резолвится")
        return {}

    log.info(
        "check: TCP start — %d endpoints | timeout %.1f→%.1f | attempts=%d "
        "| budget=%.0fs | workers=%d",
        len(endpoints), cfg.tcp_timeout, cfg.tcp_timeout_max,
        cfg.tcp_attempts, cfg.tcp_endpoint_budget, cfg.tcp_workers,
    )

    raw = asyncio.run(_tcp_batch_async(tasks, cfg, on_progress))

    budget_hits = int(raw.pop("__budget_hits__", 0))  # type: ignore[arg-type]
    result = raw  # type: ignore[assignment]

    log.info("check: TCP done — %d/%d alive, %d budget-cut",
             len(result), len(endpoints), budget_hits)
    if budget_hits:
        log.info(
            "check: %d endpoints не уложились в %.0fs budget "
            "(если их много — подними tcp_endpoint_budget в config.json)",
            budget_hits, cfg.tcp_endpoint_budget,
        )
    return result  # type: ignore[return-value]


# ──────────────────────────────────────────────────────────────────────
#  TLS
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
    infos = list(infos)
    if not infos:
        return []

    mode = (cfg.mode or "tcp").lower()
    do_tls = mode == "tcp+tls"

    endpoints = sorted({i.endpoint for i in infos})
    hosts = sorted({h for h, _ in endpoints})

    log.info("check: %d keys, %d endpoints, %d unique hosts",
             len(infos), len(endpoints), len(hosts))

    host_to_ips = resolve_hosts(hosts, on_progress=on_progress)

    ping_by_ep = tcp_batch(
        endpoints, cfg, on_progress, host_to_ips=host_to_ips,
    )
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
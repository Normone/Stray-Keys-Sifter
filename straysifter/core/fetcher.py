"""Загрузчик источников.

⚑ ЕДИНСТВЕННОЕ место в проекте, где упоминается прокси. ⚑
Прокси нужен, чтобы достучаться до GitHub/gitverse, когда их блокируют.
Проверки ключей идут ВСЕГДА напрямую (см. core.checks).

Стратегия (cfg.prefer):
    direct      — сначала напрямую, при неудаче через прокси
    proxy       — сначала через прокси, при неудаче напрямую
    direct-only — только напрямую
    proxy-only  — только через прокси (если задан)

Каждая попытка повторяется 2 раза (RETRY_DELAYS) на своём транспорте.
trust_env=False — игнорируем HTTP_PROXY/HTTPS_PROXY из окружения,
чтобы случайный export не утащил fetch непонятно куда.
"""
from __future__ import annotations

import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Iterable

import requests

from .config import FetcherConfig

log = logging.getLogger(__name__)

RETRY_DELAYS = (0.0, 1.0)
"""Пауза перед попытками. Первая попытка сразу, вторая через 1с."""


def _make_session(ua: str, proxy: str | None) -> requests.Session:
    s = requests.Session()
    s.trust_env = False
    s.headers["User-Agent"] = ua
    if proxy:
        s.proxies.update({"http": proxy, "https": proxy})
    return s


class SourceFetcher:
    def __init__(self, cfg: FetcherConfig):
        self.cfg = cfg
        self._direct = _make_session(cfg.ua, None)
        self._proxied = _make_session(cfg.ua, cfg.proxy) if cfg.proxy else None

    # ── порядок попыток ─────────────────────────────────────────────

    def _attempts(self) -> list[tuple[str, requests.Session]]:
        prefer = (self.cfg.prefer or "direct").lower()
        has_proxy = self._proxied is not None

        if prefer == "proxy-only":
            if not has_proxy:
                log.warning("fetch: prefer=proxy-only, но proxy не задан — пропускаю")
                return []
            return [("proxy", self._proxied)]

        if prefer == "direct-only":
            return [("direct", self._direct)]

        if prefer == "proxy":
            return ([("proxy", self._proxied)] if has_proxy else []) + \
                   [("direct", self._direct)]

        # "direct" — дефолт
        return [("direct", self._direct)] + \
               ([("proxy", self._proxied)] if has_proxy else [])

    # ── сам fetch ────────────────────────────────────────────────────

    def text(self, url: str) -> str | None:
        attempts = self._attempts()
        if not attempts:
            return None

        for transport, session in attempts:
            for delay in RETRY_DELAYS:
                if delay > 0:
                    time.sleep(delay)
                try:
                    r = session.get(url, timeout=self.cfg.timeout)
                    r.raise_for_status()
                    if transport == "proxy":
                        log.debug("fetch via proxy: %s", url)
                    return r.text
                except Exception as e:
                    last_err = e

            log.debug("fetch: %s transport failed for %s (%s)",
                      transport, url, last_err)

        log.warning("fetch %s -> %s (tried: %s)",
                    url, last_err,
                    ",".join(t for t, _ in attempts))
        return None

    def many(self, urls: Iterable[str]) -> dict[str, str | None]:
        urls = list(urls)
        out: dict[str, str | None] = {}
        if not urls:
            return out
        workers = max(1, min(self.cfg.workers, len(urls)))
        with ThreadPoolExecutor(max_workers=workers) as ex:
            fmap = {ex.submit(self.text, u): u for u in urls}
            for fut in as_completed(fmap):
                url = fmap[fut]
                txt = fut.result()
                out[url] = txt
                name = url.rsplit("/", 1)[-1][:40] or url
                log.info("  %s %s (%s)",
                         "✓" if txt else "✗", name,
                         f"{len(txt)} chars" if txt else "unreachable")
        return out
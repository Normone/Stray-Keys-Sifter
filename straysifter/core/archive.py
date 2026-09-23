"""Архив сырых ответов источников.

Зачем:
    • Источники (GitHub, gitverse) иногда блокируют или перезаписывают файлы.
    • Прокси может отвалиться — а проверки должны продолжаться.
    • Хочется уметь воспроизвести старый прогон.

Как работает:
    Каждый успешный fetch → снапшот в data/raw/YYYY-MM-DD/<ts>__<hash>__<name>.
    Если fetch не удался — берём последний снапшот для этого URL.

Ретеншен: старые папки <YYYY-MM-DD> удаляются при старте цикла
(по умолчанию хранится 7 дней).
"""
from __future__ import annotations

import hashlib
import logging
import shutil
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Literal

from .fetcher import SourceFetcher

log = logging.getLogger(__name__)

Provenance = Literal["live", "cached", "unavailable"]


@dataclass
class FetchedText:
    url: str
    text: str | None
    provenance: Provenance

    @property
    def ok(self) -> bool:
        return self.text is not None


def _url_hash(url: str) -> str:
    return hashlib.sha1(url.encode("utf-8")).hexdigest()[:10]


def _short_name(url: str) -> str:
    tail = url.rsplit("/", 1)[-1] or "index"
    tail = tail.split("?", 1)[0]
    return "".join(c if c.isalnum() or c in "-_." else "_" for c in tail)[:60]


class SourceArchive:
    def __init__(self, root: Path | str):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    # ── запись ───────────────────────────────────────────────────────
    def snapshot(self, url: str, text: str) -> Path:
        ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        day = ts[:10]
        name = f"{ts}__{_url_hash(url)}__{_short_name(url)}"
        p = self.root / day / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
        log.debug("archive: saved %s (%d chars)", p, len(text))
        return p

    # ── чтение ───────────────────────────────────────────────────────
    def latest(self, url: str) -> Path | None:
        h = _url_hash(url)
        pattern = f"*__{h}__*"
        for day in sorted(self.root.glob("*/"), reverse=True):
            matches = sorted(day.glob(pattern), reverse=True)
            if matches:
                return matches[0]
        return None

    def latest_text(self, url: str) -> str | None:
        p = self.latest(url)
        if p is None:
            return None
        try:
            return p.read_text(encoding="utf-8")
        except Exception as e:
            log.warning("archive: cannot read %s: %s", p, e)
            return None

    # ── сервис ───────────────────────────────────────────────────────
    def fetch_with_fallback(
        self, url: str, fetcher: SourceFetcher,
    ) -> FetchedText:
        text = fetcher.text(url)
        if text:
            self.snapshot(url, text)
            return FetchedText(url=url, text=text, provenance="live")

        cached = self.latest_text(url)
        if cached is not None:
            log.info("archive: fallback to cached for %s", url)
            return FetchedText(url=url, text=cached, provenance="cached")

        log.warning("archive: nothing available for %s", url)
        return FetchedText(url=url, text=None, provenance="unavailable")

    def fetch_many(
        self, urls: list[str], fetcher: SourceFetcher,
    ) -> list[FetchedText]:
        from concurrent.futures import ThreadPoolExecutor, as_completed

        out: list[FetchedText] = []
        workers = max(1, min(fetcher.cfg.workers, max(len(urls), 1)))
        with ThreadPoolExecutor(max_workers=workers) as ex:
            fmap = {ex.submit(self.fetch_with_fallback, u, fetcher): u
                    for u in urls}
            for fut in as_completed(fmap):
                res = fut.result()
                mark = {"live": "✓", "cached": "◌", "unavailable": "✗"}[res.provenance]
                log.info("  %s %s [%s]", mark,
                         res.url.rsplit("/", 1)[-1][:40], res.provenance)
                out.append(res)
        return out

    # ── ретеншен ─────────────────────────────────────────────────────
    def cleanup(self, keep_days: int = 7) -> int:
        """Удаляет папки <YYYY-MM-DD>, старше keep_days. Возвращает число удалённых."""
        cutoff = datetime.now() - timedelta(days=keep_days)
        removed = 0
        for day_dir in self.root.iterdir():
            if not day_dir.is_dir():
                continue
            try:
                day = datetime.strptime(day_dir.name, "%Y-%m-%d")
            except ValueError:
                continue
            if day < cutoff:
                try:
                    shutil.rmtree(day_dir)
                    removed += 1
                    log.info("archive: removed old day %s", day_dir.name)
                except Exception as e:
                    log.warning("archive: cannot remove %s: %s", day_dir, e)
        return removed
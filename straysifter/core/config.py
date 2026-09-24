"""Единый конфиг. Приоритет: env > config.json > defaults."""
from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field, asdict
from pathlib import Path

from .paths import find_home

log = logging.getLogger(__name__)


@dataclass
class FetcherConfig:
    """Прокси используется ТОЛЬКО для загрузки источников.

    prefer управляет порядком попыток:
        "direct"      — сначала напрямую, потом через прокси (дефолт)
        "proxy"       — сначала через прокси, потом напрямую
        "direct-only" — только напрямую, прокси игнорируется
        "proxy-only"  — только через прокси, напрямую не пробуем
    """
    proxy: str | None = None
    prefer: str = "direct"
    timeout: int = 25
    workers: int = 5
    ua: str = "Mozilla/5.0 (straysifter/2.0)"


@dataclass
class ChecksConfig:
    # "tcp"     — только TCP (дефолт: ничего живого не режет)
    # "tcp+tls" — TCP + TLS (чище список, но теряет 5-15% живых)
    mode: str = "tcp"

    # ── Таймауты ────────────────────────────────────────────────────
    # 3 попытки 3→6→9с, мёртвый endpoint ждёт ~18.4с.
    # Укорачивать не стоит: 2.5/5/7.5 даёт −20% живых, потому что
    # публичные сервера часто отвечают на второй-третий секунде.
    tcp_timeout: float = 3.0
    tcp_timeout_step: float = 3.0
    tcp_timeout_max: float = 9.0

    # ── Параллелизм ─────────────────────────────────────────────────
    # 120 — проверенный дефолт. Эксперименты с 180/250 не ускоряют
    # прогон без потери живых: узкое место в самом TCP-handshake,
    # а не в числе воркеров.
    tcp_workers: int = 120

    # ── Повторы ─────────────────────────────────────────────────────
    tcp_attempts: int = 3

    # ⚠ КРИТИЧНО: 0.4, не меньше 0.3.
    # Это не «пауза для красоты». Если первый SYN потерялся на
    # маршрутизаторе/в NAT — повтор через 0.2с уйдёт по тому же
    # забитому пути. 0.4с даёт стеку время разгрузиться, и второй SYN
    # проходит. jitter=0.2 режет ~20-25% живых (проверено A/B).
    tcp_retry_jitter: float = 0.4

    # ⚠ КРИТИЧНО: 3, не 2.
    # Для хостов с 3 IP sequential-обход (IP1 → IP2 → IP3) важнее,
    # чем для хостов с 2. Параллельный обход берёт только первый
    # ответивший и теряет остальные.
    tcp_sequential_max_ips: int = 3
    tcp_sequential_after: int = 2

    # Бюджет на endpoint. 30с покрывает 3 попытки с запасом.
    tcp_endpoint_budget: float = 30.0

    # ── TLS ─────────────────────────────────────────────────────────
    tls_timeout: float = 4.0
    tls_workers: int = 30

    # ISO-коды стран, которые НЕ попадают в экспорт.
    # Пусто — экспортируем все. Пример: ["RU", "CN"].
    exclude_countries: list[str] = field(default_factory=list)


@dataclass
class GeoIPConfig:
    """Определение страны сервера по IP, а не по remark.

    enabled=True по дефолту. Работает в трёх режимах:
        1. Кэш (data/geoip_cache.json) — если IP уже видели.
        2. mmdb (оффлайн) — если установлен maxminddb и есть .mmdb файл.
        3. HTTP (ip-api.com/batch) — если ни кэша, ни mmdb нет.
    Для быстрого старта достаточно HTTP-fallback, ничего докачивать не надо.

    detect_cdn — если IP принадлежит CDN (Cloudflare, Fastly и др.),
                 страна НЕ ставится, parse_country откатывается на remark.
    """
    enabled: bool = True
    proxy: str | None = None
    http_fallback: bool = True
    db_path: str = ""
    detect_cdn: bool = True


@dataclass
class ScheduleConfig:
    fetch_hours: float = 6.0
    check_minutes: float = 360.0


@dataclass
class StorageConfig:
    dir: str = "data"

    @property
    def base(self) -> Path:
        return Path(self.dir)


@dataclass
class Config:
    fetcher: FetcherConfig = field(default_factory=FetcherConfig)
    checks: ChecksConfig = field(default_factory=ChecksConfig)
    geoip: GeoIPConfig = field(default_factory=GeoIPConfig)

    # Плоский список URL источников. Без деления по протоколам —
    # парсер сам разбирается, что в тексте.
    sources: list[str] = field(
        default_factory=lambda: ["https://example.com/sub.txt"]
    )

    schedule: ScheduleConfig = field(default_factory=ScheduleConfig)
    storage: StorageConfig = field(default_factory=StorageConfig)

    def to_dict(self) -> dict:
        return asdict(self)

    def save(self, path: Path) -> None:
        path.write_text(
            json.dumps(self.to_dict(), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )


def default_config_path() -> Path:
    return find_home() / "config.json"


def ensure_home() -> Path:
    home = find_home()
    cfg_path = home / "config.json"
    if not cfg_path.exists():
        Config().save(cfg_path)
    return home


def _merge(dc, data: dict) -> None:
    for k, v in (data or {}).items():
        if not hasattr(dc, k):
            continue
        cur = getattr(dc, k)
        if hasattr(cur, "__dataclass_fields__") and isinstance(v, dict):
            _merge(cur, v)
        else:
            try:
                setattr(dc, k, v)
            except Exception:
                pass


def _apply_env(cfg: Config) -> None:
    if v := os.environ.get("SIFTER_PROXY"):
        cfg.fetcher.proxy = v
    if v := os.environ.get("SIFTER_FETCH_PREFER"):
        cfg.fetcher.prefer = v.lower()
    if v := os.environ.get("SIFTER_DATA"):
        cfg.storage.dir = v
    if v := os.environ.get("SIFTER_MODE"):
        cfg.checks.mode = v.lower()
    if v := os.environ.get("SIFTER_EXCLUDE_COUNTRIES"):
        cfg.checks.exclude_countries = [
            c.strip().upper() for c in v.split(",") if c.strip()
        ]
    if v := os.environ.get("SIFTER_GEOIP"):
        cfg.geoip.enabled = v.strip().lower() in ("1", "true", "yes", "on")
    if v := os.environ.get("SIFTER_GEOIP_PROXY"):
        cfg.geoip.proxy = v
    if v := os.environ.get("SIFTER_GEOIP_DETECT_CDN"):
        cfg.geoip.detect_cdn = \
            v.strip().lower() in ("1", "true", "yes", "on")
    if v := os.environ.get("SIFTER_SOURCES"):
        cfg.sources = [u.strip() for u in v.split(",") if u.strip()]


def load_config(path: Path | None = None) -> Config:
    cfg = Config()
    p = path or default_config_path()
    if p.exists():
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            _merge(cfg, data)
        except Exception as e:
            log.warning("config: %s", e)
    _apply_env(cfg)
    return cfg
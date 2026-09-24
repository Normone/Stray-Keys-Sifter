"""fetch → parse → TCP/TLS → GeoIP → save, со статистикой источников."""
from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable

from .archive import SourceArchive, FetchedText
from .checks import CheckResult, ProgressCb, UDP_SCHEMES, run_check
from .config import Config
from .fetcher import SourceFetcher
from .parsers import ProxyInfo, TextStats, analyze_text, dedup_vless
from .storage import SourceStats, Storage

log = logging.getLogger(__name__)

ARCHIVE_KEEP_DAYS = 7
CDN_MARKER = "__CDN__"


@dataclass
class RunResult:
    fetched: list[FetchedText]
    all_infos: list[ProxyInfo]
    checked: list[CheckResult]
    hysteria_candidates: list[ProxyInfo]
    source_infos: dict[str, list[ProxyInfo]]
    text_stats: dict[str, TextStats]
    started_at: datetime
    finished_at: datetime

    @property
    def duration_s(self) -> float:
        return (self.finished_at - self.started_at).total_seconds()

    @property
    def live_sources(self) -> int:
        return sum(1 for f in self.fetched if f.provenance == "live")

    @property
    def cached_sources(self) -> int:
        return sum(1 for f in self.fetched if f.provenance == "cached")

    @property
    def unavailable_sources(self) -> int:
        return sum(1 for f in self.fetched if f.provenance == "unavailable")

    @property
    def by_scheme(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for p in self.all_infos:
            out[p.scheme] = out.get(p.scheme, 0) + 1
        return out

    @property
    def alive_by_scheme(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for r in self.checked:
            out[r.info.scheme] = out.get(r.info.scheme, 0) + 1
        return out


def _hash_text(text: str) -> str:
    return hashlib.sha1(text.encode("utf-8", errors="replace")).hexdigest()[:16]


def _fmt_schemes(by_scheme: dict[str, int]) -> str:
    if not by_scheme:
        return "(empty)"
    items = sorted(by_scheme.items(), key=lambda kv: -kv[1])
    return "  ".join(f"{k}={v}" for k, v in items)


def apply_geoip(
    infos: list[ProxyInfo],
    cfg: Config,
    base_dir: Path,
) -> None:
    if not cfg.geoip.enabled:
        return
    from .geoip import GeoIPResolver

    resolver = GeoIPResolver(cfg.geoip, base_dir)
    hosts = [i.host for i in infos if i.host]
    if not hosts:
        return
    unique = len(set(hosts))
    log.info("geoip: resolving %d unique hosts (cache=%d)",
             unique, resolver.cache_size())
    cc_map = resolver.resolve_countries(hosts)

    hit = 0
    cdn = 0
    for i in infos:
        cc = cc_map.get(i.host, "")
        if cc == CDN_MARKER:
            cdn += 1
            continue
        if cc:
            i.params["__cc"] = cc
            hit += 1
    log.info(
        "geoip: %d/%d keys got country, %d CDN-skipped, hosts resolved=%d/%d",
        hit, len(infos), cdn, len(cc_map), unique,
    )


def gather_infos(
    fetcher: SourceFetcher,
    archive: SourceArchive,
    urls: list[str] | None = None,
    on_source: Callable[[FetchedText], None] | None = None,
) -> tuple[list[FetchedText], list[ProxyInfo],
           dict[str, list[ProxyInfo]], dict[str, TextStats]]:
    urls = urls or []
    if not urls:
        log.warning("gather_infos: список источников пуст")
        return [], [], {}, {}

    fetched = archive.fetch_many(urls, fetcher)

    if on_source:
        for f in fetched:
            on_source(f)

    source_infos: dict[str, list[ProxyInfo]] = {}
    text_stats: dict[str, TextStats] = {}

    for f in fetched:
        if not f.text:
            source_infos[f.url] = []
            text_stats[f.url] = TextStats()
            continue
        name = f.url.rsplit("/", 1)[-1][:70] or f.url
        st, local = analyze_text(f.text)
        source_infos[f.url] = local
        text_stats[f.url] = st

        log.info(
            "  %s\n"
            "      found=%d   parsed=%d   uniq=%d\n"
            "      %s",
            name,
            st.raw_uris, st.parsed_ok, st.unique,
            _fmt_schemes(st.by_scheme),
        )

    flat = [i for lst in source_infos.values() for i in lst]
    unique = dedup_vless(flat)

    log.info(
        "pipeline: live=%d cached=%d unavailable=%d; parsed=%d unique=%d",
        sum(1 for f in fetched if f.provenance == "live"),
        sum(1 for f in fetched if f.provenance == "cached"),
        sum(1 for f in fetched if f.provenance == "unavailable"),
        len(flat), len(unique),
    )
    return fetched, unique, source_infos, text_stats


def _compute_source_stats(
    fetched: list[FetchedText],
    source_infos: dict[str, list[ProxyInfo]],
    text_stats: dict[str, TextStats],
    alive_keys: set[str],
) -> list[SourceStats]:
    key_sources: dict[str, set[str]] = {}
    for url, infos in source_infos.items():
        for i in infos:
            key_sources.setdefault(i.dedup_key, set()).add(url)

    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    stats: list[SourceStats] = []

    for f in fetched:
        local = source_infos.get(f.url, [])
        ts = text_stats.get(f.url) or TextStats()
        text = f.text or ""
        h = _hash_text(text) if text else ""

        alive_local = sum(1 for i in local if i.dedup_key in alive_keys)
        unique_only = sum(1 for i in local
                          if len(key_sources.get(i.dedup_key, set())) == 1)
        overlap = len(local) - unique_only
        ratio = round(alive_local / len(local), 4) if local else 0.0

        unique_alive = sum(
            1 for i in local
            if i.dedup_key in alive_keys
            and len(key_sources.get(i.dedup_key, set())) == 1
        )

        stats.append(SourceStats(
            url=f.url,
            last_fetch_ok=now if f.provenance == "live" else "",
            last_change=now,
            last_hash=h,
            kind=ts.kind,
            total_lines=ts.total_lines,
            raw_uris=ts.raw_uris,
            supported=ts.supported,
            unsupported=ts.unsupported,
            parsed_ok=ts.parsed_ok,
            parse_fail=ts.parse_fail,
            unique_local=len(local),
            unique_only_here=unique_only,
            overlap_with_others=overlap,
            alive=alive_local,
            alive_ratio=ratio,
            unique_alive=unique_alive,
            by_scheme=dict(ts.by_scheme),
            unsupported_schemes=dict(ts.unsupported_schemes),
        ))
    return stats


def run_cycle(
    cfg: Config,
    *,
    urls: list[str] | None = None,
    mode: str | None = None,
    on_source: Callable[[FetchedText], None] | None = None,
    on_progress: ProgressCb | None = None,
) -> RunResult:
    if mode:
        cfg.checks.mode = mode.lower()

    source_urls = urls if urls is not None else cfg.sources

    started = datetime.now()
    log.info("pipeline: cycle start (mode=%s, proxy=%s, geoip=%s%s, sources=%d)",
             cfg.checks.mode, cfg.fetcher.proxy or "none",
             "on" if cfg.geoip.enabled else "off",
             ", cdn=on" if (cfg.geoip.enabled and cfg.geoip.detect_cdn)
             else "",
             len(source_urls))

    if not source_urls:
        log.warning("нет источников: заполни config.json → sources")

    fetcher = SourceFetcher(cfg.fetcher)
    archive = SourceArchive(cfg.storage.base / "raw")
    storage = Storage(cfg.storage.base)

    removed = archive.cleanup(keep_days=ARCHIVE_KEEP_DAYS)
    if removed:
        log.info("pipeline: removed %d old day(s) from archive", removed)

    fetched, unique, source_infos, text_stats = gather_infos(
        fetcher, archive, urls=source_urls, on_source=on_source,
    )

    checked = run_check(unique, cfg.checks, on_progress=on_progress)

    hysteria_candidates = [i for i in unique if i.scheme in UDP_SCHEMES]
    if hysteria_candidates:
        log.info("pipeline: hysteria candidates=%d (см. hysteria2_candidates.txt)",
                 len(hysteria_candidates))

    apply_geoip([r.info for r in checked], cfg, cfg.storage.base)

    finished = datetime.now()
    result = RunResult(
        fetched=fetched,
        all_infos=unique,
        checked=checked,
        hysteria_candidates=hysteria_candidates,
        source_infos=source_infos,
        text_stats=text_stats,
        started_at=started,
        finished_at=finished,
    )

    alive_keys = {r.info.dedup_key for r in checked}
    stats = _compute_source_stats(fetched, source_infos, text_stats, alive_keys)
    storage.update_source_stats(stats)

    storage.append_history({
        "ts": started.strftime("%Y-%m-%d %H:%M"),
        "total": len(unique),
        "alive": len(checked),
        "hysteria_candidates": len(hysteria_candidates),
        "by_scheme": result.by_scheme,
        "alive_by_scheme": result.alive_by_scheme,
        "duration_s": round(result.duration_s, 1),
        "sources": {
            "live": result.live_sources,
            "cached": result.cached_sources,
            "unavailable": result.unavailable_sources,
        },
    })

    log.info(
        "pipeline: done in %.1fs — alive=%d / total=%d",
        result.duration_s, len(checked), len(unique),
    )
    return result
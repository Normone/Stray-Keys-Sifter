"""CLI: python -m straysifter <команда>."""
from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from ..core import load_config
from ..core.country import country_flag, parse_country
from ..core.pipeline import apply_geoip, run_cycle
from ..core.storage import STATUS_LABEL, Storage, compute_status


def _setup_log(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s]\n  %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


def _progress(stage: str, done: int, total: int, alive: int) -> None:
    if not total:
        return
    line = f"  {stage}: {done}/{total} ({alive} ok)"

    if sys.stderr.isatty():
        sys.stderr.write("\r" + line + " " * 10)
        sys.stderr.flush()
        if done == total:
            sys.stderr.write("\n")
        return

    if done % 500 == 0 or done == total:
        logging.getLogger("straysifter.progress").info(
            "%s: %d/%d (%d ok)", stage, done, total, alive,
        )


def _source_line(f) -> None:
    mark = {"live": "✓", "cached": "◌", "unavailable": "✗"}[f.provenance]
    name = f.url.rsplit("/", 1)[-1][:48] or f.url
    n = len(f.text) if f.text else 0
    print(f"  {mark} {name:<50} [{f.provenance}] {n} chars")


def _short_name(url: str) -> str:
    tail = url.rstrip("/").rsplit("/", 1)[-1] or url
    tail = tail.split("?", 1)[0]
    return tail[:40] if tail else url[:40]


def _strip_ext(name: str) -> str:
    for ext in (".txt", ".yaml", ".yml", ".json", ".csv"):
        if name.lower().endswith(ext):
            return name[:-len(ext)]
    return name


def _numbered_names(urls: list[str]) -> dict[str, str]:
    short = [_short_name(u) for u in urls]
    counts: dict[str, int] = {}
    for s in short:
        counts[s] = counts.get(s, 0) + 1
    seen: dict[str, int] = {}
    out: dict[str, str] = {}
    for u, s in zip(urls, short):
        if counts[s] > 1:
            seen[s] = seen.get(s, 0) + 1
            out[u] = f"{s}#{seen[s]}"
        else:
            out[u] = s
    return out


def _match_source(stats: dict, pattern: str) -> str | None:
    needle = pattern.lower()
    matches = [u for u in stats if needle in u.lower()]
    if not matches:
        return None
    matches.sort(key=lambda u: (-len(needle), u))
    return matches[0]


def _resolve_exclude(args, cfg) -> set[str]:
    out: set[str] = set()
    if cfg.checks.exclude_countries:
        out |= {c.upper() for c in cfg.checks.exclude_countries}
    if getattr(args, "exclude_country", None):
        out |= {
            c.strip().upper()
            for c in args.exclude_country.split(",")
            if c.strip()
        }
    return out


# ── команды ──────────────────────────────────────────────────────────

def cmd_collect(args) -> int:
    cfg = load_config()
    if args.mode:
        cfg.checks.mode = args.mode
    if getattr(args, "no_geoip", False):
        cfg.geoip.enabled = False

    excluded = _resolve_exclude(args, cfg)

    print(f"=== collect: mode={cfg.checks.mode}, "
          f"proxy={cfg.fetcher.proxy or 'none'}, "
          f"geoip={'on' if cfg.geoip.enabled else 'off'}, "
          f"sources={len(cfg.sources)}"
          + (f", exclude={sorted(excluded)}" if excluded else "")
          + " ===")

    res = run_cycle(cfg, on_source=_source_line, on_progress=_progress)

    st = Storage(cfg.storage.base)
    recs = st.replace_working(res.checked)

    print(f"\nЖивых: {len(res.checked)} / всего: {len(res.all_infos)}; "
          f"за {res.duration_s:.1f}s")
    if res.by_scheme:
        print("  by scheme: " + " ".join(
            f"{k}={v}" for k, v in sorted(res.by_scheme.items())))
    print(f"Рабочая база: {len(recs)} записей")

    p = st.export_checked(
        res.checked, parse_country, country_flag,
        exclude_countries=excluded,
    )
    print(f"Экспорт: {p}")

    hp = st.export_hysteria_candidates(
        res.hysteria_candidates, parse_country, country_flag,
    )
    if hp:
        print(f"Экспорт (hysteria, без проверки): {hp}  "
              f"({len(res.hysteria_candidates)})")
    return 0


def cmd_sources(args) -> int:
    cfg = load_config()
    from ..core.archive import SourceArchive
    from ..core.fetcher import SourceFetcher

    urls = cfg.sources
    if not urls:
        print("Источники не заданы. Открой config.json и заполни sources.")
        return 1

    fetcher = SourceFetcher(cfg.fetcher)
    archive = SourceArchive(cfg.storage.base / "raw")
    print(f"=== sources: {len(urls)} URL, "
          f"proxy={cfg.fetcher.proxy or 'none'} ===")
    for r in archive.fetch_many(urls, fetcher):
        _source_line(r)
    return 0


def cmd_export(args) -> int:
    cfg = load_config()
    if getattr(args, "no_geoip", False):
        cfg.geoip.enabled = False
    excluded = _resolve_exclude(args, cfg)

    st = Storage(cfg.storage.base)
    db = st.load_working()
    if not db:
        print("База пуста.")
        return 1

    from ..core.checks import CheckResult, UDP_SCHEMES
    from ..core.parsers import parse_any

    results: list[CheckResult] = []
    hysteria: list = []
    for rec in db:
        info = parse_any(rec.key)
        if info is None:
            continue
        info.raw = rec.key
        if info.scheme in UDP_SCHEMES:
            hysteria.append(info)
        else:
            results.append(CheckResult(info=info, ping=rec.ping))

    if cfg.geoip.enabled:
        apply_geoip([r.info for r in results] + hysteria, cfg, cfg.storage.base)

    p = st.export_checked(
        results, parse_country, country_flag,
        exclude_countries=excluded,
    )
    print(f"✓ {p}")

    hp = st.export_hysteria_candidates(hysteria, parse_country, country_flag)
    if hp:
        print(f"✓ {hp}  (hysteria, без проверки)")
    if excluded:
        print(f"  (excluded countries: {sorted(excluded)})")
    return 0


def cmd_export_source(args) -> int:
    cfg = load_config()
    if getattr(args, "no_geoip", False):
        cfg.geoip.enabled = False
    excluded = _resolve_exclude(args, cfg)

    from ..core.archive import SourceArchive
    from ..core.checks import CheckResult, UDP_SCHEMES, run_check
    from ..core.parsers import analyze_text

    st = Storage(cfg.storage.base)
    stats = st.load_source_stats()

    url = _match_source(stats, args.pattern)
    if url is None:
        print(f"Источник по '{args.pattern}' не найден в sources.json.")
        return 1

    archive = SourceArchive(cfg.storage.base / "raw")
    path = archive.latest(url)
    if path is None:
        print(f"Архив для {url} не найден.")
        return 1

    text = path.read_text(encoding="utf-8", errors="ignore")
    ts, infos = analyze_text(text)
    print(f"source : {url}")
    print(f"архив  : {path}")
    print(f"parsed : found={ts.raw_uris} unique={ts.unique}")
    print(f"schemes: " + " ".join(
        f"{k}={v}" for k, v in sorted(ts.by_scheme.items())))

    if not infos:
        print("нет ключей для проверки")
        return 0

    mode = args.mode or cfg.checks.mode
    cfg.checks.mode = mode
    print(f"check  : mode={mode}")

    results = run_check(infos, cfg.checks, on_progress=_progress)
    print(f"\nTCP alive: {len(results)} / {len(infos)}")

    hysteria_infos = [i for i in infos if i.scheme in UDP_SCHEMES]

    if cfg.geoip.enabled:
        apply_geoip([r.info for r in results], cfg, cfg.storage.base)

    safe = _strip_ext(_short_name(url).replace(" ", "_")) or "source"
    exports = st.exports_dir

    p_alive = st.export_checked(
        results, parse_country, country_flag,
        path=exports / f"source_{safe}_alive.txt",
        exclude_countries=excluded,
    )

    all_results = [CheckResult(info=i, ping=0) for i in infos
                   if i.scheme not in UDP_SCHEMES]
    if cfg.geoip.enabled:
        apply_geoip([r.info for r in all_results], cfg, cfg.storage.base)

    all_path = exports / f"source_{safe}_all.txt"
    st.export_checked(
        all_results, parse_country, country_flag,
        path=all_path, exclude_countries=excluded,
    )

    print(f"✓ {p_alive}  ({len(results)})")
    print(f"✓ {all_path}    ({len(all_results)})")
    if hysteria_infos:
        print(f"  (hysteria/hysteria2 в источнике: {len(hysteria_infos)}, "
              f"см. общий hysteria2_candidates.txt после collect)")
    if excluded:
        print(f"  (excluded countries: {sorted(excluded)})")
    return 0


# ──────────────────────────────────────────────────────────────────────
#  geoip-update: качает mmdb с нескольких зеркал
# ──────────────────────────────────────────────────────────────────────

# Основные зеркала GeoLite2-Country, отдаются через GitHub raw/CDN,
# без авторизации и без UA-фильтра. Формат совместим с db-ip (тот же
# ключ country.iso_code), поэтому парсер читает одинаково.
_GEOIP_MIRRORS = [
    # P3TERX/GeoLite.mmdb — ежедневное обновление, самый актуальный
    ("P3TERX/GeoLite.mmdb (Country)",
     "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb"),
    # Loyalsoldier/geoip — тот же maxmind формат, обновляется из releases
    ("Loyalsoldier/geoip (Country)",
     "https://github.com/Loyalsoldier/geoip/releases/latest/download/Country.mmdb"),
    # wp-statistics зеркало — обновляется реже, но стабильное
    ("wp-statistics/GeoLite2-Country",
     "https://raw.githubusercontent.com/wp-statistics/GeoLite2-Country/master/GeoLite2-Country.mmdb"),
]

# db-ip требует браузерный UA — если запускать через urllib, отдаёт 403.
# Оставляем на случай, если GitHub недоступен, но с правильным UA.
_DBIP_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36")


def _download(url: str, dest: Path, *, browser_ua: bool = False) -> int:
    """Скачивает url в dest. Возвращает размер в байтах.

    browser_ua=True — подставляет браузерный User-Agent (для db-ip.com).
    """
    import requests

    headers = {}
    if browser_ua:
        headers["User-Agent"] = _DBIP_UA
        headers["Referer"] = "https://db-ip.com/"

    r = requests.get(url, headers=headers or None, stream=True, timeout=60)
    r.raise_for_status()

    tmp = dest.with_name(dest.name + ".tmp")
    total = int(r.headers.get("Content-Length", 0) or 0)
    got = 0
    try:
        with tmp.open("wb") as fh:
            for chunk in r.iter_content(chunk_size=1 << 20):
                if not chunk:
                    continue
                fh.write(chunk)
                got += len(chunk)
                if total:
                    pct = 100 * got / total
                    sys.stderr.write(
                        f"\r      {got // 1024} / {total // 1024} KB ({pct:.0f}%)"
                    )
                else:
                    sys.stderr.write(f"\r      {got // 1024} KB")
                sys.stderr.flush()
        sys.stderr.write("\n")
    except Exception:
        sys.stderr.write("\n")
        try:
            tmp.unlink()
        except Exception:
            pass
        raise

    tmp.replace(dest)
    return got


def _download_dbip(year: int, month: int, dest: Path) -> int:
    """db-ip.com отдаёт gzip. Скачиваем и распаковываем."""
    import gzip
    import requests

    url = (f"https://download.db-ip.com/free/"
           f"dbip-country-lite-{year}-{month:02d}.mmdb.gz")
    print(f"      url: {url}")

    headers = {"User-Agent": _DBIP_UA, "Referer": "https://db-ip.com/"}
    r = requests.get(url, headers=headers, stream=True, timeout=60)
    r.raise_for_status()

    gz_tmp = dest.with_suffix(".mmdb.gz.tmp")
    got = 0
    try:
        with gz_tmp.open("wb") as fh:
            for chunk in r.iter_content(chunk_size=1 << 20):
                if chunk:
                    fh.write(chunk)
                    got += len(chunk)
                    sys.stderr.write(f"\r      {got // 1024} KB (gz)")
                    sys.stderr.flush()
        sys.stderr.write("\n")

        tmp_out = dest.with_name(dest.name + ".tmp")
        with gzip.open(gz_tmp, "rb") as src, tmp_out.open("wb") as dst:
            while True:
                chunk = src.read(1 << 20)
                if not chunk:
                    break
                dst.write(chunk)
        tmp_out.replace(dest)
    finally:
        try:
            gz_tmp.unlink()
        except Exception:
            pass

    return dest.stat().st_size


def cmd_geoip_update(args) -> int:
    """Скачать mmdb для оффлайн GeoIP-lookup.

    Порядок попыток:
        1. GitHub-зеркала GeoLite2-Country (P3TERX, Loyalsoldier, wp-statistics).
        2. db-ip.com с браузерным User-Agent.
        3. Если и то и другое — инструкция на ручное скачивание.

    Флаг --from URL — использовать свой источник.
    """
    from datetime import date

    cfg = load_config()
    st = Storage(cfg.storage.base)
    dest = Path(cfg.geoip.db_path) if cfg.geoip.db_path \
        else st.base / "dbip-country-lite.mmdb"

    dest.parent.mkdir(parents=True, exist_ok=True)
    exists_info = "no"
    if dest.exists():
        exists_info = f"yes ({dest.stat().st_size // 1024} KB)"
    print(f"target: {dest}")
    print(f"exists: {exists_info}")

    # ── режим --from URL ────────────────────────────────────────────
    if args.from_url:
        print(f"using custom URL: {args.from_url}")
        try:
            size = _download(args.from_url, dest)
            print(f"✓ {dest} ({size / (1024 * 1024):.1f} MB)")
            return 0
        except Exception as e:
            print(f"✗ failed: {e}")
            return 1

    # ── 1. GitHub-зеркала ───────────────────────────────────────────
    for name, url in _GEOIP_MIRRORS:
        print(f"trying {name}")
        print(f"      url: {url}")
        try:
            size = _download(url, dest)
            print(f"✓ {dest} ({size / (1024 * 1024):.1f} MB)")
            print()
            print("готово. mmdb подхватится при следующем запуске.")
            print("проверить: straysifter status  (должно быть 'mmdb=yes')")
            return 0
        except Exception as e:
            print(f"✗ failed: {e}")

    # ── 2. db-ip.com с браузерным UA ────────────────────────────────
    today = date.today()
    y, m = today.year, today.month
    print("trying db-ip.com (3 latest months)")
    for _ in range(3):
        try:
            size = _download_dbip(y, m, dest)
            print(f"✓ {dest} ({size / (1024 * 1024):.1f} MB)")
            print()
            print("готово. mmdb подхватится при следующем запуске.")
            return 0
        except Exception as e:
            print(f"✗ db-ip {y}-{m:02d}: {e}")
        m -= 1
        if m == 0:
            m = 12
            y -= 1

    # ── 3. Всё провалилось ──────────────────────────────────────────
    print()
    print("Автоматически не удалось.")
    print("Попробуй вручную:")
    print("  1. Скачай .mmdb с https://github.com/P3TERX/GeoLite.mmdb")
    print("  2. Положи в: " + str(dest))
    print()
    print("Или укажи свой источник:")
    print("  straysifter geoip-update --from https://.../Country.mmdb")
    return 1


def cmd_geoip_clear(args) -> int:
    cfg = load_config()
    st = Storage(cfg.storage.base)
    cache = st.base / "geoip_cache.json"
    if not cache.exists():
        print("Кэш пуст.")
        return 0
    try:
        cache.unlink()
        print(f"✓ удалён {cache}")
        return 0
    except Exception as e:
        print(f"не удалось: {e}")
        return 1


def cmd_status(args) -> int:
    cfg = load_config()
    st = Storage(cfg.storage.base)
    db = st.load_working()
    hist = st.load_history()
    src = st.load_source_stats()

    print(f"data dir      : {st.base}")
    print(f"proxy (fetch) : {cfg.fetcher.proxy or 'none (direct)'}")
    print(f"mode          : {cfg.checks.mode}")
    print(f"sources       : {len(cfg.sources)} URL")

    geoip_cache = st.base / "geoip_cache.json"
    mmdb = st.base / "dbip-country-lite.mmdb"
    geoip_line = "on" if cfg.geoip.enabled else "off"
    if cfg.geoip.enabled:
        geoip_line += (f" (mmdb: {'yes' if mmdb.exists() else 'no'}, "
                       f"cache: {'yes' if geoip_cache.exists() else 'no'})")
    print(f"geoip         : {geoip_line}")
    if cfg.checks.exclude_countries:
        print(f"exclude       : {sorted(cfg.checks.exclude_countries)}")
    print(f"schedule      : check every {cfg.schedule.check_minutes:.0f}min")
    print(f"working DB    : {len(db)} записей")
    if db:
        by_scheme: dict[str, int] = {}
        for r in db:
            by_scheme[r.scheme] = by_scheme.get(r.scheme, 0) + 1
        print("  by scheme   : " + " ".join(
            f"{k}={v}" for k, v in sorted(by_scheme.items())))
        print(f"  top         : {db[0].ping}ms  {db[0].name}")

    if src:
        buckets: dict[str, int] = {}
        for s in src.values():
            buckets[compute_status(s)] = buckets.get(compute_status(s), 0) + 1
        summary = " ".join(f"{STATUS_LABEL.get(k, k)}={v}"
                           for k, v in sorted(buckets.items()))
        print(f"stats         : {len(src)} sources ({summary})")
    else:
        print("stats         : нет данных")

    print(f"history       : {len(hist)} записей")
    if hist:
        last = hist[-1]
        print(f"  last cycle  : {last.get('ts')}  "
              f"alive={last.get('alive')} / total={last.get('total')}")
    return 0


def cmd_sources_stats(args) -> int:
    cfg = load_config()
    st = Storage(cfg.storage.base)
    stats = st.load_source_stats()
    if not stats:
        print("Нет данных. Запусти `straysifter collect` хотя бы раз.")
        return 0

    order = {"dead": 0, "never_ok": 1, "empty": 2, "no_alive": 3,
             "not_updating": 4, "stale": 5, "low_yield": 6, "ok": 7}

    rows: list[tuple[str, str, dict, str]] = []
    for url, s in stats.items():
        status = compute_status(s)
        rows.append((url, "", s, status))
    rows.sort(key=lambda r: (order.get(r[3], 99),
                             -r[2].get("unique_alive", 0),
                             -r[2].get("alive_ratio", 0)))

    names = _numbered_names([r[0] for r in rows])
    rows = [(u, names[u], s, st) for u, _, s, st in rows]

    if args.json:
        payload = []
        for url, name, s, status in rows:
            row = dict(s)
            row["status"] = status
            row["name"] = name
            payload.append(row)
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 0

    name_w = max((len(r[1]) for r in rows), default=10)
    name_w = min(max(name_w, 16), 40)

    header = (f"{'status':<11}{'found':>7}{'uniq':>7}"
              f"{'contrib':>9}{'alive':>7}{'ratio':>8}  name")
    print(header)
    print("-" * (len(header) + name_w - 4))

    for url, name, s, status in rows:
        label = STATUS_LABEL.get(status, status)
        found = s.get("raw_uris", 0)
        uniq = s.get("unique_local", 0)
        contrib = s.get("unique_alive", 0)
        alive = s.get("alive", 0)
        ratio = s.get("alive_ratio", 0.0)
        print(f"{label:<11}{found:>7}{uniq:>7}"
              f"{contrib:>9}{alive:>7}{ratio * 100:>7.1f}%  {name}")

    problems = [r for r in rows
                if r[3] in ("not_updating", "stale", "dead", "never_ok")]
    if problems and args.verbose:
        print()
        print("times (проблемные):")
        for url, name, s, status in problems:
            fetch = s.get("last_fetch_ok", "") or "never"
            change = s.get("last_change", "") or "never"
            print(f"  {name:<{name_w}}  fetch {fetch}  change {change}")

    if args.verbose:
        with_unsup = [(r[1], r[2]) for r in rows
                      if r[2].get("unsupported_schemes")]
        if with_unsup:
            print()
            print("unsupported schemes:")
            for name, s in with_unsup:
                u = s.get("unsupported_schemes", {})
                line = " ".join(f"{k}={v}" for k, v in sorted(u.items()))
                print(f"  {name:<{name_w}}  {line}")

    print()
    print("full URLs:")
    for url, name, s, status in rows:
        print(f"  {name:<{name_w}}  {url}")

    print()
    print("status: ok / low_yield / not_updating / stale / empty / "
          "no_alive / dead / never_ok")
    print("cols:")
    print("  found   — всего URI в источнике")
    print("  uniq    — уникальных ключей в этом источнике")
    print("  contrib — живых ключей, которых НЕТ в других источниках")
    print("  alive   — сколько прошло TCP-чек")
    print("  ratio   — alive / uniq")
    return 0


def cmd_inspect(args) -> int:
    import asyncio

    cfg = load_config()
    from ..core.archive import SourceArchive
    from ..core.checks import _resolve_one, _try_ips_parallel
    from ..core.parsers import (
        KEY_RE, SUPPORTED_SCHEMES, _scheme_of, analyze_text,
    )

    archive = SourceArchive(cfg.storage.base / "raw")
    st = Storage(cfg.storage.base)
    stats = st.load_source_stats()
    match_url = _match_source(stats, args.pattern)
    if match_url is None and args.pattern.startswith("http"):
        match_url = args.pattern
    if match_url is None:
        print(f"Источник по шаблону '{args.pattern}' не найден.")
        return 1

    path = archive.latest(match_url)
    if path is None:
        print(f"Архив для {match_url} не найден.")
        return 1

    text = path.read_text(encoding="utf-8", errors="ignore")
    print(f"URL    : {match_url}")
    print(f"архив  : {path}")
    print(f"размер : {len(text)} chars, {len(text.splitlines())} lines")
    print()

    uris = KEY_RE.findall(text)
    print(f"regex  : найдено {len(uris)} URI-совпадений")
    by_scheme: dict[str, int] = {}
    for u in uris:
        s = _scheme_of(u)
        by_scheme[s] = by_scheme.get(s, 0) + 1
    for s, n in sorted(by_scheme.items()):
        tag = "supported" if s in SUPPORTED_SCHEMES else "skip"
        print(f"  {s:<12} {n:>6}  ({tag})")
    print()

    ts, infos = analyze_text(text)
    print(f"parsed : kind={ts.kind}")
    print(f"  raw_uris   = {ts.raw_uris}")
    print(f"  supported  = {ts.supported}")
    print(f"  unsupported= {ts.unsupported}")
    print(f"  parsed_ok  = {ts.parsed_ok}")
    print(f"  parse_fail = {ts.parse_fail}")
    print(f"  unique     = {ts.unique}")
    if ts.unsupported_schemes:
        print("  skipped    = " + " ".join(
            f"{k}={v}" for k, v in sorted(ts.unsupported_schemes.items())))
    print()

    endpoints = sorted({i.endpoint for i in infos})
    print(f"unique endpoints: {len(endpoints)}")

    if args.resolve:
        print()
        print("DNS:")
        for host, _ in endpoints:
            _, ips = _resolve_one(host)
            if ips:
                print(f"  {host:<40} -> {', '.join(ips)}")
            else:
                print(f"  {host:<40} -> FAIL")

    if args.check:
        print()
        print(f"TCP-чек (timeout={args.check_timeout}s):")
        for host, port in endpoints:
            _, ips = _resolve_one(host)
            if not ips:
                print(f"  {'DNSFAIL':>8}  {host}:{port}")
                continue
            r = asyncio.run(_try_ips_parallel(ips, port, args.check_timeout))
            mark = f"{r:>5}ms" if r is not None else "  FAIL"
            print(f"  {mark}  {host}:{port}  ({len(ips)} IPs)")

    if args.limit:
        print()
        print(f"первые {args.limit} URI из источника:")
        for u in uris[:args.limit]:
            print(f"  {u[:120]}")
        print()
        print(f"первые {args.limit} распарсенных:")
        for p in infos[:args.limit]:
            print(f"  {p.scheme}://{p.host}:{p.port}  name={p.name[:40]!r}")
    return 0


def cmd_history(args) -> int:
    cfg = load_config()
    st = Storage(cfg.storage.base)
    hist = st.load_history()
    if not hist:
        print("История пуста.")
        return 0

    limit = args.limit or 20
    print(f"{'когда':<18} {'alive':>7} {'total':>7} {'dur':>6}  by scheme")
    for h in hist[-limit:]:
        alive = h.get("alive", 0)
        total = h.get("total", 0)
        dur = h.get("duration_s", 0)
        schemes = h.get("alive_by_scheme", {})
        sch = " ".join(f"{k}={v}" for k, v in sorted(schemes.items()))
        print(f"{h.get('ts',''):<18} {alive:>7} {total:>7} {dur:>5.1f}s  {sch}")
    return 0


def cmd_clean(args) -> int:
    cfg = load_config()
    st = Storage(cfg.storage.base)
    if args.working:
        st.clear_working()
        print("Рабочая база очищена.")
    if args.history:
        st.clear_history()
        print("История очищена.")
    if args.sources:
        st.clear_source_stats()
        print("Статистика источников очищена.")
    if not (args.working or args.history or args.sources):
        print("Укажи --working / --history / --sources.")
        return 1
    return 0


# ── парсер ───────────────────────────────────────────────────────────

def _add_exclude_flag(sp: argparse.ArgumentParser) -> None:
    sp.add_argument(
        "--exclude-country", default=None, metavar="ISO,ISO",
        help="выкинуть ключи этих стран из экспорта (напр. RU,CN). "
             "Дополняет checks.exclude_countries из config.json",
    )


def _add_no_geoip_flag(sp: argparse.ArgumentParser) -> None:
    sp.add_argument(
        "--no-geoip", action="store_true",
        help="не использовать GeoIP в этом вызове",
    )


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="straysifter",
        description="Stray Keys Sifter — сборщик VPN-ключей + TCP/TLS-отсев.",
    )
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("collect", help="fetch → parse → check → save → export")
    sp.add_argument("--mode", choices=["tcp", "tcp+tls"], default=None)
    _add_exclude_flag(sp)
    _add_no_geoip_flag(sp)
    sp.set_defaults(func=cmd_collect)

    sub.add_parser("sources", help="только fetch источников"
                   ).set_defaults(func=cmd_sources)

    sp = sub.add_parser("sources-stats", help="статистика по источникам")
    sp.add_argument("--json", action="store_true", help="вывести JSON")
    sp.add_argument("-v2", "--verbose", action="store_true")
    sp.set_defaults(func=cmd_sources_stats)

    sp = sub.add_parser("inspect",
                        help="разобрать один источник: что нашли, что нет")
    sp.add_argument("pattern")
    sp.add_argument("--limit", type=int, default=10)
    sp.add_argument("--check", action="store_true")
    sp.add_argument("--resolve", action="store_true")
    sp.add_argument("--check-timeout", type=float, default=4.0)
    sp.set_defaults(func=cmd_inspect)

    sp = sub.add_parser("export-source",
                        help="выгрузить один источник (alive + all)")
    sp.add_argument("pattern")
    sp.add_argument("--mode", choices=["tcp", "tcp+tls"], default=None)
    _add_exclude_flag(sp)
    _add_no_geoip_flag(sp)
    sp.set_defaults(func=cmd_export_source)

    sp = sub.add_parser("export", help="выгрузить checked.txt из базы")
    _add_exclude_flag(sp)
    _add_no_geoip_flag(sp)
    sp.set_defaults(func=cmd_export)

    sp = sub.add_parser("geoip-update",
                        help="скачать mmdb для оффлайн-GeoIP "
                             "(GitHub-зеркала GeoLite2 или db-ip.com)")
    sp.add_argument("--from", dest="from_url", default=None, metavar="URL",
                    help="взять mmdb из своего источника")
    sp.set_defaults(func=cmd_geoip_update)

    sub.add_parser("geoip-clear",
                   help="очистить кэш GeoIP (data/geoip_cache.json)"
                   ).set_defaults(func=cmd_geoip_clear)

    sub.add_parser("status", help="база, история, сводка по источникам"
                   ).set_defaults(func=cmd_status)

    sp = sub.add_parser("history", help="последние прогоны")
    sp.add_argument("--limit", type=int, default=20)
    sp.set_defaults(func=cmd_history)

    sp = sub.add_parser("clean", help="очистить базу/историю/статистику")
    sp.add_argument("--working", action="store_true")
    sp.add_argument("--history", action="store_true")
    sp.add_argument("--sources", action="store_true")
    sp.set_defaults(func=cmd_clean)

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    _setup_log(args.verbose)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
"""Рабочая база, история, статистика источников, экспорт.

Экспорт делает минимальную санитизацию URI для совместимости с клиентами
на sing-box (Throne, Hiddify, Karing). Мы не трогаем working.json и не
меняем смысл ключей — только убираем то, что sing-box в принципе не
умеет парсить:

    * WS path: `?ed=N` → (пусто). Xray-only early data, sing-box не знает.
    * `type=raw` → `type=tcp`. Алиас Xray 25.x, sing-box знает только tcp.

Оба фикса безопасны для любого клиента, поэтому применяются всегда.
"""
from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable, Iterable
from urllib.parse import quote, unquote

from .checks import CheckResult
from .parsers import ProxyInfo

log = logging.getLogger(__name__)

WORKING_DB_LIMIT = 20000
HISTORY_LIMIT = 500


def _atomic_write(path: Path, text: str) -> None:
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)


# ──────────────────────────────────────────────────────────────────────
#  URI-санитизация для клиента
# ──────────────────────────────────────────────────────────────────────

_ED_RE = re.compile(r"[?&]ed=\d+", re.IGNORECASE)
_PATH_RE = re.compile(r"([?&])path=([^&]*)")
_RAW_TYPE_RE = re.compile(r"([?&])type=raw(?=&|$)", re.IGNORECASE)


def _sanitize_uri_for_client(raw: str) -> str:
    """Минимальные правки для совместимости с sing-box/Throne.

    Не меняет семантику ключа. Работает по query-части, fragment не трогает.
    """
    if "?" not in raw:
        return raw

    head, tail = raw.split("?", 1)
    if "#" in tail:
        qs, frag = tail.split("#", 1)
        frag = "#" + frag
    else:
        qs, frag = tail, ""

    m = _PATH_RE.search(qs)
    if m:
        prefix = m.group(1)
        path_val = m.group(2)
        decoded = unquote(path_val)
        if _ED_RE.search(decoded):
            cleaned = _ED_RE.sub("", decoded)
            cleaned = re.sub(r"[?&]$", "", cleaned)
            if cleaned == "":
                cleaned = "/"
            new_path_val = quote(cleaned, safe="/?=&")
            qs = qs[:m.start()] + prefix + "path=" + new_path_val + qs[m.end():]

    qs = _RAW_TYPE_RE.sub(r"\1type=tcp", qs)

    return head + "?" + qs + frag


# ──────────────────────────────────────────────────────────────────────
#  Модели
# ──────────────────────────────────────────────────────────────────────

@dataclass
class WorkingRecord:
    key: str
    name: str
    host: str
    port: int
    scheme: str = "vless"
    ping: int = 0
    last_checked: str = ""

    @classmethod
    def from_result(cls, res: CheckResult, ts: str) -> "WorkingRecord":
        i = res.info
        return cls(
            key=i.raw,
            name=i.display_name,
            host=i.host,
            port=i.port,
            scheme=i.scheme,
            ping=int(res.ping or 0),
            last_checked=ts,
        )

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class SourceStats:
    url: str
    last_fetch_ok: str = ""
    last_change: str = ""
    last_hash: str = ""

    kind: str = "uri"
    total_lines: int = 0
    raw_uris: int = 0
    supported: int = 0
    unsupported: int = 0
    parsed_ok: int = 0
    parse_fail: int = 0

    unique_local: int = 0
    unique_only_here: int = 0
    overlap_with_others: int = 0

    alive: int = 0
    alive_ratio: float = 0.0
    unique_alive: int = 0

    by_scheme: dict = field(default_factory=dict)
    unsupported_schemes: dict = field(default_factory=dict)

    cycles_seen: int = 0

    def to_dict(self) -> dict:
        return asdict(self)


def compute_status(s: dict, now: datetime | None = None) -> str:
    now = now or datetime.now()

    def age_hours(ts: str) -> float:
        if not ts:
            return float("inf")
        try:
            return (now - datetime.strptime(ts, "%Y-%m-%d %H:%M")
                    ).total_seconds() / 3600
        except Exception:
            return float("inf")

    if not s.get("last_fetch_ok"):
        return "never_ok"

    fetch_age_h = age_hours(s["last_fetch_ok"])
    if fetch_age_h > 24 * 7:
        return "dead"
    if fetch_age_h > 24 * 2:
        return "stale"

    if s.get("unique_local", 0) == 0:
        return "empty"

    change_age_h = age_hours(s.get("last_change") or s["last_fetch_ok"])
    if change_age_h > 24 * 30 and s.get("unique_local", 0) > 0:
        return "not_updating"

    ratio = s.get("alive_ratio", 0.0)
    if s.get("alive", 0) == 0:
        return "no_alive"
    if ratio < 0.03:
        return "low_yield"
    return "ok"


STATUS_LABEL = {
    "ok": "ok",
    "low_yield": "low yield",
    "not_updating": "not upd",
    "stale": "stale",
    "empty": "empty",
    "no_alive": "no alive",
    "dead": "dead",
    "never_ok": "never ok",
    "unknown": "unknown",
}


def _filter_excluded_countries(
    items: list[CheckResult],
    excluded: set[str],
    country_of: Callable,
) -> list[CheckResult]:
    if not excluded:
        return items
    out: list[CheckResult] = []
    dropped = 0
    for r in items:
        cc = (country_of(r.info) or "XX").upper()
        if cc in excluded:
            dropped += 1
            continue
        out.append(r)
    if dropped:
        log.info("storage: excluded %d keys by country %s",
                 dropped, sorted(excluded))
    return out


class Storage:
    def __init__(self, base: Path | str):
        self.base = Path(base)
        self.base.mkdir(parents=True, exist_ok=True)
        self.working_file = self.base / "working.json"
        self.history_file = self.base / "history.json"
        self.sources_file = self.base / "sources.json"
        self.exports_dir = self.base / "exports"
        self.exports_dir.mkdir(parents=True, exist_ok=True)

    # ── рабочая база ────────────────────────────────────────────────
    def load_working(self) -> list[WorkingRecord]:
        try:
            raw = json.loads(self.working_file.read_text(encoding="utf-8"))
            if not isinstance(raw, list):
                return []
            known = set(WorkingRecord.__dataclass_fields__)
            return [
                WorkingRecord(**{k: v for k, v in item.items() if k in known})
                for item in raw if isinstance(item, dict)
            ]
        except FileNotFoundError:
            return []
        except Exception as e:
            log.warning("storage: %s", e)
            return []

    def save_working(self, records: Iterable[WorkingRecord]) -> list[WorkingRecord]:
        out = sorted(records, key=lambda r: r.ping)[:WORKING_DB_LIMIT]
        try:
            _atomic_write(
                self.working_file,
                json.dumps([r.to_dict() for r in out],
                           ensure_ascii=False, indent=2),
            )
        except Exception as e:
            log.error("storage: %s", e)
        return out

    def replace_working(self, results: list[CheckResult]) -> list[WorkingRecord]:
        ts = datetime.now().strftime("%Y-%m-%d %H:%M")
        return self.save_working(
            WorkingRecord.from_result(r, ts) for r in results
        )

    def clear_working(self) -> None:
        try:
            self.working_file.unlink()
        except FileNotFoundError:
            pass

    # ── история ─────────────────────────────────────────────────────
    def load_history(self) -> list[dict]:
        try:
            data = json.loads(self.history_file.read_text(encoding="utf-8"))
            return data if isinstance(data, list) else []
        except FileNotFoundError:
            return []
        except Exception:
            return []

    def append_history(self, entry: dict) -> None:
        hist = self.load_history()
        hist.append(entry)
        hist = hist[-HISTORY_LIMIT:]
        try:
            _atomic_write(
                self.history_file,
                json.dumps(hist, ensure_ascii=False, indent=2),
            )
        except Exception as e:
            log.warning("storage: history %s", e)

    def clear_history(self) -> None:
        try:
            self.history_file.unlink()
        except FileNotFoundError:
            pass

    # ── статистика источников ───────────────────────────────────────
    def load_source_stats(self) -> dict[str, dict]:
        try:
            raw = json.loads(self.sources_file.read_text(encoding="utf-8"))
            return raw if isinstance(raw, dict) else {}
        except FileNotFoundError:
            return {}
        except Exception as e:
            log.warning("storage: sources %s", e)
            return {}

    def update_source_stats(
        self, stats_list: list[SourceStats],
    ) -> dict[str, dict]:
        all_stats = self.load_source_stats()
        for s in stats_list:
            old = all_stats.get(s.url, {})
            if old.get("last_hash") == s.last_hash and old.get("last_change"):
                s.last_change = old["last_change"]
            if not s.last_fetch_ok:
                s.last_fetch_ok = old.get("last_fetch_ok", "")
            s.cycles_seen = int(old.get("cycles_seen", 0)) + 1
            all_stats[s.url] = s.to_dict()
        try:
            _atomic_write(
                self.sources_file,
                json.dumps(all_stats, ensure_ascii=False, indent=2),
            )
        except Exception as e:
            log.warning("storage: sources write %s", e)
        return all_stats

    def clear_source_stats(self) -> None:
        try:
            self.sources_file.unlink()
        except FileNotFoundError:
            pass

    # ── экспорт ─────────────────────────────────────────────────────
    def export_checked(
        self,
        alive: list[CheckResult],
        country_of: callable,
        flag_of: callable,
        path: Path | None = None,
        *,
        exclude_countries: set[str] | None = None,
    ) -> Path:
        """Общий checked.txt + по одному файлу на схему.

        exclude_countries — ISO-коды, которые НЕ попадают в экспорт.
        Каждая строка URI проходит sanitize (WS ?ed=N, type=raw) — это
        снимает известные спотыкачи sing-box/Throne.
        """
        if exclude_countries:
            alive = _filter_excluded_countries(
                alive, {c.upper() for c in exclude_countries}, country_of,
            )

        p = path or (self.exports_dir / "checked.txt")
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        header = "# VPN keys — только живые по TCP"
        if exclude_countries:
            header += f" (excluded: {','.join(sorted(exclude_countries))})"

        n_sanitized = self._count_sanitized(alive)
        if n_sanitized:
            log.info("storage: sanitized %d keys for client compatibility",
                     n_sanitized)

        self._write_grouped(p, alive, country_of, flag_of, now, header=header)

        by_scheme: dict[str, list[CheckResult]] = {}
        for r in alive:
            by_scheme.setdefault(r.info.scheme, []).append(r)

        for scheme, items in by_scheme.items():
            sp = self.exports_dir / f"checked_{scheme}.txt"
            self._write_grouped(
                sp, items, country_of, flag_of, now,
                header=f"# {scheme} keys — только живые по TCP",
            )

        log.info("storage: exported %s (%d alive, %d schemes)",
                 p, len(alive), len(by_scheme))
        return p

    def export_hysteria_candidates(
        self,
        infos: list[ProxyInfo],
        country_of: callable,
        flag_of: callable,
    ) -> Path | None:
        """Все hysteria/hysteria2-ключи без проверки живости.

        TCP-connect к ним бессмысленен (UDP-протокол), полноценная
        QUIC-проверка требует sing-box. Отдаём отдельным файлом —
        пользователь сам импортирует в клиент и прогонит тест.
        """
        if not infos:
            return None

        seen: set[str] = set()
        unique: list[ProxyInfo] = []
        for i in infos:
            if i.dedup_key in seen:
                continue
            seen.add(i.dedup_key)
            unique.append(i)

        p = self.exports_dir / "hysteria2_candidates.txt"
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        groups: dict[str, list[ProxyInfo]] = {}
        for i in unique:
            groups.setdefault(country_of(i), []).append(i)

        order = sorted(
            groups.keys(),
            key=lambda c: (0 if c == "RU" else (1 if c != "XX" else 2), c),
        )

        lines = [
            "# Hysteria / Hysteria2 candidates — БЕЗ проверки живости",
            f"# Обновлено: {now}",
            f"# Всего: {len(unique)}",
            "#",
            "# UDP-протоколы: TCP-connect к ним провалится; полноценная",
            "# проверка требует sing-box. Импортируй файл в клиент и прогони",
            "# тест задержки сам.",
        ]
        for cc in order:
            group = groups[cc]
            for i, info in enumerate(group, 1):
                base = info.raw.split("#", 1)[0]
                base = _sanitize_uri_for_client(base)
                lines.append(
                    f"{base}#{flag_of(cc)} {cc}-{i:03d} "
                    f"[{info.protocol_label}] unverified"
                )

        _atomic_write(p, "\n".join(lines))
        log.info("storage: exported %s (%d hysteria candidates)",
                 p, len(unique))
        return p

    @staticmethod
    def _count_sanitized(items: list[CheckResult]) -> int:
        n = 0
        for r in items:
            base = r.info.raw.split("#", 1)[0]
            if _sanitize_uri_for_client(base) != base:
                n += 1
        return n

    def _write_grouped(
        self,
        path: Path,
        items: list[CheckResult],
        country_of: callable,
        flag_of: callable,
        ts: str,
        header: str,
    ) -> None:
        groups: dict[str, list[CheckResult]] = {}
        for r in items:
            groups.setdefault(country_of(r.info), []).append(r)

        order = sorted(
            groups.keys(),
            key=lambda c: (0 if c == "RU" else (1 if c != "XX" else 2), c),
        )

        lines = [
            header,
            f"# Обновлено: {ts}",
            f"# Всего: {len(items)}",
            "",
        ]
        for cc in order:
            group = sorted(groups[cc], key=lambda r: r.ping)
            for i, r in enumerate(group, 1):
                base = r.info.raw.split("#", 1)[0]
                base = _sanitize_uri_for_client(base)
                lines.append(
                    f"{base}#{flag_of(cc)} {cc}-{i:03d} "
                    f"[{r.info.protocol_label}] {r.ping}ms"
                )
        _atomic_write(path, "\n".join(lines))
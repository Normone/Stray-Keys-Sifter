"""Определение «домашней» директории проекта."""
from __future__ import annotations

import os
from pathlib import Path

_HOME_CACHE: Path | None = None
_MARKERS = ("config.json", ".straysifter")


def find_home() -> Path:
    global _HOME_CACHE
    if _HOME_CACHE is not None:
        return _HOME_CACHE

    if v := os.environ.get("straysifter_HOME"):
        _HOME_CACHE = Path(v).expanduser().resolve()
        return _HOME_CACHE

    cur = Path.cwd().resolve()
    for p in (cur, *cur.parents):
        for marker in _MARKERS:
            if (p / marker).exists():
                _HOME_CACHE = p
                return p

    _HOME_CACHE = cur
    return cur


def reset_cache() -> None:
    global _HOME_CACHE
    _HOME_CACHE = None
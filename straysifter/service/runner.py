"""Раннер: периодический цикл fetch → check → save → export."""
from __future__ import annotations

import logging
import signal
import threading
import time

from ..core import load_config
from ..core.country import country_flag, parse_country
from ..core.pipeline import run_cycle
from ..core.storage import STATUS_LABEL, Storage, compute_status

log = logging.getLogger(__name__)


class Runner:
    def __init__(self, cfg=None):
        self.cfg = cfg or load_config()
        self.stop_event = threading.Event()
        self.storage = Storage(self.cfg.storage.base)

        self._next_check = 0.0

    def cycle_checks(self) -> None:
        log.info("cycle: start (mode=%s, proxy=%s, sources=%d)",
                 self.cfg.checks.mode, self.cfg.fetcher.proxy or "none",
                 len(self.cfg.sources))
        try:
            res = run_cycle(self.cfg, on_progress=self._log_progress)
            recs = self.storage.replace_working(res.checked)
            log.info("cycle: alive=%d, db=%d", len(res.checked), len(recs))
            self.storage.export_checked(res.checked, parse_country, country_flag)

            stats = self.storage.load_source_stats()
            buckets: dict[str, int] = {}
            for s in stats.values():
                st = compute_status(s)
                buckets[st] = buckets.get(st, 0) + 1
            summary = " ".join(
                f"{STATUS_LABEL.get(k, k)}={v}"
                for k, v in sorted(buckets.items())
            )
            log.info("cycle: sources summary — %s", summary)
        except Exception:
            log.exception("cycle: failed")

    @staticmethod
    def _log_progress(stage: str, done: int, total: int, alive: int) -> None:
        if total and (done % 500 == 0 or done == total):
            log.info("  %s: %d/%d ok=%d", stage, done, total, alive)

    def run_forever(self) -> None:
        log.info("runner: start (check every %.1fmin, mode=%s)",
                 self.cfg.schedule.check_minutes, self.cfg.checks.mode)
        self._next_check = time.monotonic()

        while not self.stop_event.is_set():
            now = time.monotonic()
            if now >= self._next_check:
                self.cycle_checks()
                self._next_check = now + self.cfg.schedule.check_minutes * 60
            self.stop_event.wait(
                max(1.0, min(30.0, self._next_check - time.monotonic()))
            )
        log.info("runner: stopped")

    def stop(self) -> None:
        self.stop_event.set()


def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s]\n  %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    runner = Runner()

    def _sig(*_):
        runner.stop()

    signal.signal(signal.SIGTERM, _sig)
    if hasattr(signal, "SIGINT"):
        signal.signal(signal.SIGINT, _sig)

    try:
        runner.run_forever()
    except KeyboardInterrupt:
        runner.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
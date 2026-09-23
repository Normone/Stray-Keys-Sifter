"""POSIX-демон: двойной fork."""
from __future__ import annotations

import logging
import logging.handlers
import os
import signal
import sys
import time
from pathlib import Path

from ..core.config import ensure_home
from ..core.paths import find_home

log = logging.getLogger(__name__)

LOG_MAX_BYTES = 5 * 1024 * 1024
LOG_BACKUPS = 5

_HAS_FORK = hasattr(os, "fork")


def _home() -> Path:
    return find_home()


def _pid_file() -> Path:
    return _home() / "straysifter.pid"


def _log_file() -> Path:
    return _home() / "straysifter.log"


def _daemonize() -> None:
    if not _HAS_FORK:
        raise RuntimeError("os.fork недоступен (Windows)")

    pid = os.fork()
    if pid > 0:
        sys.exit(0)

    os.setsid()
    os.umask(0o022)

    pid = os.fork()
    if pid > 0:
        sys.exit(0)

    os.chdir(_home())

    devnull = os.open(os.devnull, os.O_RDWR)
    for fd in (sys.stdin.fileno(), sys.stdout.fileno(), sys.stderr.fileno()):
        os.dup2(devnull, fd)
    os.close(devnull)

    _pid_file().write_text(str(os.getpid()))


def _get_pid() -> int | None:
    if not _HAS_FORK:
        return None
    try:
        pid = int(_pid_file().read_text().strip())
        os.kill(pid, 0)
        return pid
    except (FileNotFoundError, ValueError, ProcessLookupError, PermissionError):
        return None


def _remove_pidfile() -> None:
    try:
        _pid_file().unlink()
    except FileNotFoundError:
        pass


def install() -> int:
    if not _HAS_FORK:
        print("✗ POSIX-демон недоступен на этой платформе.")
        return 1
    home = ensure_home()
    probe = home / ".straysifter_write_probe"
    try:
        probe.write_text("ok")
        probe.unlink()
    except OSError as e:
        print(f"✗ нет прав на запись в {home}: {e}")
        return 1

    print("✓ daemon(posix) готов")
    print(f"  PID : {_pid_file()}")
    print(f"  Лог : {_log_file()}")
    print("  Старт: python -m straysifter.service start")
    return 0


def uninstall() -> int:
    stop()
    _remove_pidfile()
    print("✓ daemon(posix) удалён (логи и данные оставлены)")
    return 0


def start() -> int:
    if not _HAS_FORK:
        print("✗ os.fork недоступен.")
        return 1
    if pid := _get_pid():
        print(f"Уже запущен (PID {pid}).")
        return 0

    print("Форкаюсь в фон...")
    _daemonize()

    root = logging.getLogger()
    root.setLevel(logging.INFO)
    for h in list(root.handlers):
        root.removeHandler(h)
    handler = logging.handlers.RotatingFileHandler(
        _log_file(), maxBytes=LOG_MAX_BYTES, backupCount=LOG_BACKUPS,
        encoding="utf-8",
    )
    handler.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s]\n  %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    ))
    root.addHandler(handler)

    from ..core import load_config
    from .runner import Runner

    runner = Runner(load_config())

    def _graceful(signum, frame):
        log.info("daemon: signal %d, stopping...", signum)
        runner.stop()

    signal.signal(signal.SIGTERM, _graceful)
    signal.signal(signal.SIGINT, _graceful)

    try:
        runner.run_forever()
    finally:
        _remove_pidfile()
        log.info("daemon: stopped")
    return 0


def stop() -> int:
    if not _HAS_FORK:
        return 1
    pid = _get_pid()
    if not pid:
        print("Демон не запущен.")
        _remove_pidfile()
        return 0

    print(f"Останавливаю PID {pid}...")
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        _remove_pidfile()
        return 0

    for _ in range(300):
        time.sleep(0.1)
        if not _get_pid():
            print("Остановлен.")
            return 0

    print("Не завершился за 30с, SIGKILL...")
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    _remove_pidfile()
    print("Убит.")
    return 0


def restart() -> int:
    stop()
    time.sleep(0.5)
    return start()


def status() -> int:
    if not _HAS_FORK:
        print("✗ POSIX-демон недоступен на этой платформе.")
        return 1
    pid = _get_pid()
    if pid:
        print(f"✓ Запущен (PID {pid})")
        print(f"  Лог: {_log_file()}")
        return 0
    print("✗ Не запущен")
    if _log_file().exists():
        try:
            lines = _log_file().read_text(encoding="utf-8").splitlines()[-5:]
            if lines:
                print("  Последние строки:")
                for line in lines:
                    print("   ", line)
        except Exception:
            pass
    return 1
"""Windows-бэкенд «демона» без SCM."""
from __future__ import annotations

import ctypes
import logging
import logging.handlers
import os
import signal
import subprocess
import sys
import time
from ctypes import wintypes
from pathlib import Path

from ..core.config import ensure_home
from ..core.paths import find_home

log = logging.getLogger(__name__)

LOG_MAX_BYTES = 5 * 1024 * 1024
LOG_BACKUPS = 5


def _home() -> Path:
    return find_home()


def _pid_file() -> Path:
    return _home() / "straysifter.pid"


def _log_file() -> Path:
    return _home() / "straysifter.log"


_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
_STILL_ACTIVE = 259
_k32 = ctypes.WinDLL("kernel32", use_last_error=True)


def _pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    h = _k32.OpenProcess(_PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not h:
        return False
    try:
        code = wintypes.DWORD()
        if not _k32.GetExitCodeProcess(h, ctypes.byref(code)):
            return False
        return code.value == _STILL_ACTIVE
    finally:
        _k32.CloseHandle(h)


def _read_pid() -> int | None:
    try:
        pid = int(_pid_file().read_text().strip())
    except (FileNotFoundError, ValueError):
        return None
    return pid if _pid_alive(pid) else None


def _remove_pidfile() -> None:
    try:
        _pid_file().unlink()
    except FileNotFoundError:
        pass


def install() -> int:
    home = ensure_home()
    probe = home / ".straysifter_write_probe"
    try:
        probe.write_text("ok")
        probe.unlink()
    except OSError as e:
        print(f"✗ нет прав на запись в {home}: {e}")
        return 1

    print("✓ daemon(windows) готов")
    print(f"  PID : {_pid_file()}")
    print(f"  Лог : {_log_file()}")
    print("  Старт: python -m straysifter.service start")
    return 0


def uninstall() -> int:
    stop()
    _remove_pidfile()
    print("✓ daemon(windows) удалён (логи и данные оставлены)")
    return 0


def start() -> int:
    if pid := _read_pid():
        print(f"Уже запущен (PID {pid}).")
        return 0

    home = _home()
    py = sys.executable

    flags = (
        subprocess.DETACHED_PROCESS
        | subprocess.CREATE_NEW_PROCESS_GROUP
        | subprocess.CREATE_NO_WINDOW
    )

    log_path = _log_file()
    log_handle = open(log_path, "a", encoding="utf-8")

    try:
        proc = subprocess.Popen(
            [py, "-m", "straysifter.service", "_run_runner"],
            cwd=str(home),
            stdin=subprocess.DEVNULL,
            stdout=log_handle,
            stderr=log_handle,
            creationflags=flags,
            close_fds=False,
        )
    finally:
        log_handle.close()

    _pid_file().write_text(str(proc.pid))
    time.sleep(0.5)

    if not _pid_alive(proc.pid):
        print(f"✗ процесс сразу упал, смотри {log_path}")
        _remove_pidfile()
        return 1

    print(f"✓ Запущен в фоне (PID {proc.pid})")
    print(f"  Лог: {log_path}")
    return 0


def stop() -> int:
    pid = _read_pid()
    if not pid:
        print("Демон не запущен.")
        _remove_pidfile()
        return 0

    print(f"Останавливаю PID {pid}...")
    subprocess.run(
        ["taskkill", "/PID", str(pid), "/F"],
        capture_output=True, text=True, check=False,
    )
    _remove_pidfile()
    print("Остановлен.")
    return 0


def restart() -> int:
    stop()
    time.sleep(0.5)
    return start()


def status() -> int:
    pid = _read_pid()
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


def run_runner_detached() -> int:
    """Выполняется внутри detached-процесса."""
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

    os.chdir(_home())
    from ..core import load_config
    from .runner import Runner

    runner = Runner(load_config())

    try:
        signal.signal(signal.SIGINT, lambda *_: runner.stop())
        signal.signal(signal.SIGTERM, lambda *_: runner.stop())
    except Exception:
        pass
    if hasattr(signal, "SIGBREAK"):
        try:
            signal.signal(signal.SIGBREAK, lambda *_: runner.stop())
        except Exception:
            pass

    try:
        runner.run_forever()
    finally:
        _remove_pidfile()
    return 0
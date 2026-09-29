"""Windows Service (pywin32) обёртка для straysifter.

Устанавливается и управляется через straysifter-service:
    straysifter-service install-service
    straysifter-service start-service
    straysifter-service stop-service
    straysifter-service restart-service
    straysifter-service status-service
    straysifter-service remove-service
    straysifter-service debug-service

Отладка без установки службы: python -m straysifter.service debug-service

Требования:
    pip install pywin32
    python <...>/Scripts/pywin32_postinstall.py -install   (от админа, один раз)

Служба устанавливается от LocalSystem, auto-start, restart-on-failure.
ImagePath = "<python.exe>" "<script.py>", то есть SCM запускает наш
скрипт напрямую, а не pythonservice.exe-обёртку pywin32.

Пути проекта передаются через env-переменные службы (straysifter_HOME,
SIFTER_DATA), потому что рабочий каталог LocalSystem — C:\\Windows\\System32.
"""
from __future__ import annotations

import logging
import logging.handlers
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

# Кладём корень проекта в sys.path до любых импортов straysifter.
# Нужно, потому что этот файл может запускаться как обычный скрипт
# (SCM именно так его и запускает).
_THIS = Path(__file__).resolve()
_PROJECT_ROOT = _THIS.parents[2]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

try:
    import win32serviceutil
    import win32service
    import win32event
    import servicemanager
    _HAS_PYWIN32 = True
except ImportError:
    _HAS_PYWIN32 = False


SERVICE_NAME = "Straysifter"
SERVICE_DISPLAY_NAME = "Stray Keys Sifter"
SERVICE_DESCRIPTION = (
    "Сборщик публичных VPN-ключей: fetch, TCP/sing-box проверка, "
    "GeoIP, экспорт."
)

# Сколько секунд ждать graceful shutdown после SvcStop, до жёсткого kill.
# SCM по умолчанию даёт 30 секунд, оставляем запас.
STOP_GRACE_SEC = 25

LOG_MAX_BYTES = 5 * 1024 * 1024
LOG_BACKUPS = 5


# ── env / пути ──────────────────────────────────────────────────────

def _home() -> Path:
    from straysifter.core.paths import find_home
    return find_home()


def _setup_file_logging() -> None:
    """Перенаправляет root logger в straysifter.log с ротацией."""
    log_file = _home() / "straysifter.log"
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    for h in list(root.handlers):
        root.removeHandler(h)
    handler = logging.handlers.RotatingFileHandler(
        log_file, maxBytes=LOG_MAX_BYTES, backupCount=LOG_BACKUPS,
        encoding="utf-8",
    )
    handler.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s]\n  %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    ))
    root.addHandler(handler)


def _kill_singbox_orphans() -> None:
    """Убить оставшиеся sing-box.exe от предыдущих batch'ей.

    sing-box запускается как дочерний процесс python'а. При жёстком
    kill'е питона он может остаться сиротой. Чистим перед выходом.
    """
    try:
        subprocess.run(
            ["taskkill", "/IM", "sing-box.exe", "/F"],
            capture_output=True, text=True, check=False, timeout=10,
        )
    except Exception:
        pass


# ── сам класс службы ────────────────────────────────────────────────

if _HAS_PYWIN32:

    class StraysifterService(win32serviceutil.ServiceFramework):
        _svc_name_ = SERVICE_NAME
        _svc_display_name_ = SERVICE_DISPLAY_NAME
        _svc_description_ = SERVICE_DESCRIPTION

        def __init__(self, args):
            super().__init__(args)
            self._stop_event = win32event.CreateEvent(None, 0, 0, None)
            self._runner = None
            self._runner_thread = None

        def SvcDoRun(self):
            # Сразу рапортуем RUNNING. Иначе SCM ждёт первого
            # ReportServiceStatus и, если мы долго возимся на старте
            # (chdir, логирование, load_config), может выдать 1053.
            self.ReportServiceStatus(win32service.SERVICE_RUNNING)
            servicemanager.LogMsg(
                servicemanager.EVENTLOG_INFORMATION_TYPE,
                servicemanager.PYS_SERVICE_STARTED,
                (self._svc_name_, ""),
            )
            try:
                self._run()
            except Exception as e:
                servicemanager.LogErrorMsg(f"straysifter: fatal: {e}")
                raise

        def _run(self):
            # LocalSystem cwd = C:\Windows\System32. Перепрыгиваем в
            # корень проекта, чтобы относительные пути (data/,
            # config.json) разрешались правильно.
            home = _home()
            os.chdir(home)
            _setup_file_logging()

            log = logging.getLogger("straysifter.service")
            log.info("service(windows): start (cwd=%s, user=%s)",
                     home, os.environ.get("USERNAME", "?"))

            from straysifter.core import load_config
            from straysifter.service.runner import Runner

            self._runner = Runner(load_config())

            def _worker():
                try:
                    self._runner.run_forever()
                except Exception:
                    log.exception("service(windows): runner died")

            self._runner_thread = threading.Thread(
                target=_worker, daemon=True,
            )
            self._runner_thread.start()

            # Ждём сигнала остановки (SvcStop дёргает _stop_event).
            win32event.WaitForSingleObject(
                self._stop_event, win32event.INFINITE,
            )

            log.info("service(windows): stop requested")
            if self._runner is not None:
                self._runner.stop()

            # SCM даёт 30 секунд на остановку. Пока цикл дорабатывает,
            # периодически рапортуем STOP_PENDING, иначе SCM решит,
            # что служба висит, и прибьёт её TerminateProcess'ом.
            deadline = time.monotonic() + STOP_GRACE_SEC
            while (self._runner_thread.is_alive()
                   and time.monotonic() < deadline):
                self.ReportServiceStatus(
                    win32service.SERVICE_STOP_PENDING,
                    waitHint=5000,
                    checkpoint=1,
                )
                self._runner_thread.join(timeout=1.0)

            if self._runner_thread.is_alive():
                log.warning(
                    "service(windows): runner did not stop in %ds, "
                    "forcing exit", STOP_GRACE_SEC,
                )
            _kill_singbox_orphans()
            log.info("service(windows): stopped")

        def SvcStop(self):
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            win32event.SetEvent(self._stop_event)

else:
    class StraysifterService:  # type: ignore[no-redef]
        pass


# ── операции установки / управления ─────────────────────────────────

def _check_pywin32() -> bool:
    if _HAS_PYWIN32:
        return True
    print("✗ pywin32 не установлен.")
    print()
    print("  pip install pywin32")
    print("  python <path-to-python>/Scripts/pywin32_postinstall.py -install")
    print("  (второе — от админа, один раз)")
    print()
    print("После этого перезапусти команду.")
    return False


def _set_service_env(home: Path) -> None:
    """Прописывает env-переменные в реестр службы.

    Нужно потому, что LocalSystem стартует в C:\\Windows\\System32,
    а find_home() должен найти корень проекта. straysifter_HOME
    читается в core/paths.py до всяких эвристик.
    """
    import winreg
    key_path = rf"SYSTEM\CurrentControlSet\Services\{SERVICE_NAME}"
    env = [
        f"straysifter_HOME={home}",
        f"SIFTER_DATA={home / 'data'}",
        f"PYTHONPATH={home}",
    ]
    with winreg.OpenKey(
        winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_SET_VALUE,
    ) as k:
        winreg.SetValueEx(k, "Environment", 0, winreg.REG_MULTI_SZ, env)


def install() -> int:
    if not _check_pywin32():
        return 1

    home = _home()
    script = _THIS

    # Служба могла остаться от предыдущей установки — снимаем,
    # чтобы не плодить конфликты.
    subprocess.run(
        ["sc", "stop", SERVICE_NAME],
        capture_output=True, text=True, check=False,
    )
    time.sleep(1)
    subprocess.run(
        ["sc", "delete", SERVICE_NAME],
        capture_output=True, text=True, check=False,
    )

    # Ключевой момент: явно задаём exeName (python.exe) и exeArgs
    # ("<script>"). Тогда pywin32 не подставит свою pythonservice.exe
    # обёртку — SCM запустит python.exe напрямую с нашим скриптом.
    # В argv скрипта будет только имя файла — блок __main__ внизу
    # сам вызовет servicemanager.Initialize + StartServiceCtrlDispatcher.
    win32serviceutil.InstallService(
        pythonClassString=None,
        serviceName=SERVICE_NAME,
        displayName=SERVICE_DISPLAY_NAME,
        startType=win32service.SERVICE_AUTO_START,
        exeName=sys.executable,
        exeArgs=f'"{script}"',
        description=SERVICE_DESCRIPTION,
    )

    # Restart-on-failure: 3 попытки с интервалом 60 секунд.
    subprocess.run(
        ["sc", "failure", SERVICE_NAME,
         "restart/60000/restart/60000/restart/60000"],
        capture_output=True, text=True, check=False,
    )

    # Env-переменные для find_home() в session 0.
    try:
        _set_service_env(home)
    except Exception as e:
        print(f"✗ не удалось прописать env: {e}")
        print("  служба установлена, но может не найти config.json")
        return 1

    # Покажем, что SCM собирается запускать — для самопроверки.
    # Вывод sc.exe в UTF-16/cp866, поэтому парсим не строки,
    # а показываем сырой вывод — в PowerShell он рендерится нормально.
    qc = subprocess.run(
        ["sc", "qc", SERVICE_NAME],
        capture_output=True, text=True, check=False,
    )

    print(f"✓ служба '{SERVICE_DISPLAY_NAME}' установлена")
    print(f"  имя:    {SERVICE_NAME}")
    print(f"  python: {sys.executable}")
    print(f"  script: {script}")
    print(f"  home:   {home}")
    print()
    print("  Проверить: sc.exe qc Straysifter")
    print("  Запуск:    straysifter-service start-service")
    return 0


def remove() -> int:
    if not _check_pywin32():
        return 1
    subprocess.run(
        ["sc", "stop", SERVICE_NAME],
        capture_output=True, text=True, check=False,
    )
    time.sleep(1)
    try:
        win32serviceutil.RemoveService(SERVICE_NAME)
    except Exception as e:
        print(f"✗ {e}")
        return 1
    print(f"✓ служба '{SERVICE_DISPLAY_NAME}' удалена")
    return 0


def start() -> int:
    if not _check_pywin32():
        return 1
    try:
        win32serviceutil.StartService(SERVICE_NAME)
    except Exception as e:
        print(f"✗ не удалось запустить: {e}")
        return 1
    print(f"✓ служба '{SERVICE_DISPLAY_NAME}' запущена")
    return 0


def stop() -> int:
    if not _check_pywin32():
        return 1
    try:
        win32serviceutil.StopService(SERVICE_NAME)
    except Exception as e:
        print(f"✗ не удалось остановить: {e}")
        return 1
    print(f"✓ служба '{SERVICE_DISPLAY_NAME}' остановлена")
    return 0


def restart() -> int:
    stop()
    time.sleep(1)
    return start()


def status() -> int:
    r = subprocess.run(
        ["sc", "query", SERVICE_NAME],
        capture_output=True, text=True, check=False,
        encoding="cp866", errors="replace",
    )
    if r.returncode != 0:
        print(f"✗ служба '{SERVICE_DISPLAY_NAME}' не установлена")
        return 1
    print(r.stdout.strip())
    return 0


def debug() -> int:
    """Запуск логики в консоли без установки службы.

    Полезно, если служба не стартует и нужно увидеть traceback
    в живом виде.
    """
    print("[DEBUG] запуск runner'а в консоли. Ctrl+C для выхода.\n")
    home = _home()
    os.chdir(home)
    _setup_file_logging()
    from straysifter.core import load_config
    from straysifter.service.runner import Runner
    try:
        Runner(load_config()).run_forever()
    except KeyboardInterrupt:
        print("\nОстановлено.")
    return 0


def _run_as_service() -> None:
    """SCM-режим: регистрируемся у Service Control Manager и ждём.

    Стандартный паттерн pywin32:
        Initialize → PrepareToHostSingle → StartServiceCtrlDispatcher.

    Именно этот путь нужен, когда ImagePath = "python.exe script.py",
    а не "pythonservice.exe <class>". Без явного PrepareToHostSingle
    HandleCommandLine в некоторых сборках pywin32 не регистрирует
    ServiceMain, и SCM получает 1053.
    """
    servicemanager.Initialize()
    servicemanager.PrepareToHostSingle(StraysifterService)
    servicemanager.StartServiceCtrlDispatcher()


if __name__ == "__main__":
    # Этот блок нужен pywin32: SCM запускает файл как скрипт и ждёт,
    # что тот сам разберётся, что делать (start/stop/install/...).
    if not _HAS_PYWIN32:
        print("✗ pywin32 не установлен")
        sys.exit(1)

    # Без аргументов — нас запустил SCM. Регистрируем ServiceMain
    # и уходим в ожидание. Никакого HandleCommandLine здесь быть
    # не должно: он для интерактивного управления.
    if len(sys.argv) == 1:
        _run_as_service()
        sys.exit(0)

    # С аргументами — ручное управление.
    if sys.argv[1] == "debug":
        sys.exit(debug())

    win32serviceutil.HandleCommandLine(StraysifterService)
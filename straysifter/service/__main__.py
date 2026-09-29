"""Управление сервисом: python -m straysifter.service <cmd>."""
from __future__ import annotations

import argparse
import logging
import subprocess
import sys
from pathlib import Path

IS_WINDOWS = sys.platform.startswith("win")


def _backend():
    """Daemon-бэкенд (старый, detached/fork)."""
    if IS_WINDOWS:
        from . import daemon_windows
        return daemon_windows
    from . import daemon_posix
    return daemon_posix


def _service_backend():
    """Windows Service (pywin32). Только для Windows."""
    if not IS_WINDOWS:
        return None
    from . import service_windows
    return service_windows


def _setup_log(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


# ── daemon-команды (старые) ─────────────────────────────────────────

def _cmd_install(args) -> int:
    return _backend().install()


def _cmd_uninstall(args) -> int:
    return _backend().uninstall()


def _cmd_action(args, name: str) -> int:
    return getattr(_backend(), name)()


def _cmd_status(args) -> int:
    return _backend().status()


def _cmd_debug(args) -> int:
    from ..core import load_config
    from .runner import Runner
    print("[DEBUG] Раннер в консоли. Ctrl+C для выхода.\n")
    try:
        Runner(load_config()).run_forever()
    except KeyboardInterrupt:
        print("\nОстановлено.")
    return 0


def _cmd_run_runner(args) -> int:
    """Внутренняя команда для detached-процесса на Windows."""
    if not IS_WINDOWS:
        return 1
    from . import daemon_windows
    return daemon_windows.run_runner_detached()


# ── Windows Service команды ─────────────────────────────────────────

def _service_required() -> int | None:
    """Возвращает код ошибки, если служба недоступна, иначе None."""
    if not IS_WINDOWS:
        print("✗ управление Windows-службой доступно только на Windows")
        return 1
    backend = _service_backend()
    if backend is None:
        print("✗ не удалось загрузить service_windows")
        return 1
    return None


def _cmd_install_service(args) -> int:
    err = _service_required()
    if err is not None:
        return err
    return _service_backend().install()


def _cmd_remove_service(args) -> int:
    err = _service_required()
    if err is not None:
        return err
    return _service_backend().remove()


def _cmd_start_service(args) -> int:
    err = _service_required()
    if err is not None:
        return err
    return _service_backend().start()


def _cmd_stop_service(args) -> int:
    err = _service_required()
    if err is not None:
        return err
    return _service_backend().stop()


def _cmd_restart_service(args) -> int:
    err = _service_required()
    if err is not None:
        return err
    return _service_backend().restart()


def _cmd_status_service(args) -> int:
    err = _service_required()
    if err is not None:
        return err
    return _service_backend().status()


def _cmd_debug_service(args) -> int:
    err = _service_required()
    if err is not None:
        return err
    return _service_backend().debug()


# ── CLI ─────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="straysifter.service",
        description="Управление сервисом straysifter.",
    )
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="cmd", required=True)

    # daemon (старый, detached subprocess / двойной fork)
    sub.add_parser("install",
                   help="установить detached-daemon (fallback)")
    sub.choices["install"].set_defaults(func=_cmd_install)

    sub.add_parser("uninstall")
    sub.choices["uninstall"].set_defaults(func=_cmd_uninstall)

    sub.add_parser("start")
    sub.choices["start"].set_defaults(func=lambda a: _cmd_action(a, "start"))

    sub.add_parser("stop")
    sub.choices["stop"].set_defaults(func=lambda a: _cmd_action(a, "stop"))

    sub.add_parser("restart")
    sub.choices["restart"].set_defaults(
        func=lambda a: _cmd_action(a, "restart"))

    sub.add_parser("status")
    sub.choices["status"].set_defaults(func=_cmd_status)

    sub.add_parser("debug")
    sub.choices["debug"].set_defaults(func=_cmd_debug)

    sub.add_parser("_run_runner")
    sub.choices["_run_runner"].set_defaults(func=_cmd_run_runner)

    # Windows Service (pywin32)
    sub.add_parser("install-service",
                   help="установить Windows-службу (pywin32)")
    sub.choices["install-service"].set_defaults(func=_cmd_install_service)

    sub.add_parser("remove-service")
    sub.choices["remove-service"].set_defaults(func=_cmd_remove_service)

    sub.add_parser("start-service")
    sub.choices["start-service"].set_defaults(func=_cmd_start_service)

    sub.add_parser("stop-service")
    sub.choices["stop-service"].set_defaults(func=_cmd_stop_service)

    sub.add_parser("restart-service")
    sub.choices["restart-service"].set_defaults(func=_cmd_restart_service)

    sub.add_parser("status-service")
    sub.choices["status-service"].set_defaults(func=_cmd_status_service)

    sub.add_parser("debug-service",
                   help="запустить логику службы в консоли")
    sub.choices["debug-service"].set_defaults(func=_cmd_debug_service)

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    _setup_log(args.verbose)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
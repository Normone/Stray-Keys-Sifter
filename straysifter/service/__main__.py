"""Управление сервисом: python -m straysifter.service <cmd>."""
from __future__ import annotations

import argparse
import logging
import sys

IS_WINDOWS = sys.platform.startswith("win")


def _backend():
    if IS_WINDOWS:
        from . import daemon_windows
        return daemon_windows
    from . import daemon_posix
    return daemon_posix


def _setup_log(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


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


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="straysifter.service",
        description="Управление сервисом straysifter.",
    )
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("install").set_defaults(func=_cmd_install)
    sub.add_parser("uninstall").set_defaults(func=_cmd_uninstall)
    sub.add_parser("start").set_defaults(func=lambda a: _cmd_action(a, "start"))
    sub.add_parser("stop").set_defaults(func=lambda a: _cmd_action(a, "stop"))
    sub.add_parser("restart").set_defaults(func=lambda a: _cmd_action(a, "restart"))
    sub.add_parser("status").set_defaults(func=_cmd_status)
    sub.add_parser("debug").set_defaults(func=_cmd_debug)
    sub.add_parser("_run_runner").set_defaults(func=_cmd_run_runner)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    _setup_log(args.verbose)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
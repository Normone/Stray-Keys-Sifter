"""Stray Keys Sifter — сборщик и TCP-отсев публичных VPN-ключей."""
import logging

__version__ = "2.1.0"

# urllib3 в DEBUG-режиме сыпет строкой на каждый HTTP-запрос.
# Наши логи с -v читать невозможно. Гасим его отдельно, наш
# пакет продолжает писать DEBUG.
logging.getLogger("urllib3").setLevel(logging.WARNING)
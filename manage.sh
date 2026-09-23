#!/usr/bin/env bash
# straysifter — control panel для Linux/macOS.

set -e
cd "$(dirname "$0")"

PY="${PYTHON:-python3}"
if ! command -v "$PY" >/dev/null 2>&1; then
    PY=python
fi

pause() {
    read -rp "Enter для продолжения..." _
}

svc() {
    "$PY" -m straysifter.service "$@"
}

open_path() {
    local p="$1"
    if [ ! -e "$p" ]; then
        echo "не найдено: $p"
        pause
        return
    fi
    xdg-open "$p" 2>/dev/null || open "$p" 2>/dev/null || \
        echo "откройте вручную: $(pwd)/$p"
}

menu() {
    clear
    cat <<'EOF'

  =========================================
   straysifter - control panel
  =========================================

   -- Запуск --
   1. Полный цикл (fetch + check + export)
   2. Быстрый цикл (без geoip)
   3. Только fetch источников
   4. Статистика источников
   5. Экспорт БД в checked.txt
   6. Экспорт одного источника
   7. Статус базы
   8. История прогонов
   9. Очистить базу / историю / статистику

   -- GeoIP --
   G. Скачать DB-IP mmdb
   H. Очистить geoip-кэш

   -- Конфиг --
   A. Показать config.json
   E. Редактировать config.json

   -- Сервис в фоне --
   I. Установить / переустановить
   J. Запустить
   K. Остановить
   L. Перезапустить
   M. Статус сервиса
   N. Удалить сервис

   -- Просмотр --
   O. Лог в реальном времени (Ctrl+C - выход)
   P. Открыть папку data
   Q. Открыть exports
   R. Открыть checked.txt

   0. Выход

  =========================================

EOF
    read -rp "Выбор [0-9/A-R]: " CH
    case "$CH" in
        0) exit 0 ;;
        1) clear; "$PY" -m straysifter -v collect; pause ;;
        2) clear; "$PY" -m straysifter -v collect --no-geoip; pause ;;
        3) clear; "$PY" -m straysifter -v sources; pause ;;
        4) clear; "$PY" -m straysifter sources-stats; pause ;;
        5) clear; "$PY" -m straysifter export; pause ;;
        6) clear
           read -rp "Часть URL источника (напр. update): " PAT
           if [ -n "$PAT" ]; then
               "$PY" -m straysifter export-source "$PAT"
           fi
           pause ;;
        7) clear; "$PY" -m straysifter status; pause ;;
        8) clear; "$PY" -m straysifter history; pause ;;
        9) clear
           read -rp "Очистить [W]orking / [H]istory / [S]ource-stats / [B]oth / [N]othing: " X
           case "$X" in
               [Ww]) "$PY" -m straysifter clean --working ;;
               [Hh]) "$PY" -m straysifter clean --history ;;
               [Ss]) "$PY" -m straysifter clean --sources ;;
               [Bb]) "$PY" -m straysifter clean --working --history --sources ;;
           esac
           pause ;;
        [Gg]) clear; "$PY" -m straysifter geoip-update; pause ;;
        [Hh]) clear
              read -rp "Очистить geoip-кэш? [Y/N]: " Y
              if [ "${Y,,}" = "y" ]; then
                  "$PY" -m straysifter geoip-clear
              fi
              pause ;;
        [Aa]) clear
              if [ -f config.json ]; then cat config.json; else echo "config.json не найден"; fi
              pause ;;
        [Ee]) clear
              if [ ! -f config.json ]; then
                  echo "config.json не найден. Сначала пункт I."
                  pause
              else
                  "${EDITOR:-nano}" config.json
                  pause
              fi ;;
        [Ii]) clear; svc install; pause ;;
        [Jj]) clear; svc start; pause ;;
        [Kk]) clear; svc stop; pause ;;
        [Ll]) clear; svc restart; pause ;;
        [Mm]) clear; svc status; pause ;;
        [Nn]) clear
              read -rp "Удалить сервис (stop + pid)? Данные и конфиг не тронутся. [Y/N]: " Y
              if [ "${Y,,}" = "y" ]; then
                  svc uninstall
              fi
              pause ;;
        [Oo]) clear
              if [ ! -f straysifter.log ]; then
                  echo "straysifter.log не найден. Запустите сервис (пункт J)."
                  pause
              else
                  echo "Смотрим straysifter.log. Ctrl+C - выход."
                  tail -f straysifter.log
                  pause
              fi ;;
        [Pp]) open_path data ;;
        [Qq]) open_path data/exports ;;
        [Rr]) if [ -f data/exports/checked.txt ]; then
                  "${EDITOR:-less}" data/exports/checked.txt
              else
                  clear
                  echo "checked.txt не создан. Запустите цикл (пункт 1)."
                  pause
              fi ;;
        *) echo "Неизвестный выбор"; sleep 1 ;;
    esac
    menu
}

menu
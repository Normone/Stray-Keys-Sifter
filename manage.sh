#!/usr/bin/env bash
# straysifter — control panel for Linux/macOS.

set -e
cd "$(dirname "$0")"

PY="${PYTHON:-python3}"
if ! command -v "$PY" >/dev/null 2>&1; then
    PY=python
fi

pause_screen() {
    read -rp "Press Enter to continue..." _
}

svc() {
    "$PY" -m straysifter.service "$@"
}

open_path() {
    local p="$1"
    if [ ! -e "$p" ]; then
        echo "not found: $p"
        pause_screen
        return
    fi
    xdg-open "$p" 2>/dev/null || open "$p" 2>/dev/null || \
        echo "open manually: $(pwd)/$p"
}

set_mode() {
    echo "Current:"
    "$PY" -m straysifter config-show checks.mode || true
    echo
    echo "Choose new mode:"
    echo "  1. tcp        (fast, wide list)"
    echo "  2. tcp+tls    (TCP + TLS handshake, cleaner)"
    echo "  3. singbox    (real HTTP via tunnel, slow, accurate)"
    echo "  0. Cancel"
    read -rp "Choice [0-3]: " M
    case "$M" in
        1) MODE=tcp ;;
        2) MODE=tcp+tls ;;
        3) MODE=singbox ;;
        *) return ;;
    esac
    "$PY" -m straysifter config-set checks.mode "$MODE"
    echo
    read -rp "Restart service now? [Y/N]: " Y
    case "$Y" in
        [Yy]) svc restart ;;
    esac
    pause_screen
}

service_menu() {
    while true; do
        clear
        cat <<'EOF'

  =========================================
   straysifter - service
  =========================================

   1. Install / reinstall
   2. Start
   3. Stop
   4. Restart
   5. Service status
   6. Uninstall service
   7. Set service mode (tcp / tcp+tls / singbox)

   0. Back to main

  =========================================

EOF
        read -rp "Choice: " CH
        case "$CH" in
            0) return ;;
            1) svc install; pause_screen ;;
            2) svc start; pause_screen ;;
            3) svc stop; pause_screen ;;
            4) svc restart; pause_screen ;;
            5) svc status; pause_screen ;;
            6) read -rp "Uninstall service? Data and config are NOT touched. [Y/N]: " Y
               case "$Y" in
                   [Yy]) svc uninstall; pause_screen ;;
               esac ;;
            7) set_mode ;;
            *) echo "Unknown choice"; sleep 1 ;;
        esac
    done
}

view_menu() {
    while true; do
        clear
        cat <<'EOF'

  =========================================
   straysifter - view
  =========================================

   1. Live log (Ctrl+C to exit)
   2. Open data folder
   3. Open exports folder
   4. Open checked.txt

   0. Back to main

  =========================================

EOF
        read -rp "Choice: " CH
        case "$CH" in
            0) return ;;
            1) if [ ! -f straysifter.log ]; then
                   echo "straysifter.log not found."
                   pause_screen
               else
                   echo "Watching straysifter.log. Ctrl+C to exit."
                   tail -f straysifter.log
               fi ;;
            2) open_path data ;;
            3) open_path data/exports ;;
            4) if [ -f data/exports/checked.txt ]; then
                   "${EDITOR:-less}" data/exports/checked.txt
               else
                   echo "checked.txt not created."
                   pause_screen
               fi ;;
            *) echo "Unknown choice"; sleep 1 ;;
        esac
    done
}

main_menu() {
    while true; do
        clear
        cat <<'EOF'

  =========================================
   straysifter - control panel
  =========================================

   -- Run --
   1. Collect keys (fetch + TCP check + export)
   2. Collect keys (fetch + sing-box check + export)
   3. Inspect a source
   4. Fetch sources only
   5. Source stats
   6. Export DB to checked.txt
   7. Export one source
   8. DB status
   9. History
   C. Clear DB / history / stats

   -- GeoIP --
   G. Update mmdb
   H. Clear geoip cache

   S. Service menu
   V. View menu

   0. Exit

  =========================================

EOF
        read -rp "Choice: " CH
        case "$CH" in
            0) exit 0 ;;
            1) clear; "$PY" -m straysifter -v collect; pause_screen ;;
            2) clear; "$PY" -m straysifter -v collect --mode singbox; pause_screen ;;
            3) clear
               read -rp "Part of source URL (e.g. update): " PAT
               if [ -n "$PAT" ]; then
                   "$PY" -m straysifter -v inspect "$PAT"
                   pause_screen
               fi ;;
            4) clear; "$PY" -m straysifter -v sources; pause_screen ;;
            5) clear; "$PY" -m straysifter sources-stats; pause_screen ;;
            6) clear; "$PY" -m straysifter export; pause_screen ;;
            7) clear
               read -rp "Part of source URL (e.g. update): " PAT
               if [ -n "$PAT" ]; then
                   "$PY" -m straysifter export-source "$PAT"
                   pause_screen
               fi ;;
            8) clear; "$PY" -m straysifter status; pause_screen ;;
            9) clear; "$PY" -m straysifter history; pause_screen ;;
            [Cc]) clear
                  read -rp "Clear [W]orking / [H]istory / [S]ource-stats / [B]oth / [N]othing: " X
                  case "$X" in
                      [Ww]) "$PY" -m straysifter clean --working ;;
                      [Hh]) "$PY" -m straysifter clean --history ;;
                      [Ss]) "$PY" -m straysifter clean --sources ;;
                      [Bb]) "$PY" -m straysifter clean --working --history --sources ;;
                  esac
                  pause_screen ;;
            [Gg]) clear; "$PY" -m straysifter geoip-update; pause_screen ;;
            [Hh]) clear
                  read -rp "Clear geoip cache? [Y/N]: " Y
                  case "$Y" in
                      [Yy]) "$PY" -m straysifter geoip-clear ;;
                  esac
                  pause_screen ;;
            [Ss]) service_menu ;;
            [Vv]) view_menu ;;
            *) echo "Unknown choice"; sleep 1 ;;
        esac
    done
}

main_menu
#!/usr/bin/env bash
# straysifter — control panel for Linux/macOS.

set -e
cd "$(dirname "$0")"

PY="${PYTHON:-python3}"
if ! command -v "$PY" >/dev/null 2>&1; then
    PY=python
fi

pause() {
    read -rp "Press Enter to continue..." _
}

svc() {
    "$PY" -m straysifter.service "$@"
}

open_path() {
    local p="$1"
    if [ ! -e "$p" ]; then
        echo "not found: $p"
        pause
        return
    fi
    xdg-open "$p" 2>/dev/null || open "$p" 2>/dev/null || \
        echo "open manually: $(pwd)/$p"
}

menu() {
    clear
    cat <<'EOF'

  =========================================
   straysifter - control panel
  =========================================

   -- Run --
   1. Collect keys (fetch + check + export)
   2. Inspect a source
   3. Fetch sources only
   4. Source stats
   5. Export DB to checked.txt
   6. Export one source
   7. DB status
   8. History
   9. Clear DB / history / stats

   -- GeoIP --
   G. Update mmdb
   H. Clear geoip cache

   -- Config --
   A. Show config.json
   E. Edit config.json

   -- Service --
   I. Install / reinstall
   J. Start
   K. Stop
   L. Restart
   M. Service status
   N. Uninstall service

   -- View --
   O. Live log (Ctrl+C to exit)
   P. Open data folder
   Q. Open exports folder
   R. Open checked.txt

   0. Exit

  =========================================

EOF
    read -rp "Choice [0-9/A-R]: " CH
    case "$CH" in
        0) exit 0 ;;
        1) clear; "$PY" -m straysifter -v collect; pause ;;
        2) clear
           read -rp "Part of source URL (e.g. update): " PAT
           if [ -n "$PAT" ]; then
               "$PY" -m straysifter inspect "$PAT"
           fi
           pause ;;
        3) clear; "$PY" -m straysifter -v sources; pause ;;
        4) clear; "$PY" -m straysifter sources-stats; pause ;;
        5) clear; "$PY" -m straysifter export; pause ;;
        6) clear
           read -rp "Part of source URL (e.g. update): " PAT
           if [ -n "$PAT" ]; then
               "$PY" -m straysifter export-source "$PAT"
           fi
           pause ;;
        7) clear; "$PY" -m straysifter status; pause ;;
        8) clear; "$PY" -m straysifter history; pause ;;
        9) clear
           read -rp "Clear [W]orking / [H]istory / [S]ource-stats / [B]oth / [N]othing: " X
           case "$X" in
               [Ww]) "$PY" -m straysifter clean --working ;;
               [Hh]) "$PY" -m straysifter clean --history ;;
               [Ss]) "$PY" -m straysifter clean --sources ;;
               [Bb]) "$PY" -m straysifter clean --working --history --sources ;;
           esac
           pause ;;
        [Gg]) clear; "$PY" -m straysifter geoip-update; pause ;;
        [Hh]) clear
              read -rp "Clear geoip cache? [Y/N]: " Y
              if [ "${Y,,}" = "y" ]; then
                  "$PY" -m straysifter geoip-clear
              fi
              pause ;;
        [Aa]) clear
              if [ -f config.json ]; then cat config.json; else echo "config.json not found"; fi
              pause ;;
        [Ee]) clear
              if [ ! -f config.json ]; then
                  echo "config.json not found. Run option I first."
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
              read -rp "Uninstall service (stop + pid)? Data and config are NOT touched. [Y/N]: " Y
              if [ "${Y,,}" = "y" ]; then
                  svc uninstall
              fi
              pause ;;
        [Oo]) clear
              if [ ! -f straysifter.log ]; then
                  echo "straysifter.log not found. Start service (option J) first."
                  pause
              else
                  echo "Watching straysifter.log. Ctrl+C to exit."
                  tail -f straysifter.log
                  pause
              fi ;;
        [Pp]) open_path data ;;
        [Qq]) open_path data/exports ;;
        [Rr]) if [ -f data/exports/checked.txt ]; then
                  "${EDITOR:-less}" data/exports/checked.txt
              else
                  clear
                  echo "checked.txt not created. Run a cycle (option 1)."
                  pause
              fi ;;
        *) echo "Unknown choice"; sleep 1 ;;
    esac
    menu
}

menu
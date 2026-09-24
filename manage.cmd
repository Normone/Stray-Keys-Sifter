@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"
goto MAIN


:MAIN
cls
echo.
echo  =========================================
echo   straysifter - control panel
echo  =========================================
echo.
echo   -- Run --
echo   1. Collect keys (fetch + TCP check + export)
echo   2. Collect keys (fetch + sing-box check + export)
echo   3. Inspect a source
echo   4. Fetch sources only
echo   5. Source stats
echo   6. Export DB to checked.txt
echo   7. Export one source
echo   8. DB status
echo   9. History
echo   C. Clear DB / history / stats
echo.
echo   -- GeoIP --
echo   G. Update mmdb
echo   H. Clear geoip cache
echo.
echo   S. Service menu
echo   V. View menu
echo.
echo   0. Exit
echo.
echo  =========================================
echo.
set "CH="
set /p "CH=Choice: "

if "!CH!"=="" goto MAIN
if "!CH!"=="0" exit /b
if "!CH!"=="1" goto COLLECT_TCP
if "!CH!"=="2" goto COLLECT_SINGBOX
if "!CH!"=="3" goto INSPECT
if "!CH!"=="4" goto SOURCES
if "!CH!"=="5" goto SOURCES_STATS
if "!CH!"=="6" goto EXPORT
if "!CH!"=="7" goto EXPORT_SOURCE
if "!CH!"=="8" goto STATUS
if "!CH!"=="9" goto HISTORY
if /i "!CH!"=="C" goto CLEAN
if /i "!CH!"=="G" goto GEOIP_UPDATE
if /i "!CH!"=="H" goto GEOIP_CLEAR
if /i "!CH!"=="S" goto SVC_MENU
if /i "!CH!"=="V" goto VIEW_MENU

echo  Unknown choice.
timeout /t 1 >nul
goto MAIN


:SVC_MENU
cls
echo.
echo  =========================================
echo   straysifter - service
echo  =========================================
echo.
echo   1. Install / reinstall
echo   2. Start
echo   3. Stop
echo   4. Restart
echo   5. Service status
echo   6. Uninstall service
echo   7. Set service mode (tcp / tcp+tls / singbox)
echo.
echo   0. Back to main
echo.
echo  =========================================
echo.
set "CH="
set /p "CH=Choice: "

if "!CH!"=="" goto SVC_MENU
if "!CH!"=="0" goto MAIN
if "!CH!"=="1" goto SVC_INSTALL
if "!CH!"=="2" goto SVC_START
if "!CH!"=="3" goto SVC_STOP
if "!CH!"=="4" goto SVC_RESTART
if "!CH!"=="5" goto SVC_STATUS
if "!CH!"=="6" goto SVC_UNINSTALL
if "!CH!"=="7" goto SET_MODE

echo  Unknown choice.
timeout /t 1 >nul
goto SVC_MENU


:VIEW_MENU
cls
echo.
echo  =========================================
echo   straysifter - view
echo  =========================================
echo.
echo   1. Live log (Ctrl+C to exit)
echo   2. Open data folder
echo   3. Open exports folder
echo   4. Open checked.txt
echo.
echo   0. Back to main
echo.
echo  =========================================
echo.
set "CH="
set /p "CH=Choice: "

if "!CH!"=="" goto VIEW_MENU
if "!CH!"=="0" goto MAIN
if "!CH!"=="1" goto WATCH_LOG
if "!CH!"=="2" goto OPEN_DATA
if "!CH!"=="3" goto OPEN_EXPORTS
if "!CH!"=="4" goto OPEN_CHECKED

echo  Unknown choice.
timeout /t 1 >nul
goto VIEW_MENU


:COLLECT_TCP
cls
echo  Collect keys via TCP: fetch + TCP check + GeoIP + export.
echo  Fast, wide list. 3-7 minutes.
echo.
python -m straysifter -v collect
goto MAIN

:COLLECT_SINGBOX
cls
echo  Collect keys via sing-box: fetch + real HTTP check + GeoIP + export.
echo  Slow, narrow list. Hours. Requires bin/sing-box/sing-box.exe.
echo.
python -m straysifter -v collect --mode singbox
goto MAIN

:INSPECT
cls
echo  Inspect a source: parsed counts, schemes, endpoints.
echo  Enter part of source URL (e.g. "update" or "whitelist"):
echo.
set "PAT="
set /p "PAT=Source: "
if "!PAT!"=="" goto MAIN
python -m straysifter -v inspect "!PAT!"
goto MAIN

:SOURCES
cls
echo  Fetch sources into archive, without checks.
echo.
python -m straysifter -v sources
goto MAIN

:SOURCES_STATS
cls
python -m straysifter sources-stats
goto MAIN

:EXPORT
cls
python -m straysifter export
goto MAIN

:EXPORT_SOURCE
cls
echo  Export single source (alive + all).
echo  Enter part of source URL (e.g. "update" or "whitelist"):
echo.
set "PAT="
set /p "PAT=Source: "
if "!PAT!"=="" goto MAIN
python -m straysifter export-source "!PAT!"
goto MAIN

:STATUS
cls
python -m straysifter status
goto MAIN

:HISTORY
cls
python -m straysifter history
goto MAIN

:CLEAN
cls
echo  What to clear?
echo   W - working DB
echo   H - history
echo   S - source stats
echo   B - all of the above
echo   N - nothing
set "X="
set /p "X=Choice [W/H/S/B/N]: "
if /i "!X!"=="W" python -m straysifter clean --working
if /i "!X!"=="H" python -m straysifter clean --history
if /i "!X!"=="S" python -m straysifter clean --sources
if /i "!X!"=="B" python -m straysifter clean --working --history --sources
goto MAIN


:GEOIP_UPDATE
cls
echo  Download mmdb for offline GeoIP (GitHub mirrors, then db-ip.com).
echo.
python -m straysifter geoip-update
goto MAIN

:GEOIP_CLEAR
cls
echo  Clear geoip cache (data/geoip_cache.json).
set "Y="
set /p "Y=Confirm [Y/N]: "
if /i "!Y!"=="Y" python -m straysifter geoip-clear
goto MAIN


:SVC_INSTALL
cls
python -m straysifter.service install
goto SVC_MENU

:SVC_START
cls
python -m straysifter.service start
goto SVC_MENU

:SVC_STOP
cls
python -m straysifter.service stop
goto SVC_MENU

:SVC_RESTART
cls
python -m straysifter.service restart
goto SVC_MENU

:SVC_STATUS
cls
python -m straysifter.service status
goto SVC_MENU

:SVC_UNINSTALL
cls
echo  Uninstall service (stop + remove pid file).
echo  Data and config.json are NOT touched.
set "Y="
set /p "Y=Confirm [Y/N]: "
if /i "!Y!"=="Y" (
    python -m straysifter.service uninstall
)
goto SVC_MENU

:SET_MODE
cls
echo  Set service check mode.
echo.
echo   Current:
python -m straysifter config-show checks.mode
echo.
echo   Choose new mode:
echo     1. tcp        (fast, wide list)
echo     2. tcp+tls    (TCP + TLS handshake, cleaner)
echo     3. singbox    (real HTTP via tunnel, slow, accurate)
echo     0. Cancel
echo.
set "M="
set /p "M=Choice [0-3]: "
if "!M!"=="" goto SVC_MENU
if "!M!"=="0" goto SVC_MENU
if "!M!"=="1" set "MODE=tcp"
if "!M!"=="2" set "MODE=tcp+tls"
if "!M!"=="3" set "MODE=singbox"
if not defined MODE (
    echo  Unknown choice.
    timeout /t 1 >nul
    goto SVC_MENU
)
python -m straysifter config-set checks.mode !MODE!
echo.
set "Y="
set /p "Y=Restart service now? [Y/N]: "
if /i "!Y!"=="Y" python -m straysifter.service restart
set "MODE="
goto SVC_MENU


:WATCH_LOG
cls
if not exist straysifter.log (
    echo  straysifter.log not found.
    echo  Start service (Service menu - 2) or run a cycle (option 1) first.
    goto VIEW_MENU
)
echo  Watching straysifter.log. Ctrl+C to exit.
echo.
powershell -NoProfile -Command "Get-Content straysifter.log -Tail 30 -Wait"
goto VIEW_MENU

:OPEN_DATA
if exist data (
    start "" explorer "%~dp0data"
    goto VIEW_MENU
)
cls
echo  data folder does not exist. Run a cycle (option 1) first.
goto VIEW_MENU

:OPEN_EXPORTS
if exist data\exports (
    start "" explorer "%~dp0data\exports"
    goto VIEW_MENU
)
cls
echo  data\exports does not exist.
goto VIEW_MENU

:OPEN_CHECKED
if exist data\exports\checked.txt (
    start "" notepad "%~dp0data\exports\checked.txt"
    goto VIEW_MENU
)
cls
echo  checked.txt not created yet.
echo  Run a cycle (option 1) or export (option 6).
goto VIEW_MENU
@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"

:MENU
cls
echo.
echo  =========================================
echo   straysifter - control panel
echo  =========================================
echo.
echo   -- Run --
echo   1. Full cycle (fetch + check + export)
echo   2. Fast cycle (no geoip)
echo   3. Fetch sources only
echo   4. Source stats
echo   5. Export DB to checked.txt
echo   6. Export one source
echo   7. DB status
echo   8. History
echo   9. Clear DB / history / stats
echo.
echo   -- GeoIP --
echo   G. Update DB-IP mmdb
echo   H. Clear geoip cache
echo.
echo   -- Config --
echo   A. Show config.json
echo   E. Edit config.json
echo.
echo   -- Service --
echo   I. Install / reinstall
echo   J. Start
echo   K. Stop
echo   L. Restart
echo   M. Service status
echo   N. Uninstall service
echo.
echo   -- View --
echo   O. Live log (Ctrl+C to exit)
echo   P. Open data folder
echo   Q. Open exports folder
echo   R. Open checked.txt
echo.
echo   0. Exit
echo.
echo  =========================================
echo.
set "CH="
set /p "CH=Choice [0-9/A-R]: "

if "!CH!"=="" goto MENU
if "!CH!"=="0" exit /b
if "!CH!"=="1" goto COLLECT
if "!CH!"=="2" goto COLLECT_FAST
if "!CH!"=="3" goto SOURCES
if "!CH!"=="4" goto SOURCES_STATS
if "!CH!"=="5" goto EXPORT
if "!CH!"=="6" goto EXPORT_SOURCE
if "!CH!"=="7" goto STATUS
if "!CH!"=="8" goto HISTORY
if "!CH!"=="9" goto CLEAN
if /i "!CH!"=="G" goto GEOIP_UPDATE
if /i "!CH!"=="H" goto GEOIP_CLEAR
if /i "!CH!"=="A" goto SHOW_CONFIG
if /i "!CH!"=="E" goto EDIT_CONFIG
if /i "!CH!"=="I" goto SVC_INSTALL
if /i "!CH!"=="J" goto SVC_START
if /i "!CH!"=="K" goto SVC_STOP
if /i "!CH!"=="L" goto SVC_RESTART
if /i "!CH!"=="M" goto SVC_STATUS
if /i "!CH!"=="N" goto SVC_UNINSTALL
if /i "!CH!"=="O" goto WATCH_LOG
if /i "!CH!"=="P" goto OPEN_DATA
if /i "!CH!"=="Q" goto OPEN_EXPORTS
if /i "!CH!"=="R" goto OPEN_CHECKED

echo  Unknown choice.
timeout /t 1 > nul
goto MENU


:COLLECT
cls
echo  Full cycle: fetch + TCP + GeoIP + export. 3-7 minutes.
echo.
pause
python -m straysifter -v collect
echo.
pause
goto MENU

:COLLECT_FAST
cls
echo  Fast cycle: без GeoIP. 2-5 minutes.
echo.
pause
python -m straysifter -v collect --no-geoip
echo.
pause
goto MENU

:SOURCES
cls
echo  Fetch sources into archive, без проверок.
echo.
pause
python -m straysifter -v sources
echo.
pause
goto MENU

:SOURCES_STATS
cls
python -m straysifter sources-stats
echo.
pause
goto MENU

:EXPORT
cls
python -m straysifter export
echo.
pause
goto MENU

:EXPORT_SOURCE
cls
echo  Export single source (alive + all).
echo  Enter part of source URL (e.g. "update" or "whitelist"):
echo.
set "PAT="
set /p "PAT=Source: "
if "!PAT!"=="" goto MENU
python -m straysifter export-source "!PAT!"
echo.
pause
goto MENU

:STATUS
cls
python -m straysifter status
echo.
pause
goto MENU

:HISTORY
cls
python -m straysifter history
echo.
pause
goto MENU

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
echo.
pause
goto MENU


:GEOIP_UPDATE
cls
echo  Download DB-IP Lite mmdb for offline GeoIP.
echo.
python -m straysifter geoip-update
echo.
pause
goto MENU

:GEOIP_CLEAR
cls
echo  Clear geoip cache (data/geoip_cache.json).
set "Y="
set /p "Y=Confirm [Y/N]: "
if /i "!Y!"=="Y" python -m straysifter geoip-clear
echo.
pause
goto MENU


:SHOW_CONFIG
cls
if exist config.json (
    type config.json
) else (
    echo  config.json not found. Run option I first.
)
echo.
pause
goto MENU

:EDIT_CONFIG
cls
if not exist config.json (
    echo  config.json not found. Run option I first.
    echo.
    pause
    goto MENU
)
echo  Opening config.json in Notepad.
echo  After saving - restart service (option L).
echo.
start "" notepad "config.json"
pause
goto MENU


:SVC_INSTALL
cls
python -m straysifter.service install
echo.
pause
goto MENU

:SVC_START
cls
python -m straysifter.service start
echo.
pause
goto MENU

:SVC_STOP
cls
python -m straysifter.service stop
echo.
pause
goto MENU

:SVC_RESTART
cls
python -m straysifter.service restart
echo.
pause
goto MENU

:SVC_STATUS
cls
python -m straysifter.service status
echo.
pause
goto MENU

:SVC_UNINSTALL
cls
echo  Uninstall service (stop + remove pid file).
echo  Data and config.json are NOT touched.
set "Y="
set /p "Y=Confirm [Y/N]: "
if /i "!Y!"=="Y" (
    python -m straysifter.service uninstall
)
echo.
pause
goto MENU


:WATCH_LOG
cls
if not exist straysifter.log (
    echo  straysifter.log not found.
    echo  Start service (option J) or run a cycle (option 1) first.
    echo.
    pause
    goto MENU
)
echo  Watching straysifter.log. Ctrl+C to exit.
echo.
powershell -NoProfile -Command "Get-Content straysifter.log -Tail 30 -Wait"
echo.
pause
goto MENU

:OPEN_DATA
if exist data (
    start "" explorer "%~dp0data"
    goto MENU
)
cls
echo  data folder does not exist. Run a cycle (option 1) first.
echo.
pause
goto MENU

:OPEN_EXPORTS
if exist data\exports (
    start "" explorer "%~dp0data\exports"
    goto MENU
)
cls
echo  data\exports does not exist.
echo.
pause
goto MENU

:OPEN_CHECKED
if exist data\exports\checked.txt (
    start "" notepad "%~dp0data\exports\checked.txt"
    goto MENU
)
cls
echo  checked.txt not created yet.
echo  Run a cycle (option 1) or export (option 5).
echo.
pause
goto MENU
@echo off
setlocal enabledelayedexpansion

REM Если перезапущено с UAC — флаг --admin, стартуем сразу в меню.
if "%~1"=="--admin" (
    shift
)

cd /d "%~dp0"
goto MAIN


REM ── Проверка прав ─────────────────────────────────────────────
:IS_ADMIN
net session >nul 2>&1
exit /b %errorlevel%

:REQUIRE_ADMIN
call :IS_ADMIN
if %errorlevel%==0 exit /b 0
echo.
echo  This action requires administrator rights.
echo.
set "Y="
set /p "Y=Restart manage.cmd as admin? [Y/N]: "
if /i not "!Y!"=="Y" exit /b 1
echo  Launching elevated copy...
powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -ArgumentList '--admin' -Verb RunAs"
exit /b 2


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
echo   -- Background --
echo   F. Set check mode (tcp / tcp+tls / singbox)
echo   S. Daemon menu (old, detached)
echo   W. Windows Service menu (pywin32, SCM)
echo.
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
if /i "!CH!"=="F" goto SET_MODE
if /i "!CH!"=="S" goto DAEMON_MENU
if /i "!CH!"=="W" goto SERVICE_MENU
if /i "!CH!"=="V" goto VIEW_MENU

echo  Unknown choice.
timeout /t 1 >nul
goto MAIN


:DAEMON_MENU
cls
echo.
echo  =========================================
echo   straysifter - daemon (old, detached)
echo  =========================================
echo.
echo   1. Install
echo   2. Start
echo   3. Stop
echo   4. Restart
echo   5. Status
echo   6. Uninstall
echo.
echo   0. Back to main
echo.
echo  =========================================
echo.
set "CH="
set /p "CH=Choice: "

if "!CH!"=="" goto DAEMON_MENU
if "!CH!"=="0" goto MAIN
if "!CH!"=="1" goto D_INSTALL
if "!CH!"=="2" goto D_START
if "!CH!"=="3" goto D_STOP
if "!CH!"=="4" goto D_RESTART
if "!CH!"=="5" goto D_STATUS
if "!CH!"=="6" goto D_UNINSTALL

echo  Unknown choice.
timeout /t 1 >nul
goto DAEMON_MENU


:SERVICE_MENU
cls
echo.
echo  =========================================
echo   straysifter - Windows Service (pywin32)
echo  =========================================
echo.
echo   1. Install service     (admin)
echo   2. Start service       (admin)
echo   3. Stop service        (admin)
echo   4. Restart service     (admin)
echo   5. Service status      (SCM)
echo   6. Remove service      (admin)
echo.
echo   0. Back to main
echo.
echo  =========================================
echo.
set "CH="
set /p "CH=Choice: "

if "!CH!"=="" goto SERVICE_MENU
if "!CH!"=="0" goto MAIN
if "!CH!"=="1" goto W_INSTALL
if "!CH!"=="2" goto W_START
if "!CH!"=="3" goto W_STOP
if "!CH!"=="4" goto W_RESTART
if "!CH!"=="5" goto W_STATUS
if "!CH!"=="6" goto W_REMOVE

echo  Unknown choice.
timeout /t 1 >nul
goto SERVICE_MENU


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
echo.
pause
goto MAIN

:COLLECT_SINGBOX
cls
echo  Collect keys via sing-box: fetch + real HTTP check + GeoIP + export.
echo  Slow, narrow list. Hours. Requires bin/sing-box/sing-box.exe.
echo.
python -m straysifter -v collect --mode singbox
echo.
pause
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
echo.
pause
goto MAIN

:SOURCES
cls
echo  Fetch sources into archive, without checks.
echo.
python -m straysifter -v sources
echo.
pause
goto MAIN

:SOURCES_STATS
cls
python -m straysifter sources-stats
echo.
pause
goto MAIN

:EXPORT
cls
python -m straysifter export
echo.
pause
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
echo.
pause
goto MAIN

:STATUS
cls
python -m straysifter status
echo.
pause
goto MAIN

:HISTORY
cls
python -m straysifter history
echo.
pause
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
echo.
pause
goto MAIN


:GEOIP_UPDATE
cls
echo  Download mmdb for offline GeoIP (GitHub mirrors, then db-ip.com).
echo.
python -m straysifter geoip-update
echo.
pause
goto MAIN

:GEOIP_CLEAR
cls
echo  Clear geoip cache (data/geoip_cache.json).
set "Y="
set /p "Y=Confirm [Y/N]: "
if /i "!Y!"=="Y" python -m straysifter geoip-clear
echo.
pause
goto MAIN


:SET_MODE
cls
echo  Set check mode.
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
if "!M!"=="" goto MAIN
if "!M!"=="0" goto MAIN
if "!M!"=="1" set "MODE=tcp"
if "!M!"=="2" set "MODE=tcp+tls"
if "!M!"=="3" set "MODE=singbox"
if not defined MODE (
    echo  Unknown choice.
    timeout /t 1 >nul
    goto MAIN
)
python -m straysifter config-set checks.mode !MODE!
set "MODE="
echo.
pause
goto MAIN


:D_INSTALL
cls
python -m straysifter.service install
echo.
pause
goto DAEMON_MENU

:D_START
cls
python -m straysifter.service start
echo.
pause
goto DAEMON_MENU

:D_STOP
cls
python -m straysifter.service stop
echo.
pause
goto DAEMON_MENU

:D_RESTART
cls
python -m straysifter.service restart
echo.
pause
goto DAEMON_MENU

:D_STATUS
cls
python -m straysifter.service status
echo.
pause
goto DAEMON_MENU

:D_UNINSTALL
cls
echo  Uninstall daemon (stop + remove pid file).
echo  Data and config.json are NOT touched.
set "Y="
set /p "Y=Confirm [Y/N]: "
if /i "!Y!"=="Y" (
    python -m straysifter.service uninstall
)
echo.
pause
goto DAEMON_MENU


:W_INSTALL
cls
call :REQUIRE_ADMIN
if errorlevel 2 exit /b
if errorlevel 1 goto SERVICE_MENU
python -m straysifter.service install-service
echo.
pause
goto SERVICE_MENU

:W_START
cls
call :REQUIRE_ADMIN
if errorlevel 2 exit /b
if errorlevel 1 goto SERVICE_MENU
python -m straysifter.service start-service
echo.
pause
goto SERVICE_MENU

:W_STOP
cls
call :REQUIRE_ADMIN
if errorlevel 2 exit /b
if errorlevel 1 goto SERVICE_MENU
python -m straysifter.service stop-service
echo.
pause
goto SERVICE_MENU

:W_RESTART
cls
call :REQUIRE_ADMIN
if errorlevel 2 exit /b
if errorlevel 1 goto SERVICE_MENU
python -m straysifter.service restart-service
echo.
pause
goto SERVICE_MENU

:W_STATUS
cls
python -m straysifter.service status-service
echo.
pause
goto SERVICE_MENU

:W_REMOVE
cls
echo  Remove Windows Service (via SCM).
echo  Data and config.json are NOT touched.
set "Y="
set /p "Y=Confirm [Y/N]: "
if /i not "!Y!"=="Y" goto SERVICE_MENU
call :REQUIRE_ADMIN
if errorlevel 2 exit /b
if errorlevel 1 goto SERVICE_MENU
python -m straysifter.service remove-service
echo.
pause
goto SERVICE_MENU


:WATCH_LOG
cls
if not exist straysifter.log (
    echo  straysifter.log not found.
    echo  Start any background service first.
    echo.
    pause
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
echo.
pause
goto VIEW_MENU

:OPEN_EXPORTS
if exist data\exports (
    start "" explorer "%~dp0data\exports"
    goto VIEW_MENU
)
cls
echo  data\exports does not exist.
echo.
pause
goto VIEW_MENU

:OPEN_CHECKED
if exist data\exports\checked.txt (
    start "" notepad "%~dp0data\exports\checked.txt"
    goto VIEW_MENU
)
cls
echo  checked.txt not created yet.
echo  Run a cycle (option 1) or export (option 6).
echo.
pause
goto VIEW_MENU
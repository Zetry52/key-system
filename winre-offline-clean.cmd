@echo off
setlocal EnableExtensions EnableDelayedExpansion

echo.
echo WinRE offline cleanup for the fake taskhost/taskhostw malware tasks
echo.
set "OSDRIVE="
set /p OSDRIVE=Enter the Windows drive letter in WinRE (example C or D): 
if "%OSDRIVE%"=="" set "OSDRIVE=C"
set "OSDRIVE=%OSDRIVE::=%"

if not exist "%OSDRIVE%:\Windows\System32\Config\SOFTWARE" (
    echo.
    echo ERROR: %OSDRIVE%:\Windows\System32\Config\SOFTWARE not found
    echo Check the drive letter and run again.
    pause
    exit /b 1
)

echo.
echo Loading offline SOFTWARE hive...
reg load HKLM\OFFSOFT "%OSDRIVE%:\Windows\System32\Config\SOFTWARE"
if errorlevel 1 (
    echo Failed to load offline SOFTWARE hive.
    pause
    exit /b 1
)

for %%T in (CashClean OnlogonCheck ServiceManager WinlogonCheck CreedMobe) do call :DeleteTask WindowsBackup %%T
call :DeleteTask CreedMobeQ RecoveryHosts

echo.
echo Restoring offline Winlogon and removing common policy blocks...
reg add "HKLM\OFFSOFT\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Shell /t REG_SZ /d explorer.exe /f >nul 2>&1
reg add "HKLM\OFFSOFT\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Userinit /t REG_SZ /d C:\Windows\system32\userinit.exe, /f >nul 2>&1
reg delete "HKLM\OFFSOFT\Microsoft\Windows\CurrentVersion\Run" /v "Realtek HD Audio" /f >nul 2>&1
reg delete "HKLM\OFFSOFT\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v DisableTaskMgr /f >nul 2>&1
reg delete "HKLM\OFFSOFT\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v DisableRegistryTools /f >nul 2>&1
reg delete "HKLM\OFFSOFT\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v DisableCMD /f >nul 2>&1

echo.
echo Removing known malware folders...
if exist "%OSDRIVE%:\ProgramData\ReaItekHD" rd /s /q "%OSDRIVE%:\ProgramData\ReaItekHD"
if exist "%OSDRIVE%:\ProgramData\RealtekHD" rd /s /q "%OSDRIVE%:\ProgramData\RealtekHD"

for /r "%OSDRIVE%:\ProgramData" %%F in (CreedMobe*.bat taskhost.exe taskhostw.exe) do (
    del /f /q "%%F" >nul 2>&1
)

echo.
echo Unloading offline hive...
reg unload HKLM\OFFSOFT >nul 2>&1

echo.
echo Offline cleanup finished.
echo Reboot into normal Windows and test Explorer, Task Manager, and Task Scheduler.
pause
exit /b 0

:DeleteTask
set "FOLDER=%~1"
set "NAME=%~2"
set "TREE=HKLM\OFFSOFT\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Microsoft\Windows\%FOLDER%\%NAME%"
set "TASKID="

echo.
echo Processing %FOLDER%\%NAME%

for /f "tokens=3" %%I in ('reg query "%TREE%" /v Id 2^>nul ^| find /i "Id"') do set "TASKID=%%I"

if defined TASKID (
    echo Found TaskCache id !TASKID!
    for %%K in (Tasks Plain Boot Logon Maintenance Idle Time Calendar Event) do (
        reg delete "HKLM\OFFSOFT\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\%%K\!TASKID!" /f >nul 2>&1
    )
) else (
    echo TaskCache id not found for %FOLDER%\%NAME%
)

reg delete "%TREE%" /f >nul 2>&1

if exist "%OSDRIVE%:\Windows\System32\Tasks\Microsoft\Windows\%FOLDER%\%NAME%" (
    del /f /q "%OSDRIVE%:\Windows\System32\Tasks\Microsoft\Windows\%FOLDER%\%NAME%" >nul 2>&1
    if exist "%OSDRIVE%:\Windows\System32\Tasks\Microsoft\Windows\%FOLDER%\%NAME%" (
        echo WARN: file still present %OSDRIVE%:\Windows\System32\Tasks\Microsoft\Windows\%FOLDER%\%NAME%
    ) else (
        echo OK: file removed %OSDRIVE%:\Windows\System32\Tasks\Microsoft\Windows\%FOLDER%\%NAME%
    )
)

goto :eof

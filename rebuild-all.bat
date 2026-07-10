@echo off
setlocal EnableExtensions EnableDelayedExpansion

set "ROOT=%~dp0"
if "%ROOT:~-1%"=="\" set "ROOT=%ROOT:~0,-1%"

if not exist "%ROOT%\MasterHide.sln" (
    echo [ERROR] Expected MasterHide.sln next to this script.
    exit /b 1
)

set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
set "MSBUILD="

if exist "%VSWHERE%" (
    for /f "usebackq delims=" %%I in (`"%VSWHERE%" -latest -requires Microsoft.Component.MSBuild -find MSBuild\**\Bin\MSBuild.exe`) do (
        set "MSBUILD=%%I"
    )
)

if not defined MSBUILD if exist "%ProgramFiles%\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe" set "MSBUILD=%ProgramFiles%\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe"
if not defined MSBUILD if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\2019\BuildTools\MSBuild\Current\Bin\MSBuild.exe" set "MSBUILD=%ProgramFiles(x86)%\Microsoft Visual Studio\2019\BuildTools\MSBuild\Current\Bin\MSBuild.exe"

if not defined MSBUILD (
    echo [ERROR] MSBuild.exe was not found.
    exit /b 1
)

echo Using MSBuild:
echo   %MSBUILD%
echo Repo root:
echo   %ROOT%
echo.

call :try_stop_service MasterHide
call :try_stop_service DLLInjector
call :try_stop_service KasperskyHookDrv
call :try_stop_service klhk

set "FAILURES=0"

call :build_project "DLL\DLL\DLL.vcxproj" Debug
call :build_project "DLL\DLL\DLL.vcxproj" Release
call :build_project "KasperskyHook\KasperskyHookDrv\KasperskyHookDrv.vcxproj" Debug
call :build_project "KasperskyHook\KasperskyHookDrv\KasperskyHookDrv.vcxproj" Release
call :build_project "KasperskyHook\KasperskyHookLoader\KasperskyHookLoader.vcxproj" Debug
call :build_project "KasperskyHook\KasperskyHookLoader\KasperskyHookLoader.vcxproj" Release
call :build_project "MasterHide\MasterHide.vcxproj" Debug
call :build_project "MasterHide\MasterHide.vcxproj" Release
call :build_project "MasterHide\MasterHide\MasterHide.vcxproj" Debug
call :build_project "MasterHide\MasterHide\MasterHide.vcxproj" Release
call :build_project "MasterHide\TestHide\TestHide.vcxproj" Debug
call :build_project "MasterHide\TestHide\TestHide.vcxproj" Release
call :build_project "TestHide\TestHide.vcxproj" Debug
call :build_project "TestHide\TestHide.vcxproj" Release
call :build_project "windows-kernel-dll-injector\DLLInjector\DLLInjector\DLLInjector.vcxproj" Debug
call :build_project "windows-kernel-dll-injector\DLLInjector\DLLInjector\DLLInjector.vcxproj" Release
call :build_project "windows-kernel-dll-injector\DLLInjector\DLLInjectorCom\DLLInjectorCom.vcxproj" Debug
call :build_project "windows-kernel-dll-injector\DLLInjector\DLLInjectorCom\DLLInjectorCom.vcxproj" Release

echo.
if not "%FAILURES%"=="0" (
    echo [ERROR] %FAILURES% build^(s^) failed.
    exit /b 1
)

if exist "C:\Windows\Temp\inject.dll" (
    for %%I in ("C:\Windows\Temp\inject.dll") do (
        echo inject.dll refreshed:
        echo   %%~fI
        echo   %%~zI bytes, %%~tI
    )
) else (
    echo [WARNING] C:\Windows\Temp\inject.dll was not found after rebuild.
)

echo.
echo All 9 projects rebuilt successfully.
exit /b 0

:try_stop_service
sc query "%~1" >nul 2>&1
if errorlevel 1 exit /b 0

echo Stopping service: %~1
sc stop "%~1" >nul 2>&1
ping 127.0.0.1 -n 3 >nul
exit /b 0

:build_project
set "PROJECT=%~1"
set "CONFIG=%~2"

echo === BUILD %CONFIG%^|x64 :: %PROJECT% ===
"%MSBUILD%" "%ROOT%\%PROJECT%" /t:Rebuild /m /p:Configuration=%CONFIG% /p:Platform=x64 /p:SkipPackageVerification=true
set "CODE=%ERRORLEVEL%"

if not "%CODE%"=="0" (
    echo [FAILED] %PROJECT% ^(%CONFIG%^|x64^) exited with code %CODE%
    set /a FAILURES+=1
)

echo.
exit /b 0

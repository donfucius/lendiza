@echo off
rem Build the differential-test harness with MSVC. Run from the repository root:
rem   cmd /c tests\diff\build.bat
rem Binaries and objects go to tests\diff\out\ (gitignored).
rem Needs the x64 Native Tools environment (cl.exe on PATH).
setlocal
cd /d "%~dp0"
if "%VCINSTALLDIR%"=="" (
    echo This script needs the x64 Native Tools command prompt, or call it as:
    echo   cmd /c ""C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" ^&^& tests\diff\build.bat"
    exit /b 1
)
if not exist out mkdir out
cl /nologo /O2 /W4 /std:c++17 /D_CRT_SECURE_NO_WARNINGS /I..\..\include ^
    harness.cpp ..\..\src\lendiza.cpp /Foout\ /Fe:out\harness.exe

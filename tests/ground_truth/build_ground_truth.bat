@echo off
REM Build Ground Truth samples with MSVC x64
REM Usage: build_ground_truth.bat
setlocal

call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul 2>&1

set SRC=%~dp0source
set BIN=%~dp0binaries
set META=%~dp0metadata

if not exist "%BIN%" mkdir "%BIN%"
if not exist "%META%" mkdir "%META%"

for %%f in ("%SRC%\*.c") do (
    set NAME=%%~nf
    echo Building %%~nf -O0...
    cl.exe /nologo /Od /Zi /Fd"%BIN%\%%~nf_O0.pdb" /Fe"%BIN%\%%~nf_O0.exe" "%%f" /link /MAP:"%META%\%%~nf_O0.map" > "%META%\%%~nf_O0_build.log" 2>&1
    echo Building %%~nf -O2...
    cl.exe /nologo /O2 /Zi /Fd"%BIN%\%%~nf_O2.pdb" /Fe"%BIN%\%%~nf_O2.exe" "%%f" /link /MAP:"%META%\%%~nf_O2.map" > "%META%\%%~nf_O2_build.log" 2>&1
)

echo.
echo Extracting symbols with dumpbin...
for %%f in ("%BIN%\*_O0.exe" "%BIN%\*_O2.exe") do (
    set BASE=%%~nf
    dumpbin /symbols "%%f" > "%META%\%%~nf_symbols.txt" 2>&1
    dumpbin /disasm "%%f" > "%META%\%%~nf_disasm.txt" 2>&1
)

echo Done.
endlocal

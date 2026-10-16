@echo off
rem Compiles fixture/PixelTone.c into a real, optimized, debug-symbol-free x64 PE
rem for the native Windows track (obfuscator-plan.draft.md step 5). Rerunning regenerates
rem artifacts/native-baseline/PixelTone.exe; keep a copy first if you need to preserve
rem existing evidence (same caveat as scripts/build-fixture.ps1 for the .NET fixture).
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
if not exist C:\HFF\MDI\Dysphasia\artifacts\native-baseline mkdir C:\HFF\MDI\Dysphasia\artifacts\native-baseline
cl.exe /O2 /MT /W4 /nologo /Fe:C:\HFF\MDI\Dysphasia\artifacts\native-baseline\PixelTone.exe C:\HFF\MDI\Dysphasia\fixture\PixelTone.c /link /SUBSYSTEM:CONSOLE

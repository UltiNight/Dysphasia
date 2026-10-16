@echo off
rem Compiles fixture/PixelTone.protected4.c (P2+P3+loop-unrolling+pointer-aliasing plus
rem exception-based routing on wmain's preset validation, source-level) into
rem artifacts/native-protected4/PixelTone.exe.
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
if not exist C:\HFF\MDI\Dysphasia\artifacts\native-protected4 mkdir C:\HFF\MDI\Dysphasia\artifacts\native-protected4
cl.exe /O2 /MT /W4 /nologo /Fe:C:\HFF\MDI\Dysphasia\artifacts\native-protected4\PixelTone.exe C:\HFF\MDI\Dysphasia\fixture\PixelTone.protected4.c /link /SUBSYSTEM:CONSOLE

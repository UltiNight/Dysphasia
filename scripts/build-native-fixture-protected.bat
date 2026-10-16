@echo off
rem Compiles fixture/PixelTone.protected.c (source-level string-obfuscation pass) into
rem artifacts/native-protected/PixelTone.exe. See fixture/PixelTone.protected.c and
rem reports/native-track-baseline.draft.md for what this pass does and why it's at the
rem source level rather than binary-rewritten like tools/obfuscator's P1-P3.
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
if not exist C:\HFF\MDI\Dysphasia\artifacts\native-protected mkdir C:\HFF\MDI\Dysphasia\artifacts\native-protected
cl.exe /O2 /MT /W4 /nologo /Fe:C:\HFF\MDI\Dysphasia\artifacts\native-protected\PixelTone.exe C:\HFF\MDI\Dysphasia\fixture\PixelTone.protected.c /link /SUBSYSTEM:CONSOLE

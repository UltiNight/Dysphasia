@echo off
rem Compiles fixture/PixelTone.protected2.c (P2 string obfuscation + P3 control-flow
rem flattening, both source-level) into artifacts/native-protected2/PixelTone.exe.
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
if not exist C:\HFF\MDI\Dysphasia\artifacts\native-protected2 mkdir C:\HFF\MDI\Dysphasia\artifacts\native-protected2
cl.exe /O2 /MT /W4 /nologo /Fe:C:\HFF\MDI\Dysphasia\artifacts\native-protected2\PixelTone.exe C:\HFF\MDI\Dysphasia\fixture\PixelTone.protected2.c /link /SUBSYSTEM:CONSOLE

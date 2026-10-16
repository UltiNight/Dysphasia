@echo off
rem Compiles fixture/PixelTone.protected3.c (P2+P3 plus loop unrolling on fingerprint
rem and pointer aliasing on read_int's accumulator, both source-level) into
rem artifacts/native-protected3/PixelTone.exe.
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
if not exist C:\HFF\MDI\Dysphasia\artifacts\native-protected3 mkdir C:\HFF\MDI\Dysphasia\artifacts\native-protected3
cl.exe /O2 /MT /W4 /nologo /Fe:C:\HFF\MDI\Dysphasia\artifacts\native-protected3\PixelTone.exe C:\HFF\MDI\Dysphasia\fixture\PixelTone.protected3.c /link /SUBSYSTEM:CONSOLE

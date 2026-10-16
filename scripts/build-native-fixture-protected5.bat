@echo off
rem Compiles fixture/PixelTone.protected5.c (P2+P3+loop-unrolling+pointer-aliasing+
rem exception-routing plus anti-debugging via a dynamically-resolved IsDebuggerPresent,
rem source-level) into artifacts/native-protected5/PixelTone.exe.
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
if not exist C:\HFF\MDI\Dysphasia\artifacts\native-protected5 mkdir C:\HFF\MDI\Dysphasia\artifacts\native-protected5
cl.exe /O2 /MT /W4 /nologo /Fe:C:\HFF\MDI\Dysphasia\artifacts\native-protected5\PixelTone.exe C:\HFF\MDI\Dysphasia\fixture\PixelTone.protected5.c /link /SUBSYSTEM:CONSOLE

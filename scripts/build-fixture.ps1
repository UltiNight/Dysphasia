$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$output = Join-Path $root 'artifacts\baseline'
New-Item -ItemType Directory -Force -Path $output | Out-Null
$compiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (!(Test-Path -LiteralPath $compiler)) { throw "Missing .NET Framework C# compiler: $compiler" }
& $compiler /nologo /target:exe /platform:x64 /optimize+ /debug- "/out:$output\PixelTone.exe" (Join-Path $root 'fixture\PixelTone.cs')
if ($LASTEXITCODE -ne 0) { throw 'Fixture compilation failed' }
$manifest = [ordered]@{
    generated_at_utc = [DateTime]::UtcNow.ToString('o')
    target = 'Windows x64 .NET Framework managed PE; no apphost indirection'
    compiler = $compiler
    compiler_version = (Get-Item -LiteralPath $compiler).VersionInfo.FileVersion
    options = '/target:exe /platform:x64 /optimize+ /debug-'
    source_sha256 = (Get-FileHash (Join-Path $root 'fixture\PixelTone.cs')).Hash
    binary_sha256 = (Get-FileHash (Join-Path $output 'PixelTone.exe')).Hash
    bytes = (Get-Item (Join-Path $output 'PixelTone.exe')).Length
}
$manifest | ConvertTo-Json | Set-Content -Encoding utf8 (Join-Path $output 'build-manifest.json')
$manifest | ConvertTo-Json

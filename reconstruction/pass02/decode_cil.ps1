# Supplementary decoder: host opcode table, no target assembly load or execution.
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$evidence = Get-Content -LiteralPath (Join-Path $root 'logs/pass02/02-members.stdout.json') -Raw | ConvertFrom-Json
$target = Join-Path $root 'artifacts/baseline/PixelTone.exe'
$bytes = [IO.File]::ReadAllBytes($target)
$hash = (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLower()
if ($hash -ne $evidence.subject.digest.sha256) { throw 'Artifact SHA-256 mismatch' }
"SUPPLEMENTARY DERIVED CIL: not REA output"
"REA evidence: $($evidence.evidence_id)"
"Artifact SHA-256: $hash"
$ops = @{}
[Reflection.Emit.OpCodes].GetFields([Reflection.BindingFlags]'Public,Static') | ForEach-Object {
    $value = $_.GetValue($null)
    $ops[([int]$value.Value -band 65535)] = $value
}
foreach ($method in $evidence.normalized_result.methods) {
    "$($method.token) $($method.name)"
    $offset = [int]$method.body.file_offset
    $header = if ($method.body.header_format -eq 'tiny') { 1 } else { ([BitConverter]::ToUInt16($bytes,$offset) -shr 12)*4 }
    $base = $offset + $header
    $cil = [byte[]]$bytes[$base..($base + $method.body.il_size - 1)]
    $sha = [Security.Cryptography.SHA256]::Create()
    $cilHash = [BitConverter]::ToString($sha.ComputeHash($cil)).Replace('-','').ToLower()
    $sha.Dispose()
    if ($cilHash -ne $method.body.il_sha256) { throw "CIL hash mismatch: $($method.name)" }
    "CIL SHA-256: $cilHash; file offset: $base"
    $index = 0
    while ($index -lt $cil.Length) {
        $position = $index
        $code = [int]$cil[$index]; $index++
        if ($code -eq 254) { $code = 65280 + [int]$cil[$index]; $index++ }
        $op = $ops[$code]
        if ($null -eq $op) { throw 'Unsupported opcode' }
        $arg = ''
        switch ($op.OperandType.ToString()) {
            'InlineNone' {}
            'ShortInlineI' { $arg=[int]$cil[$index]; if($arg -gt 127){$arg-=256}; $index++ }
            'ShortInlineVar' { $arg=$cil[$index]; $index++ }
            'ShortInlineBrTarget' { $arg=[int]$cil[$index]; if($arg -gt 127){$arg-=256}; $index++; $arg+=$index }
            'InlineI' { $arg=[BitConverter]::ToInt32($cil,$index); $index+=4 }
            { $_ -in @('InlineMethod','InlineType','InlineString','InlineField','InlineTok','InlineSig') } { $arg='0x'+[BitConverter]::ToUInt32($cil,$index).ToString('x8'); $index+=4 }
            default { throw "Unsupported operand: $($op.OperandType)" }
        }
        '{0:x4} {1} {2}' -f $position,$op.Name,$arg
    }
}

$ErrorActionPreference = 'Stop'
$packagePath = Join-Path $PSScriptRoot '..\package.json'
$packagePath = [System.IO.Path]::GetFullPath($packagePath)
if (-not (Test-Path -LiteralPath $packagePath -PathType Leaf)) {
    throw "package.json not found at $packagePath"
}
$json = [System.IO.File]::ReadAllText($packagePath)
$bad = '"@opentelemetry/api"\s*:\s*"1\.10\.0"'
$good = '"@opentelemetry/api": "1.9.1"'
if ([System.Text.RegularExpressions.Regex]::IsMatch($json, $bad)) {
    $json = [System.Text.RegularExpressions.Regex]::Replace($json, $bad, $good, 1)
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($packagePath, $json, $utf8NoBom)
    Write-Host 'Fixed @opentelemetry/api from 1.10.0 to 1.9.1.' -ForegroundColor Green
} elseif ([System.Text.RegularExpressions.Regex]::IsMatch($json, '"@opentelemetry/api"\s*:\s*"1\.9\.1"')) {
    Write-Host '@opentelemetry/api is already pinned to 1.9.1.' -ForegroundColor Green
} else {
    throw 'Expected @opentelemetry/api dependency not found; package.json was not changed.'
}

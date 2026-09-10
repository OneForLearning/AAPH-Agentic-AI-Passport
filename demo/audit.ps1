param([ValidateSet('export','verify')][string]$Action = 'verify', [string]$Output = 'audit-export.json')
$ErrorActionPreference = 'Stop'
$ca = (Resolve-Path (Join-Path (Split-Path $PSScriptRoot) 'dev-certs/ca.crt')).Path
$uri = if ($Action -eq 'export') { 'https://localhost:3000/v1/audit/export' } else { 'https://localhost:3000/v1/audit/verify' }
$response = & curl.exe --silent --show-error --fail --cacert $ca $uri
if ($LASTEXITCODE -ne 0) { throw 'Audit request failed.' }
if ($Action -eq 'export') { $response | Set-Content -Encoding utf8 -LiteralPath $Output; Write-Output "Exported to $Output" } else { $response }

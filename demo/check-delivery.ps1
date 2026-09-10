$ErrorActionPreference = 'Stop'
$compose = docker compose config --format json
if ($LASTEXITCODE -ne 0) { throw 'docker compose config failed' }
$compose | python3 demo/check_delivery_boundary.py
if ($LASTEXITCODE -ne 0) { throw 'delivery trust-boundary check failed' }
Write-Host 'NON_PRODUCTION_DEMO delivery trust boundary: OK'

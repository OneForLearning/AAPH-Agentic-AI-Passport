$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot
$root = Join-Path $repo 'dev-certs'
$config = Join-Path $PSScriptRoot 'openssl-dev.cnf'
if (-not (Get-Command openssl -ErrorAction SilentlyContinue)) { throw 'OpenSSL is required and was not found.' }
$temporary = Join-Path ([System.IO.Path]::GetTempPath()) ("aaph-certs-" + [guid]::NewGuid())
try {
    New-Item -ItemType Directory -Path $temporary,$root -Force | Out-Null
    openssl req -x509 -newkey rsa:3072 -nodes -sha256 -days 30 -keyout "$temporary/ca.key" -out "$temporary/ca.crt" -config $config -extensions v3_ca
    $service = 'aaph-server'
    openssl req -newkey rsa:3072 -nodes -sha256 -keyout "$temporary/$service.key" -out "$temporary/$service.csr" -subj "/CN=$service"
    openssl x509 -req -sha256 -days 30 -in "$temporary/$service.csr" -CA "$temporary/ca.crt" -CAkey "$temporary/ca.key" -CAserial "$temporary/ca.srl" -CAcreateserial -out "$temporary/$service.crt" -extfile $config -extensions aaph_server
    foreach ($file in @('ca.crt','ca.key','aaph-server.crt','aaph-server.key')) {
        Move-Item -LiteralPath (Join-Path $temporary $file) -Destination (Join-Path $root $file) -Force
    }
    Write-Output "NON_PRODUCTION_DEMO CA and aaph-server certificate regenerated in $root"
} finally {
    if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Recurse -Force }
}

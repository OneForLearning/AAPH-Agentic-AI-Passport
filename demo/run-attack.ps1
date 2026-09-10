$ErrorActionPreference = 'Stop'
$cargo = 'C:\Users\User\.cargo\bin\cargo.exe'
$demoRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("aaph-demo-" + [guid]::NewGuid())
$serverProcess = $null
try {
    $certRoot = Join-Path (Split-Path $PSScriptRoot) 'dev-certs'
    if (-not (Test-Path -LiteralPath (Join-Path $certRoot 'ca.crt'))) { throw 'Run demo/generate-dev-certs.ps1 first.' }
    New-Item -ItemType Directory -Path $demoRoot | Out-Null
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'workspace') -Destination (Join-Path $demoRoot 'workspace') -Recurse
    & $cargo run -q -p aaph-core --bin aaph-keygen -- (Join-Path $demoRoot 'authority')
    & $cargo run -q -p aaph-core --bin aaph-keygen -- (Join-Path $demoRoot 'agent')
    $dbRoot = $demoRoot.Replace('\','/')

    $env:AAPH_PUBLIC_LISTEN_ADDR = '127.0.0.1:3000'
    $env:AAPH_ADMIN_LISTEN_ADDR = '127.0.0.1:3002'
    $env:AAPH_PUBLIC_TLS_CERT = Join-Path $certRoot 'aaph-server.crt'
    $env:AAPH_PUBLIC_TLS_KEY = Join-Path $certRoot 'aaph-server.key'
    $env:AAPH_ADMIN_TLS_CERT = Join-Path $certRoot 'aaph-server.crt'
    $env:AAPH_ADMIN_TLS_KEY = Join-Path $certRoot 'aaph-server.key'
    $env:AAPH_PEP_WORKSPACE = Join-Path $demoRoot 'workspace'
    $env:AAPH_PEP_DATABASE_URL = "sqlite:///$dbRoot/pep.db"
    $env:AAPH_AUTHORITY_DATABASE_URL = "sqlite:///$dbRoot/authority.db"
    $env:AAPH_AUTHORITY_SIGNING_KEY_FILE = Join-Path $demoRoot 'authority\signing.key'
    $agentPublicPath = Join-Path $demoRoot 'agent\public.key'
    $env:AAPH_AGENT_PUBLIC_KEY_FILE = $agentPublicPath
    $env:AAPH_ADMIN_SECRET = 'NON_PRODUCTION_DEMO_ADMIN'
    $env:AAPH_CONFIG_DIR = Join-Path (Split-Path $PSScriptRoot) 'config'
    $serverProcess = Start-Process -FilePath $cargo -ArgumentList 'run','-q','-p','aaph-server','--' -PassThru -WindowStyle Hidden

    for ($attempt = 0; $attempt -lt 40; $attempt++) {
        try {
            & curl.exe --silent --fail --cacert (Join-Path $certRoot 'ca.crt') https://localhost:3000/health | Out-Null
            break
        } catch { Start-Sleep -Milliseconds 250 }
    }
    $env:AAPH_AGENT_CONFIG = Join-Path (Split-Path $PSScriptRoot) 'config\agent.json'
    $env:AAPH_AGENT_SIGNING_KEY = Join-Path $demoRoot 'agent\signing.key'
    python3 -m aaph_agent.main run --task (Join-Path $PSScriptRoot 'legitimate-task.json') --planner adversarial-demo
    if ($LASTEXITCODE -ne 0) { throw 'The real attack demonstration failed.' }
} finally {
    if ($null -ne $serverProcess -and -not $serverProcess.HasExited) { Stop-Process -Id $serverProcess.Id }
    if (Test-Path -LiteralPath $demoRoot) { Remove-Item -LiteralPath $demoRoot -Recurse -Force }
}

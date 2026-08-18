# End-to-end authorization test run for Enterprise Vibe FGA (Windows).
#
# Does, in order:
#   1. Model-layer tests        (fga model test, no server needed)
#   2. Start OpenFGA            (memory datastore, http 18080 / grpc 18081)
#   3. Seed store + model + tuples, pin the model id
#   4. Start the neuro-san server wired to the OpenFGA authorizer
#   5. Run the persona E2E suite (pytest tests\e2e_authz)
#   6. Tear everything down (unless -KeepUp)
#
# Prereqs: .venv with requirements-authz.txt installed; tools\openfga.exe and
# tools\fga.exe (see authz\README.md for download commands).

param([switch]$KeepUp, [int]$HttpPort = 8123)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$fga = Join-Path $root "tools\fga.exe"
$openfga = Join-Path $root "tools\openfga.exe"
$python = Join-Path $root ".venv\Scripts\python.exe"
$logs = Join-Path $root ".e2e-logs"
New-Item -ItemType Directory -Force $logs | Out-Null

# ---- 1. model tests -------------------------------------------------------
Write-Host "== fga model test =="
Push-Location (Join-Path $root "authz\tests")
& $fga model test --tests tenancy.fga.yaml
if ($LASTEXITCODE -ne 0) { Pop-Location; throw "fga model tests failed" }
Pop-Location

# ---- 2. OpenFGA server ----------------------------------------------------
Write-Host "== starting OpenFGA =="
$fgaProc = Start-Process -FilePath $openfga -ArgumentList `
    "run","--datastore-engine","memory", `
    "--http-addr","127.0.0.1:18080","--grpc-addr","127.0.0.1:18081", `
    "--playground-enabled=false" `
    -RedirectStandardOutput "$logs\openfga.out.log" -RedirectStandardError "$logs\openfga.err.log" `
    -PassThru -WindowStyle Hidden
$env:FGA_API_URL = "http://127.0.0.1:18080"
$deadline = (Get-Date).AddSeconds(30)
while ($true) {
    try { $null = Invoke-WebRequest "$env:FGA_API_URL/healthz" -UseBasicParsing -TimeoutSec 2; break }
    catch { if ((Get-Date) -gt $deadline) { throw "OpenFGA did not become healthy" }; Start-Sleep 1 }
}

$serverProc = $null
try {
    # ---- 3. seed ----------------------------------------------------------
    Write-Host "== seeding store, model, tuples =="
    $sid = (& $fga store create --name vibe-e2e | ConvertFrom-Json).store.id
    Push-Location (Join-Path $root "authz\model")
    $mid = (& $fga model write --store-id $sid --file fga.mod | ConvertFrom-Json).authorization_model_id
    & $fga model get --store-id $sid --format json | Out-File -Encoding ascii "model.json"
    Pop-Location
    $writeResult = & $fga tuple write --store-id $sid --file (Join-Path $root "authz\seed\tuples.yaml") | ConvertFrom-Json
    if ($writeResult.failed.Count -gt 0) { throw "tuple seeding had failures" }
    Write-Host "store=$sid model=$mid tuples=$($writeResult.successful.Count)"

    # ---- 4. neuro-san server ----------------------------------------------
    Write-Host "== starting neuro-san server =="
    $env:AGENT_MANIFEST_FILE = Join-Path $root "registries\vibe\manifest.hocon"
    $env:AGENT_AUTHORIZER = "neuro_san.internals.authorization.openfga.open_fga_authorizer.OpenFgaAuthorizer"
    $env:AGENT_AUTHORIZER_ACTOR_KEY = "user"
    $env:AGENT_AUTHORIZER_RESOURCE_KEY = "agent_network"
    $env:AGENT_AUTHORIZER_ALLOW_RELATION = "can_invoke"
    $env:AGENT_AUTHORIZER_ACTOR_ID_METADATA_KEY = "user_id"
    $env:AGENT_FORWARDED_REQUEST_METADATA = "request_id user_id"
    $env:FGA_STORE_NAME = "vibe-e2e"
    $env:FGA_MODEL_ID = $mid
    $env:FGA_POLICY_FILE = Join-Path $root "authz\model\model.json"
    $env:AGENT_DEBUG_AUTH = "true"
    $serverProc = Start-Process -FilePath $python -ArgumentList `
        "-m","neuro_san.service.main_loop.server_main_loop","--http_port","$HttpPort" `
        -WorkingDirectory $root `
        -RedirectStandardOutput "$logs\server.out.log" -RedirectStandardError "$logs\server.err.log" `
        -PassThru -WindowStyle Hidden

    $deadline = (Get-Date).AddSeconds(90)
    while ($true) {
        try { $null = Invoke-WebRequest "http://127.0.0.1:$HttpPort/readyz" -UseBasicParsing -TimeoutSec 2; break }
        catch {
            if ($serverProc.HasExited) { throw "neuro-san server exited early; see $logs\server.err.log" }
            if ((Get-Date) -gt $deadline) { throw "neuro-san server did not become ready" }
            Start-Sleep 2
        }
    }

    # ---- 5. E2E suite ------------------------------------------------------
    Write-Host "== pytest tests\e2e_authz =="
    $env:E2E_BASE = "http://127.0.0.1:$HttpPort"
    & $python -m pytest (Join-Path $root "tests\e2e_authz") -v
    if ($LASTEXITCODE -ne 0) { throw "E2E tests failed" }
    Write-Host "== ALL GREEN =="
}
finally {
    if (-not $KeepUp) {
        Write-Host "== teardown =="
        if ($serverProc -and -not $serverProc.HasExited) { Stop-Process -Id $serverProc.Id -Force }
        if ($fgaProc -and -not $fgaProc.HasExited) { Stop-Process -Id $fgaProc.Id -Force }
    } else {
        Write-Host "KeepUp: openfga pid $($fgaProc.Id), server pid $($serverProc.Id)"
    }
}

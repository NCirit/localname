# `localname daemon` under the Service Control Manager (CI, administrator): install,
# verify, kill and recover, stop and start, idempotency, uninstall keeping data. Reboots
# are covered by tests/daemon/reboot-check.ps1 on real hardware.
$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..\..')
cargo build --locked --release --bin localname
if ($LASTEXITCODE -ne 0) { throw 'build failed' }
$bin = Join-Path $PWD 'target\release\localname.exe'
$data = Join-Path $env:ProgramData 'localname'
$config = Join-Path $data 'config.toml'

function Invoke-Json {
    $text = & $bin @args --output json
    if ($LASTEXITCODE -ne 0) { throw "localname $args exited $LASTEXITCODE`: $text" }
    $text | ConvertFrom-Json
}
function Resolve-Nas {
    try { (Resolve-DnsName -Name nas.lan -Server 127.0.0.1 -Type A -DnsOnly -QuickTimeout -ErrorAction Stop).IPAddress } catch { $null }
}

try {
    & $bin daemon install --output json | Out-Null
    if ($LASTEXITCODE -ne 3) { throw "install without configuration exited $LASTEXITCODE" }
    & $bin --config $config setup --apply --listen 127.0.0.1:53 --advertise 192.168.1.10 --upstream 192.0.2.1:53 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'setup failed' }
    $preview = Invoke-Json daemon install
    if (Get-Service localname -ErrorAction SilentlyContinue) { throw 'preview created the service' }
    $result = Invoke-Json daemon install --apply
    if ($result.verification.status -ne 'passed') { throw "install not verified: $($result | ConvertTo-Json -Depth 6)" }
    $service = Get-CimInstance Win32_Service -Filter "Name='localname'"
    if ($service.StartMode -ne 'Auto') { throw "start mode $($service.StartMode)" }
    if ($service.StartName -ne 'NT SERVICE\localname') { throw "account $($service.StartName)" }
    $acl = (Get-Acl $data).Access | ForEach-Object { $_.IdentityReference.Value }
    if ($acl -match 'Users$') { throw "data directory still grants Users: $acl" }
    if ((Invoke-Json daemon install --apply).changed) { throw 're-install reported a change' }

    # The administrator's CLI finds the service configuration without --config.
    $added = Invoke-Json add nas 192.168.1.20
    if ($added.verification.status -ne 'passed') { throw 'live add not verified' }
    if ((Resolve-Nas) -ne '192.168.1.20') { throw 'nas.lan not served' }

    # Killed: the recovery actions restart it.
    $old = (Get-CimInstance Win32_Service -Filter "Name='localname'").ProcessId
    Stop-Process -Id $old -Force
    $restarted = $false
    for ($i = 0; $i -lt 100; $i++) {
        Start-Sleep -Milliseconds 300
        $new = (Get-CimInstance Win32_Service -Filter "Name='localname'").ProcessId
        if ($new -and $new -ne $old -and (Resolve-Nas) -eq '192.168.1.20') { $restarted = $true; break }
    }
    if (-not $restarted) { throw 'not restarted after kill' }

    if ((Invoke-Json daemon stop).verification.status -ne 'passed') { throw 'stop' }
    if ((Get-Service localname).StartType -ne 'Automatic') { throw 'stop changed the start type' }
    if ((Invoke-Json daemon start).verification.status -ne 'passed') { throw 'start' }

    $removed = Invoke-Json daemon uninstall
    if ($removed.verification.status -ne 'passed') { throw 'uninstall not verified' }
    if (Get-Service localname -ErrorAction SilentlyContinue) { throw 'service left behind' }
    if (Test-Path (Join-Path $env:ProgramFiles 'localname\localname.exe')) { throw 'binary left behind' }
    if (-not (Test-Path $config)) { throw 'uninstall removed the configuration' }
    if ((Invoke-Json daemon status).data.state.installed) { throw 'still installed' }
    Write-Output 'daemon (Windows service): all checks passed'
} catch {
    Get-Content (Join-Path $data 'daemon.log') -ErrorAction SilentlyContinue | Select-Object -Last 50
    throw
} finally {
    & $bin daemon uninstall | Out-Null
}

# Client split DNS on Windows (CI, administrator): apply, verify, idempotency, conflicts,
# and rollback, preserving foreign NRPT rules and the DNS suffix search list. Reboots are
# covered by tests/client/reboot-check.ps1 on real hardware.
$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..\..')
cargo build --locked --release --bin localname
if ($LASTEXITCODE -ne 0) { throw 'build failed' }
$bin = Join-Path $PWD 'target\release\localname.exe'
$work = Join-Path $env:RUNNER_TEMP 'localname-client'
New-Item -ItemType Directory -Force $work | Out-Null
$config = Join-Path $work 'config.toml'

# Simple functions pass unknown --flags through $args; advanced functions would reject them.
function Invoke-Localname {
    $output = & $bin @args
    if ($LASTEXITCODE -ne 0) { throw "localname $args exited $LASTEXITCODE`: $output" }
    $output
}
function Invoke-LocalnameExpecting {
    param([int]$Expected)
    $output = & $bin @args
    if ($LASTEXITCODE -ne $Expected) { throw "localname $args exited $LASTEXITCODE (expected $Expected): $output" }
}

Invoke-Localname --config $config setup --apply --listen 127.0.0.1:53 --advertise 192.168.1.10 --upstream 192.0.2.1:53 | Out-Null
Invoke-Localname --config $config add nas 192.168.1.20 | Out-Null
$server = Start-Process -FilePath $bin -ArgumentList '--config', $config, 'serve' -PassThru -WindowStyle Hidden
$previousSuffixes = (Get-DnsClientGlobalSetting).SuffixSearchList
try {
    for ($i = 0; $i -lt 50; $i++) {
        & $bin --config $config status --check | Out-Null
        if ($LASTEXITCODE -eq 0) { break }
        Start-Sleep -Milliseconds 200
    }
    # VPN-like state that must survive untouched.
    Add-DnsClientNrptRule -Namespace '.corp.example' -NameServers '10.8.0.1' -Comment 'test VPN'
    Set-DnsClientGlobalSetting -SuffixSearchList @('example.lan')
    $before = Get-DnsClientNrptRule | Where-Object Comment -ne 'Managed by localname' |
        ForEach-Object { "$($_.Namespace) $($_.NameServers)" } | Sort-Object

    $apply = Invoke-Localname client setup --server 127.0.0.1 --apply --output json | ConvertFrom-Json
    if ($apply.verification.status -ne 'passed') { throw "verification failed: $($apply | ConvertTo-Json -Depth 8)" }
    $answer = Resolve-DnsName nas.lan -Type A -DnsOnly
    if ($answer.IPAddress -notcontains '192.168.1.20') { throw 'nas.lan did not resolve' }
    $again = Invoke-Localname client setup --server 127.0.0.1 --apply --output json | ConvertFrom-Json
    if ($again.changed) { throw 'repeated apply changed state' }
    Invoke-LocalnameExpecting 3 client setup --server 127.0.0.1 --port 5354 --zone dev.test --apply --output json

    # A foreign rule for the zone is never replaced.
    Add-DnsClientNrptRule -Namespace '.dev.test' -NameServers '10.9.9.9' -Comment 'foreign'
    Invoke-LocalnameExpecting 5 client setup --server 127.0.0.1 --zone dev.test --apply --output json

    $rollback = Invoke-Localname client rollback --output json | ConvertFrom-Json
    if ($rollback.verification.status -ne 'passed') { throw 'rollback verification failed' }
    if (Get-DnsClientNrptRule | Where-Object Comment -eq 'Managed by localname') { throw 'localname rule remains' }
    $after = Get-DnsClientNrptRule | Where-Object Comment -ne 'Managed by localname' |
        ForEach-Object { "$($_.Namespace) $($_.NameServers)" } | Sort-Object
    if (Compare-Object $before $after) { throw "foreign NRPT rules changed" }
    if (((Get-DnsClientGlobalSetting).SuffixSearchList -join ',') -ne 'example.lan') { throw 'suffix search list changed' }
    Write-Output 'Windows client split DNS: applied, verified, idempotent, conflicts refused, rolled back'
} finally {
    Stop-Process -Id $server.Id -Force -ErrorAction SilentlyContinue
    & $bin client rollback | Out-Null
    Get-DnsClientNrptRule | Where-Object { $_.Comment -in 'test VPN', 'foreign' } | ForEach-Object { Remove-DnsClientNrptRule -Name $_.Name -Force }
    Set-DnsClientGlobalSetting -SuffixSearchList $previousSuffixes
}

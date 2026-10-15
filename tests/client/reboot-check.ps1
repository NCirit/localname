# Reboot check for client split DNS on a real Windows machine (M3b). Hosted CI cannot
# reboot, so run this by hand in an administrator PowerShell against a running server:
#   .\tests\client\reboot-check.ps1 before SERVER_IP   # records state, applies
#   (reboot)
#   .\tests\client\reboot-check.ps1 after              # verifies, rolls back, compares
param([Parameter(Mandatory)][ValidateSet('before', 'after')][string]$Phase, [string]$Server)
$ErrorActionPreference = 'Stop'
$state = Join-Path $env:ProgramData 'localname-reboot-check'
$name = 'localname.lan'
function Get-Snapshot {
    Get-DnsClientNrptRule | Where-Object Comment -ne 'Managed by localname' |
        ForEach-Object { "nrpt $($_.Namespace) $($_.NameServers)" }
    Get-DnsClient | ForEach-Object {
        $servers = (Get-DnsClientServerAddress -InterfaceIndex $_.InterfaceIndex -ErrorAction SilentlyContinue).ServerAddresses -join ','
        "interface $($_.InterfaceAlias) suffix=$($_.ConnectionSpecificSuffix) dns=$servers"
    }
    "search $((Get-DnsClientGlobalSetting).SuffixSearchList -join ',')"
}
function Test-Name { [bool](Resolve-DnsName $name -Type A -ErrorAction SilentlyContinue) }
if ($Phase -eq 'before') {
    if (-not $Server) { throw 'usage: reboot-check.ps1 before SERVER_IP' }
    New-Item -ItemType Directory -Force $state | Out-Null
    Get-Snapshot | Sort-Object | Set-Content (Join-Path $state 'baseline')
    localname client setup --server $Server --apply
    if ($LASTEXITCODE -ne 0) { throw 'client setup failed' }
    if (-not (Test-Name)) { throw "FAIL: $name does not resolve after apply" }
    'Applied. Reboot, then run: .\tests\client\reboot-check.ps1 after'
} else {
    if (-not (Test-Name)) { throw "FAIL: $name no longer resolves after reboot" }
    localname client rollback
    if ($LASTEXITCODE -ne 0) { throw 'client rollback failed' }
    Clear-DnsClientCache
    if (Test-Name) { throw "FAIL: $name still resolves after rollback (does the router advertise localname?)" }
    $baseline = Get-Content (Join-Path $state 'baseline')
    $now = Get-Snapshot | Sort-Object
    if (Compare-Object $baseline $now) { throw 'FAIL: unrelated DNS state changed' }
    'PASS: configuration survived reboot; rollback restored the exact prior DNS state'
}

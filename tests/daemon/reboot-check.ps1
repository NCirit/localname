# Real-hardware reboot check for `localname daemon` on Windows (administrator PowerShell).
# Run with -Phase before (with an installed service), reboot, then -Phase after.
param([Parameter(Mandatory)][ValidateSet('before', 'after')][string]$Phase, [string]$Localname = 'localname')
$ErrorActionPreference = 'Stop'
function Get-State { (& $Localname daemon status --output json | ConvertFrom-Json).data }
if ($Phase -eq 'before') {
    $state = (Get-State).state
    if (-not $state.installed) { throw "install the service first: $Localname daemon install --apply" }
    if (-not $state.enabled) { throw 'the service does not start at boot' }
    Write-Output "Service installed and enabled. Reboot, then run: $PSCommandPath -Phase after"
} else {
    for ($i = 0; $i -lt 60; $i++) {
        if ((Get-State).dns.healthy) { Write-Output 'PASS: localname started at boot and answers DNS'; exit 0 }
        Start-Sleep -Seconds 1
    }
    & $Localname daemon status
    throw 'FAIL: not answering 60 s after boot'
}

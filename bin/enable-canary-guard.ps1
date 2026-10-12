param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string[]]$Roots
)

$npaNode = (Get-Command node -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
$npaSetupJson = & $npaNode (Join-Path $PSScriptRoot 'npa.js') canary-guard @Roots --json
if ($LASTEXITCODE -ne 0) {
    throw 'Canary guard setup failed; session settings were not changed.'
}
$npaSetup = ($npaSetupJson -join "`n") | ConvertFrom-Json -ErrorAction Stop
if (-not $npaSetup.env.NPA_CANARY_GUARD -or -not $npaSetup.env.NODE_OPTIONS) {
    throw 'Canary guard returned invalid session settings.'
}

[Environment]::SetEnvironmentVariable('NPA_CANARY_GUARD', $npaSetup.env.NPA_CANARY_GUARD, 'Process')
[Environment]::SetEnvironmentVariable('NODE_OPTIONS', $npaSetup.env.NODE_OPTIONS, 'Process')
Write-Output 'Node startup protection configured for this PowerShell session.'

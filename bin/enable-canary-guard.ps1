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

$npaCli = Join-Path $PSScriptRoot 'npa.js'
$npaSelectedRoots = @(($npaSetup.env.NPA_CANARY_GUARD | ConvertFrom-Json).roots)
$npaConfiguredLaunchers = @()
foreach ($npaLauncher in @('cmd', 'powershell', 'pwsh', 'bash', 'sh')) {
    $npaApplication = Get-Command $npaLauncher -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $npaApplication) { continue }
    $npaLauncherPath = $npaApplication.Source
    $npaWrapper = {
        $ErrorActionPreference = 'Stop'
        $npaInvocation = @($npaLauncherPath) + @($args | ForEach-Object { [string]$_ })
        $npaEncoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject $npaInvocation -Compress)))
        try {
            & $npaNode $npaCli canary-run @npaSelectedRoots --encoded-argv $npaEncoded
            $global:LASTEXITCODE = $LASTEXITCODE
        } catch {
            $global:LASTEXITCODE = 1
            throw
        }
    }.GetNewClosure()
    foreach ($npaName in @($npaLauncher, [IO.Path]::GetFileName($npaLauncherPath)) | Select-Object -Unique) {
        Set-Item -LiteralPath ('Function:global:' + $npaName) -Value $npaWrapper -Force -ErrorAction Stop
        if ((Get-Command $npaName -ErrorAction Stop).CommandType -ne 'Function') {
            throw ('An alias overrides the protected shell launcher: ' + $npaName)
        }
        $npaConfiguredLaunchers += $npaName
    }
}
Write-Output 'Node startup and shell-launcher protection configured for this PowerShell session.'
Write-Output ('Protected shell launchers: ' + ($npaConfiguredLaunchers -join ', '))

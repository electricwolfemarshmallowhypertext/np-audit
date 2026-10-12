param([string]$NodePath, [string]$CliPath, [string[]]$SelectedRoots)

$npaInvoke = $ExecutionContext.InvokeCommand
$npaPrevious = $npaInvoke.PreCommandLookupAction
if ($global:NpaCanaryLookupState -and $npaPrevious -eq $global:NpaCanaryLookupState.Handler) {
    $npaPrevious = $global:NpaCanaryLookupState.Previous
}
$npaState = @{ Busy = $false; Previous = $npaPrevious; Invoke = $npaInvoke; Node = $NodePath; Cli = $CliPath; Roots = $SelectedRoots }
$npaBlock = {
    $global:LASTEXITCODE = 2
    Microsoft.PowerShell.Utility\Write-Error 'Canary protection failed; command was not launched.' -ErrorAction Continue
}
$npaHandler = {
    param($sender, $event)
    if ($npaState.Busy) { return }
    $npaState.Busy = $true
    $npaSavedExit = $global:LASTEXITCODE
    try {
        $npaName = $event.CommandName
        $npaResolved = $npaState.Invoke.GetCommand($npaName, [System.Management.Automation.CommandTypes]::All)
        while ($npaResolved -is [System.Management.Automation.AliasInfo]) { $npaResolved = $npaResolved.ResolvedCommand }
        $npaNeedsCheck = $npaResolved -is [System.Management.Automation.ApplicationInfo] -or
            $npaResolved -is [System.Management.Automation.ExternalScriptInfo] -or
            ($npaResolved -and $npaResolved.Name -in @('Start-Process', 'Invoke-Expression'))
        if ($npaNeedsCheck) {
            # Lookup handlers swallow exceptions. Install denial before checking.
            $event.CommandScriptBlock = $npaBlock
            & $npaState.Node $npaState.Cli canary-run @($npaState.Roots) --check
            if ($LASTEXITCODE -eq 0) {
                $event.CommandScriptBlock = $null
                $global:LASTEXITCODE = $npaSavedExit
            }
        }
        if (-not $event.StopSearch -and $npaState.Previous) { $npaState.Previous.Invoke($sender, $event) }
    } finally { $npaState.Busy = $false }
}.GetNewClosure()
$npaState.Handler = [System.EventHandler[System.Management.Automation.CommandLookupEventArgs]]$npaHandler
$global:NpaCanaryLookupState = $npaState
$npaInvoke.PreCommandLookupAction = $npaState.Handler

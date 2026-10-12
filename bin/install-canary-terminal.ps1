param(
    [string[]]$ProfilePaths = @(),
    [switch]$SkipCmd,
    [switch]$Uninstall
)

$ErrorActionPreference = 'Stop'
$npaHelper = Join-Path $PSScriptRoot 'enable-canary-guard.ps1'
$npaPreload = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../src/core/canaryPreload.js')).Replace('\', '/')
$npaNode = (Get-Command node -CommandType Application | Select-Object -First 1).Source
if (-not $ProfilePaths.Count) {
    $npaDocuments = [Environment]::GetFolderPath('MyDocuments')
    $ProfilePaths = @((Join-Path $npaDocuments 'WindowsPowerShell/profile.ps1'), (Join-Path $npaDocuments 'PowerShell/profile.ps1'))
}
$npaQuote = { param($value) "'" + $value.Replace("'", "''") + "'" }
$npaPrefix = '--require "' + $npaPreload + '"'
$npaBlock = "`r`n# >>> np-audit automatic terminal activation >>>`r`n" +
    "`$env:NPA_CANARY_GUARD = '{`"autoProject`":true}'`r`n" +
    "if (-not `$env:NODE_OPTIONS -or -not `$env:NODE_OPTIONS.StartsWith($(& $npaQuote $npaPrefix))) { `$env:NODE_OPTIONS = $(& $npaQuote ($npaPrefix + ' ')) + `$env:NODE_OPTIONS }`r`n" +
    "& $(& $npaQuote $npaHelper) | Out-Null`r`n" +
    "# <<< np-audit automatic terminal activation <<<`r`n"
$npaLatin = [Text.Encoding]::GetEncoding(28591)
$npaResults = @()
foreach ($npaProfile in $ProfilePaths) {
    [byte[]]$npaOriginal = @()
    if (Test-Path -LiteralPath $npaProfile) { $npaOriginal = [IO.File]::ReadAllBytes($npaProfile) }
    if ($npaOriginal.Length -gt 131072) { throw 'PowerShell profile exceeds the 128 KiB limit' }
    $npaEncoding = [Text.UTF8Encoding]::new($false)
    if ($npaOriginal.Length -ge 2 -and $npaOriginal[0] -eq 255 -and $npaOriginal[1] -eq 254) { $npaEncoding = [Text.Encoding]::Unicode }
    elseif ($npaOriginal.Length -ge 2 -and $npaOriginal[0] -eq 254 -and $npaOriginal[1] -eq 255) { $npaEncoding = [Text.Encoding]::BigEndianUnicode }
    $npaStart = $npaLatin.GetString($npaEncoding.GetBytes("`r`n# >>> np-audit automatic terminal activation >>>`r`n"))
    $npaEnd = $npaLatin.GetString($npaEncoding.GetBytes("# <<< np-audit automatic terminal activation <<<`r`n"))
    $npaPattern = '(?s)' + [regex]::Escape($npaStart) + '.*?' + [regex]::Escape($npaEnd)
    [byte[]]$npaPreserved = @($npaLatin.GetBytes([regex]::Replace($npaLatin.GetString($npaOriginal), $npaPattern, '')))
    [byte[]]$npaOutput = $npaPreserved
    if (-not $Uninstall) { $npaOutput = [byte[]]($npaPreserved + $npaEncoding.GetBytes($npaBlock)) }
    if ($npaOriginal.Length -eq 0 -and $Uninstall) { continue }
    [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($npaProfile)) | Out-Null
    [IO.File]::WriteAllBytes($npaProfile, $npaOutput)
    $npaResults += [PSCustomObject]@{ Profile = $npaProfile; Status = $(if ($Uninstall) { 'removed' } else { 'installed' }); Bytes = $npaOutput.Length }
}
if (-not $SkipCmd) {
    $npaKeyPath = 'HKCU:/Software/Microsoft/Command Processor'
    if (-not (Test-Path -LiteralPath $npaKeyPath)) { New-Item -Path $npaKeyPath -Force | Out-Null }
    $npaKey = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Software\Microsoft\Command Processor', $true)
    $npaCurrent = [string]$npaKey.GetValue('AutoRun', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
    $npaManaged = $npaKey.GetValue('NpaManagedAutoRun', $null)
    if ($null -ne $npaManaged -and $npaCurrent -ne $npaManaged) { throw 'Command Prompt AutoRun was edited after installation; refusing to overwrite it' }
    if ($Uninstall) {
        if ($null -ne $npaManaged) {
            if ($npaKey.GetValue('NpaOriginalAutoRunPresent', 0)) { $npaKey.SetValue('AutoRun', $npaKey.GetValue('NpaOriginalAutoRun', ''), [Microsoft.Win32.RegistryValueKind]($npaKey.GetValue('NpaOriginalAutoRunKind', 1))) }
            else { $npaKey.DeleteValue('AutoRun', $false) }
            foreach ($npaName in @('NpaManagedAutoRun', 'NpaOriginalAutoRun', 'NpaOriginalAutoRunPresent', 'NpaOriginalAutoRunKind')) { $npaKey.DeleteValue($npaName, $false) }
        }
    } else {
        if ($null -eq $npaManaged) {
            $npaOriginalPresent = $npaKey.GetValueNames() -contains 'AutoRun'
            $npaKey.SetValue('NpaOriginalAutoRun', $npaCurrent, [Microsoft.Win32.RegistryValueKind]::String)
            $npaKey.SetValue('NpaOriginalAutoRunPresent', [int]$npaOriginalPresent, [Microsoft.Win32.RegistryValueKind]::DWord)
            $npaKey.SetValue('NpaOriginalAutoRunKind', $(if ($npaOriginalPresent) { [int]$npaKey.GetValueKind('AutoRun') } else { 1 }), [Microsoft.Win32.RegistryValueKind]::DWord)
        }
        $npaOriginalRun = [string]$npaKey.GetValue('NpaOriginalAutoRun', '')
        $npaLoader = 'call "' + (Join-Path $PSScriptRoot 'enable-canary.cmd') + '" "' + $npaNode + '"'
        $npaValue = $npaLoader + $(if ($npaOriginalRun) { ' & ' + $npaOriginalRun } else { '' })
        $npaKey.SetValue('AutoRun', $npaValue, [Microsoft.Win32.RegistryValueKind]::String)
        $npaKey.SetValue('NpaManagedAutoRun', $npaValue, [Microsoft.Win32.RegistryValueKind]::String)
    }
    $npaKey.Dispose()
    $npaResults += [PSCustomObject]@{ CmdAutoRun = $npaKeyPath; Status = $(if ($Uninstall) { 'removed' } else { 'installed' }) }
}
$npaResults | ConvertTo-Json -Compress

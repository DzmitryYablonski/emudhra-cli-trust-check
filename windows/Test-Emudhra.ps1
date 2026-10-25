# Entwickelt von Stanislav Stolberg. Read-only Windows eMudhra check.
#requires -Version 5.1
[CmdletBinding()]
param([switch]$Help)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Emudhra.Windows.psm1') -Force
if ($Help) {
    Write-Output 'Read-only Windows check: .NET TLS, curl.exe TLS, selected application versions. No repairs.'
    Write-Output 'Usage: .\windows\Test-Emudhra.ps1; exit codes 0/1/2/3/4 match the Bash checker.'
    exit 0
}
if (-not (Test-EmudhraWindowsPlatform)) { [Console]::Error.WriteLine('This entry point requires Windows.'); exit 2 }
$statuses = New-Object 'System.Collections.Generic.List[string]'
function Add-Result {
    param([string]$Status, [string]$Label)
    $statuses.Add($Status)
    Write-Output ('{0,-14} {1}' -f $Status, $Label)
}
$hostsToTest = @('https://dv-g3b-emudhra.we-have-a-problem.com/',
    'https://dv-g3b-aaa-emudhra.we-have-a-problem.com/',
    'https://dv-g3b-noct-emudhra.we-have-a-problem.com/',
    'https://dv-g3b-aaa-noct-emudhra.we-have-a-problem.com/')
Write-Output 'eMudhra Windows check (read-only); version data: 2026-10-24'
Write-Output 'Scope: Windows/.NET and curl TLS; Git/Node/uv and selected apps by version only.'
Write-Output 'Python/Java CA bundles, browsers, proxies and project environments are not exhaustively inspected.'
Write-Output 'After 2027-05-03 UTC, rejected test chains are inconclusive because the test certificates expire.'
try {
    $results = @($hostsToTest | ForEach-Object { Test-EmudhraTlsConnection -Uri $_ })
    $control = Test-EmudhraTlsConnection -Uri 'https://pypi.org/'
    Add-Result (Get-EmudhraVerdict -Results $results -Control $control) 'Windows/.NET TLS (direct connection, revocation checking enabled)'
} catch { Add-Result 'INCONCLUSIVE' 'Windows/.NET TLS could not complete.' }
$curlCommand = Get-Command curl.exe -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
if ($curlCommand) {
    $curlResults = @()
    foreach ($address in @($hostsToTest) + @('https://pypi.org/')) {
        try {
            $result = Invoke-EmudhraProcess -FilePath $curlCommand.Source -ArgumentList @('-q', '--silent', '--show-error', '--head', '--output', 'NUL', '--connect-timeout', '8', '--max-time', '12', $address)
            if ($result.ExitCode -eq 0) { $curlResults += 'C' }
            elseif ($result.ExitCode -in @(51, 60, 83, 91)) { $curlResults += 'B' }
            else { $curlResults += 'E' }
        } catch { $curlResults += 'E' }
    }
    Add-Result (Get-EmudhraVerdict -Results $curlResults[0..3] -Control $curlResults[4]) 'curl.exe TLS (without .curlrc; proxy environment applies)'
} else { Write-Output 'curl.exe not found; not tested.' }
$tools = @(
    @{ Command = 'git.exe'; Floor = '2.56.0.3'; Pattern = 'git version (\S+)'; Label = 'Git for Windows' },
    @{ Command = 'uv.exe'; Floor = '0.13.5'; Pattern = 'uv (\S+)'; Label = 'uv' },
    @{ Command = 'node.exe'; Floor = ''; Pattern = 'v(\S+)'; Label = 'Node.js' }
)
foreach ($tool in $tools) {
    $found = Get-Command $tool.Command -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $found) { continue }
    try {
        $result = Invoke-EmudhraProcess -FilePath $found.Source -ArgumentList @('--version') -TimeoutMs 10000
        $versionMatch = [regex]::Match($result.Output, $tool.Pattern)
        if ($result.ExitCode -ne 0 -or -not $versionMatch.Success) {
            Add-Result 'INCONCLUSIVE' ($tool.Label + ' version unavailable'); continue
        }
        $actual = $versionMatch.Groups[1].Value
        $floor = $tool.Floor
        if ($tool.Label -eq 'Node.js') {
            $floor = switch (($actual -split '\.')[0]) { '22' { '22.23.4' }; '24' { '24.22.1' }; '26' { '26.12.1' }; default { '' } }
        }
        Add-Result (Get-EmudhraVersionStatus -Actual $actual -Minimum $floor) ($tool.Label + ' ' + $actual + ' (version only)')
    } catch { Add-Result 'INCONCLUSIVE' ($tool.Label + ' could not be inspected') }
}
$appRules = @(
    @{ Pattern = '^Microsoft Visual Studio Code'; Label = 'Visual Studio Code'; Floor = '1.143.1' },
    @{ Pattern = '^Docker Desktop$'; Label = 'Docker Desktop'; Floor = '4.96.2' },
    @{ Pattern = '^Obsidian$'; Label = 'Obsidian'; Floor = '1.14.5' }
)
$registryRoots = @('HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall',
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall',
    'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')
foreach ($registryRoot in $registryRoots) {
    if (-not (Test-Path $registryRoot)) { continue }
    try {
        foreach ($key in Get-ChildItem $registryRoot -ErrorAction Stop) {
            $item = Get-ItemProperty $key.PSPath -ErrorAction Stop
            if (-not $item.PSObject.Properties['DisplayName']) { continue }
            foreach ($rule in $appRules) {
                if ($item.DisplayName -notmatch $rule.Pattern) { continue }
                if (-not $item.PSObject.Properties['DisplayVersion']) { Add-Result 'INCONCLUSIVE' ($rule.Label + ' version missing'); continue }
                Add-Result (Get-EmudhraVersionStatus $item.DisplayVersion $rule.Floor) ($rule.Label + ' ' + $item.DisplayVersion + ' (version only)')
            }
        }
    } catch { Add-Result 'INCONCLUSIVE' 'An application registry scope could not be inspected.' }
}
Write-Output 'Update Windows through your managed update channel; update selected apps separately with Update-EmudhraWindows.ps1.'
Write-Output ('Summary: vulnerable={0}; review={1}; inconclusive={2}' -f @($statuses | Where-Object { $_ -eq 'VULNERABLE' }).Count, @($statuses | Where-Object { $_ -eq 'OUTDATED' }).Count, @($statuses | Where-Object { $_ -eq 'INCONCLUSIVE' }).Count)
exit (Get-EmudhraExitCode -Statuses $statuses.ToArray())

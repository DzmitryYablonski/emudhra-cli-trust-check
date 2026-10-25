# Entwickelt von Stanislav Stolberg. Explicit, selected Windows app updates.
#requires -Version 5.1
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param([ValidateNotNullOrEmpty()][string[]]$PackageId, [switch]$Apply, [switch]$Help)
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
Import-Module (Join-Path $PSScriptRoot 'Emudhra.Windows.psm1') -Force
if ($Help -or -not $PackageId) {
    Write-Output 'Usage: .\windows\Update-EmudhraWindows.ps1 -PackageId Git.Git,Microsoft.VisualStudioCode [-Apply [-WhatIf]]'
    Write-Output ('Supported package IDs: ' + ((Get-EmudhraUpdatePackageId) -join ', '))
    Write-Output 'Default: plan only. Exit codes: 0 completed/plan, 2 usage, 3 update error, 4 no applicable update; inspect output and rerun the checker.'
    if ($Help) { exit 0 }; exit 2
}
try {
    # Validate the complete request before allowing any update.
    $plans = @($PackageId | Select-Object -Unique | ForEach-Object {
        [pscustomobject]@{ Id = $_; Arguments = @(Get-EmudhraUpdateArgument -PackageId $_) }
    })
} catch { [Console]::Error.WriteLine($_.Exception.Message); exit 2 }
if (-not $Apply) {
    foreach ($plan in $plans) { Write-Output ('PLAN: winget ' + ($plan.Arguments -join ' ')) }
    Write-Output 'No changes. Add -Apply to update only the explicitly selected installed packages.'
    Write-Output 'Windows itself: Settings > Windows Update, or your organisation-managed update channel.'
    exit 0
}
if (-not (Test-EmudhraWindowsPlatform)) { [Console]::Error.WriteLine('Applying updates requires Windows.'); exit 2 }
$failed = $false
$review = $false
foreach ($plan in $plans) {
    if ($PSCmdlet.ShouldProcess($plan.Id, 'Upgrade installed application with winget')) {
        try {
            $winget = Get-Command winget.exe -CommandType Application -ErrorAction Stop | Select-Object -First 1
            $nativeArguments = $plan.Arguments
            & $winget.Source @nativeArguments
            $updateCode = $LASTEXITCODE
            # Microsoft's UPDATE_NOT_APPLICABLE also covers unknown versions/OS constraints.
            # It cannot establish that the installed application is patched.
            if ($updateCode -eq -1978335189) {
                Write-Warning ('No applicable update for {0}; inspect winget output and rerun the checker.' -f $plan.Id)
                $review = $true
            } elseif ($updateCode -ne 0) {
                Write-Warning ('winget returned {0} for {1}; inspect its message. No success is assumed.' -f $updateCode, $plan.Id)
                $failed = $true
            }
        } catch { Write-Warning ('Could not run winget for {0}: {1}' -f $plan.Id, $_.Exception.Message); $failed = $true }
    }
}
Write-Output 'Rerun Test-Emudhra.ps1 after successful updates. Independent Python/Java CA bundles need separate maintenance.'
if ($failed) { exit 3 }
if ($review) { exit 4 }
exit 0

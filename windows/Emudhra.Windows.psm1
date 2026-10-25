# Entwickelt von Stanislav Stolberg. Shared Windows diagnostics; no system changes.
#requires -Version 5.1
Set-StrictMode -Version Latest

function Test-EmudhraWindowsPlatform {
    return [Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT
}

function Get-EmudhraVerdict {
    param([string[]]$Results, [string]$Control, [datetime]$UtcNow = [datetime]::UtcNow)
    if ($null -eq $Results -or $Results.Count -ne 4 -or @($Results | Where-Object { $_ -notin @('B', 'C', 'E') }).Count -gt 0) {
        return 'INCONCLUSIVE'
    }
    if ($Results -contains 'C') { return 'VULNERABLE' }
    # Same conservative cutoff as the upstream Bash diagnostic; expiration is not distrust.
    if ($UtcNow -ge [datetime]'2027-05-03T00:00:00Z') { return 'INCONCLUSIVE' }
    if (@($Results | Where-Object { $_ -eq 'B' }).Count -eq 4 -and $Control -eq 'C') { return 'OK' }
    return 'INCONCLUSIVE'
}

function Get-EmudhraExitCode {
    param([string[]]$Statuses)
    if ($Statuses -contains 'VULNERABLE') { return 1 }
    if ($null -eq $Statuses -or $Statuses.Count -eq 0 -or @($Statuses | Where-Object { $_ -notin @('OK', 'VERSION_OK', 'OUTDATED') }).Count -gt 0) { return 3 }
    if ($Statuses -contains 'OUTDATED') { return 4 }
    return 0
}

function Get-EmudhraVersionStatus {
    param([string]$Actual, [string]$Minimum)
    $parsed = $null
    $floor = $null
    $normalized = $Actual.Trim() -replace '^v', '' -replace '\.windows\.', '.'
    if (-not [version]::TryParse($normalized, [ref]$parsed) -or -not [version]::TryParse($Minimum, [ref]$floor)) { return 'OUTDATED' }
    if ($parsed -ge $floor) { return 'VERSION_OK' }
    return 'OUTDATED'
}

function Invoke-EmudhraProcess {
    param([string]$FilePath, [string[]]$ArgumentList, [ValidateRange(1, 120000)][int]$TimeoutMs = 15000)
    # All callers supply fixed options, package IDs or HTTPS URLs; reject ambiguous tokens.
    foreach ($item in $ArgumentList) {
        if ($item -match '[\s"]') { throw 'Process arguments must be unambiguous tokens.' }
    }
    $info = New-Object System.Diagnostics.ProcessStartInfo
    $info.FileName = $FilePath
    $info.Arguments = $ArgumentList -join ' '
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $taskProcess = New-Object System.Diagnostics.Process
    $taskProcess.StartInfo = $info
    $deadline = [Diagnostics.Stopwatch]::StartNew()
    try {
        if (-not $taskProcess.Start()) { throw 'Could not start process.' }
        $outputTask = $taskProcess.StandardOutput.ReadToEndAsync()
        $errorTask = $taskProcess.StandardError.ReadToEndAsync()
        if (-not $taskProcess.WaitForExit($TimeoutMs)) {
            $taskProcess.Kill()
            return [pscustomobject]@{ ExitCode = -1; Output = ''; TimedOut = $true }
        }
        # A child can inherit redirected pipes after its parent exits. Bound stream reads too.
        foreach ($streamTask in @($outputTask, $errorTask)) {
            $remaining = [Math]::Max(0, $TimeoutMs - [int]$deadline.ElapsedMilliseconds)
            if (-not $streamTask.Wait($remaining)) {
                return [pscustomobject]@{ ExitCode = -1; Output = ''; TimedOut = $true }
            }
        }
        return [pscustomobject]@{ ExitCode = $taskProcess.ExitCode; Output = $outputTask.GetAwaiter().GetResult(); TimedOut = $false }
    } finally {
        $taskProcess.Dispose()
    }
}

function Initialize-EmudhraTlsProbe {
    if ('EmudhraTlsProbe' -as [type]) { return }
    Add-Type -TypeDefinition @'
using System;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
public static class EmudhraTlsProbe {
    public static string Check(string hostname, int port, int timeout) {
        SslPolicyErrors policy = SslPolicyErrors.None;
        using (TcpClient client = new TcpClient()) {
            try {
                IAsyncResult connect = client.BeginConnect(hostname, port, null, null);
                using (connect.AsyncWaitHandle) {
                    if (!connect.AsyncWaitHandle.WaitOne(timeout)) return "E";
                    client.EndConnect(connect);
                }
                using (SslStream tls = new SslStream(client.GetStream(), false,
                    (sender, certificate, chain, errors) => {
                        policy = errors;
                        return errors == SslPolicyErrors.None;
                    })) {
                    IAsyncResult auth = tls.BeginAuthenticateAsClient(hostname,
                        new X509CertificateCollection(), SslProtocols.None, true, null, null);
                    using (auth.AsyncWaitHandle) {
                        if (!auth.AsyncWaitHandle.WaitOne(timeout)) return "E";
                        tls.EndAuthenticateAsClient(auth);
                    }
                    return "C";
                }
            } catch {
                return policy == SslPolicyErrors.None ? "E" : "B";
            }
        }
    }
}
'@
}

function Test-EmudhraTlsConnection {
    param([uri]$Uri, [ValidateRange(1, 30000)][int]$TimeoutMs = 8000)
    if (-not $Uri.IsAbsoluteUri -or $Uri.Scheme -ne 'https' -or $Uri.UserInfo) { throw 'An HTTPS URL without credentials is required.' }
    Initialize-EmudhraTlsProbe
    return [EmudhraTlsProbe]::Check($Uri.DnsSafeHost, $Uri.Port, $TimeoutMs)
}

function Get-EmudhraUpdatePackageId {
    return @('Git.Git', 'Microsoft.VisualStudioCode', 'Docker.DockerDesktop',
        'Obsidian.Obsidian', 'OpenJS.NodeJS.LTS', 'OpenJS.NodeJS', 'astral-sh.uv',
        'Python.Python.3.13', 'Python.Python.3.14', 'Python.Python.3.15')
}

function Get-EmudhraUpdateArgument {
    param([Parameter(Mandatory)][string]$PackageId)
    if ($PackageId -cnotin @(Get-EmudhraUpdatePackageId)) { throw 'Package ID is not in the reviewed allowlist. Use -Help to list supported IDs.' }
    return @('upgrade', '--id', $PackageId, '--exact', '--source', 'winget')
}

Export-ModuleMember -Function Test-EmudhraWindowsPlatform, Get-EmudhraVerdict, Get-EmudhraExitCode,
    Get-EmudhraVersionStatus, Invoke-EmudhraProcess, Test-EmudhraTlsConnection, Get-EmudhraUpdateArgument, Get-EmudhraUpdatePackageId

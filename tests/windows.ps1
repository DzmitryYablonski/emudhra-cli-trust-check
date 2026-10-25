# Offline regression tests. No changes to Windows certificate stores or installed applications.
#requires -Version 5.1
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repo = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $repo 'windows/Emudhra.Windows.psm1') -Force
$script:assertions = 0
function Test-Assertion {
    param([bool]$Condition, [string]$Label)
    if (-not $Condition) { throw ('FAIL: ' + $Label) }
    $script:assertions++
}
foreach ($file in Get-ChildItem (Join-Path $repo 'windows') -Recurse -Include *.ps1, *.psm1) {
    $parseTokens = $null; $parseErrors = $null
    $null = [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$parseTokens, [ref]$parseErrors)
    Test-Assertion ($parseErrors.Count -eq 0) ('syntax: ' + $file.Name)
}
Test-Assertion ((Get-EmudhraVerdict B,B,B,B C -UtcNow '2026-10-25T00:00:00Z') -eq 'OK') 'all test chains rejected and control connected'
Test-Assertion ((Get-EmudhraVerdict B,B,B,B C -UtcNow '2027-05-03T00:00:00Z') -eq 'INCONCLUSIVE') 'expired test certificates never establish distrust'
Test-Assertion ((Get-EmudhraVerdict B,C,B,B C -UtcNow '2027-05-03T00:00:00Z') -eq 'VULNERABLE') 'acceptance remains vulnerable after certificate cutoff'
Test-Assertion ((Get-EmudhraVerdict B,C,B,B E) -eq 'VULNERABLE') 'accepted chain remains vulnerable when control fails'
Test-Assertion ((Get-EmudhraVerdict B,B,B,E C) -eq 'INCONCLUSIVE') 'network error is not a certificate rejection'
Test-Assertion ((Get-EmudhraVerdict B,B,B,B E) -eq 'INCONCLUSIVE') 'failed control never passes'
Test-Assertion ((Get-EmudhraVerdict B,B,B,Q C) -eq 'INCONCLUSIVE') 'malformed probe never passes'
Test-Assertion ((Get-EmudhraVerdict B,B C) -eq 'INCONCLUSIVE') 'incomplete probe never passes'
Test-Assertion ((Get-EmudhraExitCode OK,VERSION_OK) -eq 0) 'clean summary'
Test-Assertion ((Get-EmudhraExitCode OK,VULNERABLE) -eq 1) 'vulnerable summary'
Test-Assertion ((Get-EmudhraExitCode OK,INCONCLUSIVE) -eq 3) 'incomplete summary'
Test-Assertion ((Get-EmudhraExitCode OK,OUTDATED) -eq 4) 'outdated summary'
Test-Assertion ((Get-EmudhraExitCode -Statuses @()) -eq 3) 'no checks is not a clean bill of health'
Test-Assertion ((Get-EmudhraVersionStatus '2.56.0.windows.3' '2.56.0.3') -eq 'VERSION_OK') 'Git Windows version suffix'
Test-Assertion ((Get-EmudhraVersionStatus 'v24.22.0' '24.22.1') -eq 'OUTDATED') 'older Node patch rejected'
Test-Assertion ((Get-EmudhraVersionStatus 'unknown' '1.0') -eq 'OUTDATED') 'unknown version is not a pass'
$arguments = @(Get-EmudhraUpdateArgument Git.Git)
Test-Assertion (($arguments -join ' ') -eq 'upgrade --id Git.Git --exact --source winget') 'exact, selected upgrade plan'
$blocked = $false
try { Get-EmudhraUpdateArgument 'Git.Git;whoami' } catch { $blocked = $true }
Test-Assertion $blocked 'unknown or injected package ID rejected'
$blocked = $false
try { Test-EmudhraTlsConnection -Uri 'http://localhost/' } catch { $blocked = $true }
Test-Assertion $blocked 'HTTP cannot masquerade as a TLS test'
Test-Assertion ((Test-EmudhraTlsConnection -Uri 'https://127.0.0.1:1' -TimeoutMs 100) -eq 'E') 'connection failure is inconclusive'

# Real TLS test with an isolated localhost server and a disposable synthetic key.
# It does not add certificates or keys to Windows/macOS trust stores or keychains.
$pythonName = if (Test-EmudhraWindowsPlatform) { 'python.exe' } else { 'python3' }
$pythonCommand = Get-Command $pythonName -CommandType Application | Select-Object -First 1
# Bound both a stalled process and pipes inherited by a child after the parent exits.
$timer = [Diagnostics.Stopwatch]::StartNew()
$stalled = Invoke-EmudhraProcess -FilePath $pythonCommand.Source -ArgumentList @('-c', "__import__('time').sleep(3)") -TimeoutMs 300
Test-Assertion ($stalled.TimedOut -and $stalled.ExitCode -eq -1) 'stalled subprocess reaches deadline'
Test-Assertion ($timer.ElapsedMilliseconds -lt 2500) 'subprocess deadline returns promptly'
$payload = "import subprocess,sys; subprocess.Popen([sys.executable,'-c','import time; time.sleep(3)'])"
$encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($payload))
$timer.Restart()
$inherited = Invoke-EmudhraProcess -FilePath $pythonCommand.Source -ArgumentList @('-c', "exec(__import__('base64').b64decode('$encoded'))") -TimeoutMs 1500
Test-Assertion $inherited.TimedOut 'inherited streams cannot bypass deadline'
Test-Assertion ($timer.ElapsedMilliseconds -lt 2500) 'inherited stream deadline returns promptly'
$opensslCommand = Get-Command openssl -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
$opensslPath = if ($opensslCommand) { $opensslCommand.Source } else { Join-Path $env:ProgramFiles 'Git/usr/bin/openssl.exe' }
Test-Assertion (Test-Path $opensslPath) 'OpenSSL test dependency available'
$serverInfo = New-Object System.Diagnostics.ProcessStartInfo
$serverInfo.FileName = $pythonCommand.Source
$serverInfo.Arguments = '"' + (Join-Path $PSScriptRoot 'windows_tls_server.py') + '"'
$serverInfo.UseShellExecute = $false
$serverInfo.CreateNoWindow = $true
$serverInfo.RedirectStandardOutput = $true
$serverInfo.RedirectStandardError = $true
$serverInfo.EnvironmentVariables['EMUDHRA_TEST_OPENSSL'] = $opensslPath
$serverProcess = New-Object System.Diagnostics.Process
$serverProcess.StartInfo = $serverInfo
try {
    $null = $serverProcess.Start()
    $serverError = $serverProcess.StandardError.ReadToEndAsync()
    $portTask = $serverProcess.StandardOutput.ReadLineAsync()
    Test-Assertion ($portTask.Wait(20000)) 'TLS test server startup deadline'
    $port = $portTask.GetAwaiter().GetResult()
    Test-Assertion ($null -ne $port -and $port -match '^[0-9]+$') 'TLS server reports a local port'
    Test-Assertion ((Test-EmudhraTlsConnection -Uri ('https://127.0.0.1:' + $port) -TimeoutMs 4000) -eq 'B') 'untrusted certificate is actually blocked'
    Test-Assertion ($serverProcess.WaitForExit(5000)) 'TLS server terminates'
    Test-Assertion ($serverProcess.ExitCode -eq 0) ('TLS server completed: ' + $serverError.GetAwaiter().GetResult())
} finally {
    if (-not $serverProcess.HasExited) { $serverProcess.Kill() }
    $serverProcess.Dispose()
}
$engine = (Get-Process -Id $PID).Path
$checker = Join-Path $repo 'windows/Test-Emudhra.ps1'
$updater = Join-Path $repo 'windows/Update-EmudhraWindows.ps1'
$helpOutput = & $engine -NoLogo -NoProfile -File $checker -Help 2>&1
Test-Assertion ($LASTEXITCODE -eq 0 -and ($helpOutput -join ' ') -match 'Read-only') 'checker help is available offline'
$planOutput = & $engine -NoLogo -NoProfile -File $updater -PackageId Git.Git 2>&1
Test-Assertion ($LASTEXITCODE -eq 0 -and ($planOutput -join ' ') -match 'PLAN: winget upgrade') 'default updater only shows a plan'
$updaterHelp = & $engine -NoLogo -NoProfile -File $updater -Help 2>&1
Test-Assertion ($LASTEXITCODE -eq 0 -and ($updaterHelp -join ' ') -match 'Supported package IDs:') 'updater help lists selectable IDs without prompting'
$invalidCall = "& '" + $updater.Replace("'", "''") + "' -PackageId Unknown.Package -Apply; exit " + '$LASTEXITCODE'
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($invalidCall))
$invalidResult = Invoke-EmudhraProcess -FilePath $engine -ArgumentList @('-NoLogo', '-NoProfile', '-EncodedCommand', $encoded)
Test-Assertion ($invalidResult.ExitCode -eq 2) 'invalid package selection produces usage code before applying'
if (Test-EmudhraWindowsPlatform) {
    # All update-path tests use an isolated fake executable, never the real winget.
    $sandbox = Join-Path ([IO.Path]::GetTempPath()) ('emudhra-update-test-' + [guid]::NewGuid().ToString('N'))
    $null = New-Item -ItemType Directory -Path $sandbox
    $previousPath = $env:PATH
    $previousMarker = $env:EMUDHRA_TEST_UPGRADE_MARKER
    $previousResult = $env:EMUDHRA_TEST_UPGRADE_RESULT
    try {
        $marker = Join-Path $sandbox 'invoked.txt'
        $fakeSource = Join-Path $sandbox 'FakeWinget.cs'
        $fakeExecutable = Join-Path $sandbox 'winget.exe'
        [IO.File]::WriteAllText($fakeSource, 'using System; using System.IO; class FakeWinget { static int Main(string[] args) { File.AppendAllText(Environment.GetEnvironmentVariable("EMUDHRA_TEST_UPGRADE_MARKER"), String.Join(" ", args)); return Int32.Parse(Environment.GetEnvironmentVariable("EMUDHRA_TEST_UPGRADE_RESULT")); } }')
        $compiler = Join-Path $env:WINDIR 'Microsoft.NET/Framework64/v4.0.30319/csc.exe'
        if (-not (Test-Path $compiler)) { $compiler = Join-Path $env:WINDIR 'Microsoft.NET/Framework/v4.0.30319/csc.exe' }
        & $compiler /nologo ('/out:' + $fakeExecutable) $fakeSource
        Test-Assertion ($LASTEXITCODE -eq 0) 'isolated fake updater compiled'
        $env:PATH = $sandbox + [IO.Path]::PathSeparator + $previousPath
        $env:EMUDHRA_TEST_UPGRADE_MARKER = $marker
        $env:EMUDHRA_TEST_UPGRADE_RESULT = '42'
        $whatIfOutput = & $engine -NoLogo -NoProfile -File $updater -PackageId Git.Git -Apply -WhatIf 2>&1
        Test-Assertion ($LASTEXITCODE -eq 0) ('WhatIf exits cleanly: ' + ($whatIfOutput -join ' '))
        Test-Assertion (-not (Test-Path $marker)) 'WhatIf never invokes an updater'
        $applyOutput = & $engine -NoLogo -NoProfile -File $updater -PackageId Git.Git -Apply 2>&1
        Test-Assertion ($LASTEXITCODE -eq 3) ('native update failure propagated: ' + ($applyOutput -join ' '))
        Test-Assertion ((Get-Content $marker -Raw) -eq 'upgrade --id Git.Git --exact --source winget') 'only exact selected arguments reach updater'
        $env:EMUDHRA_TEST_UPGRADE_RESULT = '-1978335189'
        $reviewOutput = & $engine -NoLogo -NoProfile -File $updater -PackageId Git.Git -Apply 2>&1
        Test-Assertion ($LASTEXITCODE -eq 4 -and ($reviewOutput -join ' ') -match 'No applicable update') 'no applicable update requires a recheck, not a success claim'
        $env:EMUDHRA_TEST_UPGRADE_RESULT = '0'
        $successOutput = & $engine -NoLogo -NoProfile -File $updater -PackageId Git.Git -Apply 2>&1
        Test-Assertion ($LASTEXITCODE -eq 0) ('successful selected update: ' + ($successOutput -join ' '))
    } finally {
        $env:PATH = $previousPath
        $env:EMUDHRA_TEST_UPGRADE_MARKER = $previousMarker
        $env:EMUDHRA_TEST_UPGRADE_RESULT = $previousResult
        Remove-Item $sandbox -Recurse -Force
    }
}
Write-Output ('PASS: {0} Windows assertions on PowerShell {1}' -f $script:assertions, $PSVersionTable.PSVersion)
# The fake updater intentionally returns nonzero; only completed assertions decide test success.
exit 0

# emudhra-cli-trust-check

Read-only diagnostics for macOS/Linux (Bash) and Windows (PowerShell 5.1 or 7). It tells you whether anything on your machine still trusts the compromised eMudhra (emSign) CA chains. Browsers are already protected. Command-line tools and language runtimes often carry their own trust stores, and many of them are not.

```bash
bash emudhra-cli-trust-check.sh                 # check this machine
bash emudhra-cli-trust-check.sh --scan ~/code   # also every virtualenv under ~/code
```

**Deutsch:** Prüft, ob ausgewählte TLS-Clients die betroffenen eMudhra-Zertifikatsketten noch akzeptieren. Der Check verändert keine Zertifikatsspeicher; Windows-Updates laufen separat und nur auf ausdrücklichen Aufruf. [Deutsche Anleitung](README.de.md).

## Background

- On 2026-10-20 it was disclosed that the private keys of 8 eMudhra intermediate CAs can be recovered from the certificates themselves ([incident tracker](https://emudhra.we-have-a-problem.com/)). Anyone can now issue a certificate for any hostname that chains to **emSign ECC Root CA - G3**, or through a cross-sign to **AAA Certificate Services**.
- Browsers enforce Certificate Transparency and blocked these chains between 17 and 22 October.
- Most CLI tools and runtimes do not enforce CT, and many ship their own root store: certifi and pip's vendored copy in Python, Node.js's built-in store, uv, Java `cacerts`, the AWS CLI and botocore. Until those are updated, they accept a forged certificate for pypi.org, registry.npmjs.org, github.com or an AWS endpoint.
- An attacker still needs a network position to use a forged certificate. The realistic case is a developer laptop on untrusted Wi-Fi, where a man-in-the-middle can swap a package during `pip install` or `npm install`, or capture a token.

## What it checks

| Area | How |
| --- | --- |
| curl, git | Real TLS connections to the incident's 4 test hosts |
| Every Python it finds (PATH, Homebrew, python.org, pyenv, conda, uv-managed) | stdlib and `requests` TLS tests; pip's vendored certifi, certifi, and botocore's own bundle checked by SHA-256 |
| Every Node.js it finds | TLS test and version |
| AWS CLI (v1 and v2) | TLS test with unsigned requests; for v2, also the content of its bundled `cacert.pem` and the version |
| Windows | .NET and curl live TLS; Git, Node, uv and selected desktop apps by version; see below |
| System CA bundles | Content, by SHA-256 of each root |
| Every Java it finds | `cacerts` content; a TLS test when `javac` is present; version |
| uv, Go, VS Code, Docker Desktop, Obsidian, Claude Code | Version compared with the fixed release |
| `--scan DIR` | Every virtualenv under DIR, plus code and config that turn TLS verification off (`verify=False`, `curl -k`, `NODE_TLS_REJECT_UNAUTHORIZED=0`, `strict-ssl false` and similar) |

Trust stores are judged by content, not by version number. A distro-patched certifi that reads the system bundle (Debian, Ubuntu, Fedora) is not flagged just because its version is old.

## How to run it

This incident is about TLS trust, so get the script over a channel you trust rather than piping `curl` into a shell.

1. **Download it** in your browser (browsers are not affected) from the [Releases](https://github.com/DzmitryYablonski/emudhra-cli-trust-check/releases) page, or clone over SSH: `git clone git@github.com:DzmitryYablonski/emudhra-cli-trust-check.git`.
2. **Check the SHA-256** against `SHA256SUMS` as shown on GitHub in your browser:
   ```bash
   shasum -a 256 emudhra-cli-trust-check.sh
   ```
3. **Read it.** The Unix checker is one Bash file. It uses no sudo, installs nothing, and writes its working files only to a temporary directory that it removes on exit. Windows uses the separate scripts and shared module in `windows/`.
4. **Run it:**
   ```bash
   bash emudhra-cli-trust-check.sh
   bash emudhra-cli-trust-check.sh --scan ~/code --scan ~/work
   bash emudhra-cli-trust-check.sh --help
   ```

It can take several minutes, depending on discovered tools and virtualenvs. The Unix checker needs Bash 3.2 or later, so the default macOS Bash works. Content checks use `python3` or, failing that, `openssl`.

## Verdicts and exit codes

| Verdict | Meaning |
| --- | --- |
| `OK` | The individual check passed: for live TLS, rejects all 4 chains and reaches pypi.org; for content checks, no listed roots found |
| `VERSION_OK` | Version floor met; not a live TLS test |
| `VULNERABLE` | Accepts a compromised chain, or a trust store it uses still holds one of the roots |
| `OUTDATED` | Older than the fixed release, or a finding to review |
| `INCONCLUSIVE` | A test host or the control site was unreachable. Check the network and run it again |
| `BROKEN` | The interpreter or venv could not run the probe |

Check exit codes: `0` all performed checks passed, `1` vulnerable, `2` usage error, `3` inconclusive/broken, `4` outdated/manual review. Vulnerable findings take precedence over incomplete checks. **Automation change:** incomplete or outdated-only runs now return nonzero instead of `0`. At the end the script prints the exact fix commands for your machine. It never runs them.

## Windows

Download/extract the repository ZIP and open PowerShell **in the repository directory**:

```powershell
Get-FileHash .\windows\*.ps1,.\windows\*.psm1 -Algorithm SHA256
.\windows\Test-Emudhra.ps1
.\windows\Test-Emudhra.ps1 -Help
```

Compare the printed SHA-256 values with `SHA256SUMS`. The check needs no administrator privileges. Follow your organisation's script-signing and execution policies. Windows/.NET connects directly with revocation checking; curl retains proxy/CA environment settings. These paths may differ behind a corporate proxy.

Optional, selected **installed application** updates with WinGet (separate from the read-only diagnostic):

```powershell
.\windows\Update-EmudhraWindows.ps1 -PackageId Git.Git,Microsoft.VisualStudioCode
.\windows\Update-EmudhraWindows.ps1 -PackageId Git.Git,Microsoft.VisualStudioCode -Apply
.\windows\Test-Emudhra.ps1
```

The first command only prints the plan; `-Apply -WhatIf` simulates execution and `-Help` lists allowed IDs. Updates can change major versions, update dependencies or request elevation. Windows OS updates remain with Windows Update or your managed channel. Neither script changes certificate stores or execution policies. See [WinGet upgrade](https://learn.microsoft.com/en-us/windows/package-manager/winget/upgrade).

Updater exit codes: `0` plan/simulation or selected updates completed, `2` usage, `3` update failure, `4` no applicable update. WinGet also uses the last case for unknown versions or platform constraints; inspect its output and rerun the check rather than assuming protection. [Microsoft's implementation](https://github.com/microsoft/winget-cli/blob/master/src/AppInstallerCLICore/Workflows/UpdateFlow.cpp).

## Development and review

Run `python3 tests/check.py` and `shellcheck emudhra-cli-trust-check.sh`. On Windows, run `./tests/windows.ps1` (Python and OpenSSL required). Tests use fixtures, localhost TLS and a fake WinGet executable; they do not update installed applications or change trust stores.

GitHub Actions runs the checks on macOS, Linux, Windows PowerShell 5.1 and PowerShell 7, with ShellCheck, PSScriptAnalyzer and SHA-256 integrity checks. Incomplete probes, expired test certificates and malformed bundles have explicit regression coverage.

Please contribute focused pull requests against this repository so incident data, fixes and Windows support can be reviewed together. Changes to result semantics or version floors should include tests and matching English/German documentation. Repository maintainers decide release versions and merging.

## Example

The `amazon/aws-cli:latest` container on 2026-10-24, trimmed:

```text
== eMudhra CA compromise: Linux check (read-only), emudhra-cli-trust-check 7.0.0 ==
  Amazon Linux 2023.12.20261021 | 2026-10-24 21:29 | fixed versions as of 2026-10-24
  tracker: https://emudhra.we-have-a-problem.com
  OK = rejects all 4 test chains and still reaches https://pypi.org/
...
== System CA bundles (content) ==
  VULNERABLE   /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem
               contains emSign-ECC-G3: TLS clients that read this bundle trust them

== curl ==
  VULNERABLE   curl 8.21.0  /usr/bin/curl
               TLS ACCEPTS compromised chains

== Python interpreters (stdlib TLS, pip, certifi, requests) ==
  VULNERABLE   /usr/bin/python3
               py 3.9.25 | stdlib ACCEPTS compromised chains

== AWS CLI (TLS test with unsigned requests) ==
  OK           aws 2.38.5  /usr/local/bin/aws
               TLS rejects 4/4 test chains | fixed from 2.38.4
...
== Summary ==
  vulnerable: 3   outdated/review: 2   inconclusive: 0

  Suggested fixes (this script changes nothing; run these yourself):
  - /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem contains emSign-ECC-G3: upgrade ca-certificates (AL2023: dnf --releasever=latest upgrade ca-certificates; AL2: yum update ca-certificates); if the store still trusts emSign-ECC-G3, put the matching PEMs into /etc/pki/ca-trust/source/blocklist/ and run update-ca-trust extract
  ...
```

The AWS CLI there is fixed, but curl and Python read the system bundle, which still holds the emSign root.

## Fixed versions (as of 2026-10-24)

| Component | Fixed in |
| --- | --- |
| certifi | 2026.10.23 |
| pip | 26.2.2 |
| uv | 0.13.5 |
| Node.js | 22.23.4, 24.22.1, 26.12.1 |
| AWS CLI v2 | 2.38.4 ([aws/aws-cli@011f84b](https://github.com/aws/aws-cli/commit/011f84bfaf)) |
| botocore | 1.43.117 ([boto/botocore@0a6c7b6](https://github.com/boto/botocore/commit/0a6c7b6b3e)) |
| Java | 8u511, 11.0.33, 17.0.21, 21.0.13, 25.0.5, 27.0.1 |
| Go | 1.26.10, 1.27.3 |
| VS Code | 1.143.1 |
| Docker Desktop | 4.96.2 |
| Obsidian | 1.14.5 |
| Claude Code | 2.1.303 |

`--version` prints the date these were last checked. Newer releases may exist by the time you read this. The TLS tests and content checks do not depend on this list.

## Common fixes

The script prints the fix for each finding. These come up most often:

- **Python project venvs:** `uv lock --upgrade-package certifi && uv sync`, or `pip install -U "certifi>=2026.10.23"`.
- **Node.js:** upgrade to 22.23.4, 24.22.1 or 26.12.1 or later. Old installs left outside PATH still run from cron, launchd or systemd, so update them or assess their dependents before removing them.
- **AWS CLI v2 before 2.38.4:** update it. Until then, `export AWS_CA_BUNDLE=/etc/ssl/cert.pem` on macOS or point it at your distro bundle, provided the script reports that bundle as `OK`.
- **System CA bundle:** update `ca-certificates`. If the distro has not shipped the removal yet, blocklist the roots (`/etc/ca-certificates.conf` on Debian and Ubuntu, `/etc/pki/ca-trust/source/blocklist/` on RHEL and Amazon Linux).
- **Java 8 older than 8u511:** update it, or remove it if nothing needs it.

## Limits

- `OK` means "rejects the 4 known test chains, and the trust stores checked are clean today". It is not a full security assessment of the machine.
- The test hosts belong to the incident tracker. If they are unreachable, TLS rows report `INCONCLUSIVE`. Their certificates expire on 2027-05-03. After that date a client would reject them as expired, which looks the same as rejecting the compromised chain, so TLS tests report `INCONCLUSIVE` and only the content and version checks remain.
- A fixed JDK keeps the roots in `cacerts` and blocks the compromised intermediates instead. The script tells the two apart with a TLS test, which needs `javac`. A JDK line whose fix has not shipped yet shows `OUTDATED` even when that test passes.
- `--scan` prints file names and line numbers, never matching source lines. Logs can still contain local paths and software versions; review them before sharing.
- Not covered exhaustively: browsers, mobile apps, containers and independent trust stores. Windows does not inspect Python/Java CA bundles, AWS bundles or project environments. For a Docker image or a CI runner, run the script inside it.
- Network use: the 4 test hosts, pypi.org, and github.com (as git's control). The AWS CLI test sends unsigned requests (`--no-sign-request`), so no AWS credentials are loaded or sent. No diagnostic reports are uploaded; the public servers still receive normal request metadata.

## Other tools

- [ikow/emudhra-ca-checker](https://github.com/ikow/emudhra-ca-checker): system bundle, certifi, and runtime versions.
- [0xAJStrike/emsign-trust-scan](https://github.com/0xAJStrike/emsign-trust-scan): offline scan of trust stores, Java `cacerts`, NSS and container images.
- [hybridsakura/emsign-trust-check](https://github.com/hybridsakura/emsign-trust-check): browser probes for an intranet.

This one focuses on the CLI tools and runtimes on a developer machine, and tests them with real TLS connections.

## Version history

- **Unreleased:** Windows diagnostics and selected WinGet updates; fail-safe errors, private source-scan output, bounded probes, regression tests/CI, and a German guide. The 7.0.0 AWS/botocore checks and test-certificate expiry guard are retained.

- **7.0.0** (2026-10-24): the first public release. Compared with v6 it adds the AWS CLI check (TLS test, bundled `cacert.pem` and version) and botocore's fallback bundle in venvs without certifi. TLS tests also stop reporting OK once the test certificates expire.
- **1 to 6:** used internally as `certificate-check-vN.sh` before the public release.

## Credits

The test hosts and the incident data come from the [eMudhra incident tracker](https://emudhra.we-have-a-problem.com/).
- Stanislav Stolberg: Windows support, diagnostic hardening, regression tests/CI and German documentation.
<!-- TODO before publishing: credit the contributor who added Linux support. -->

## License

[MIT](LICENSE). Provided as is, without warranty. Not affiliated with eMudhra, Sectigo or the authors of the tracker.

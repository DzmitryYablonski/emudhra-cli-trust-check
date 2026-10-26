# emudhra-cli-trust-check

A read-only check for macOS and Linux. It tells you whether anything on your machine still trusts the compromised eMudhra (emSign) CA chains. Browsers are already protected. Command-line tools and language runtimes often carry their own trust stores, and many of them are not.

```bash
bash emudhra-cli-trust-check.sh                 # check this machine
bash emudhra-cli-trust-check.sh --scan ~/code   # also every virtualenv under ~/code
```

## Scope

The whole tool is one file: you download one file, check one hash, read one file and run one command. These rules keep it that way.

- **One self-contained Bash file for macOS and Linux.** No modules, installers or helper files. A release ships only `emudhra-cli-trust-check.sh` and `SHA256SUMS`, and `SHA256SUMS` covers only that script.
- **Read-only.** It never installs, updates, repairs or reconfigures anything. It prints the fix commands, and you decide whether to run them.
- **Limited network use.** It connects only to the incident's test hosts and the control sites listed under [Limits](#limits). There is no telemetry, and no credentials are sent.
- **Readable in one sitting.** It stays under 1,200 lines of Bash, so a new check has to be worth the lines it adds.
- **Windows is not on `main`** until it can be tested on Windows.
- **Everything else is for development.** The tests and CI are there for maintainers. You don't need to read or run them to use the tool.

Contributions are welcome when they follow these rules. Please send focused pull requests, one topic each.

## Background

- On 2026-10-20 it was disclosed that the private keys of 8 eMudhra intermediate CAs can be recovered from the certificates themselves ([incident tracker](https://emudhra.we-have-a-problem.com/)). Anyone can now issue a certificate for any hostname that chains to **emSign ECC Root CA - G3**, or through a cross-sign to **AAA Certificate Services**.
- Browsers enforce Certificate Transparency and blocked these chains between 17 and 22 October.
- Most CLI tools and runtimes do not enforce CT, and many ship their own root store: certifi and pip's vendored copy in Python, Node.js's built-in store, uv, Java `cacerts`, the AWS CLI and botocore. Until those are updated, they accept a forged certificate for pypi.org, registry.npmjs.org, github.com or an AWS endpoint.
- An attacker still needs a network position to use a forged certificate. The realistic case is a developer laptop on untrusted Wi-Fi, where a man-in-the-middle can swap a package during `pip install` or `npm install`, or capture a token.

## What it checks

| Area | How |
| --- | --- |
| curl, git | Real TLS connections to the incident's 4 test hosts; `~/.curlrc` checked for `insecure` and `cacert` |
| Every Python it finds (PATH, Homebrew, python.org, pyenv, conda, uv-managed) | stdlib and `requests` TLS tests; pip's vendored certifi, certifi, and botocore's own bundle checked by SHA-256 |
| Every Node.js it finds | TLS test and version |
| Every Bun it finds (PATH, `~/.bun/bin`, Homebrew) | TLS test and version |
| AWS CLI (v1 and v2) | TLS test with unsigned requests; for v2, also the content of its bundled `cacert.pem` and the version |
| System CA bundles | Content, by SHA-256 of each root |
| Every Java it finds | `cacerts` content, including emSign Root CA - G1 and G2, which OpenJDK also says to remove; a TLS test when `javac` is present; the October 2026 release as a minimum version |
| Perl `Mozilla::CA` | Content of its CA bundle |
| uv, Go, Deno, GitHub CLI, Docker CLI, conda, rustup, VS Code, Docker Desktop, Obsidian, Claude Code | Version compared with the fixed release |
| `--scan DIR` | Every virtualenv under DIR, plus code and config that turn TLS verification off (`verify=False`, `curl -k`, `NODE_TLS_REJECT_UNAUTHORIZED=0`, `strict-ssl false` and similar) |

Trust stores are judged by content, not by version number. A distro-patched certifi that reads the system bundle (Debian, Ubuntu, Fedora) is not flagged just because its version is old.

## How to run it

This incident is about TLS trust, so get the script over a channel you trust rather than piping `curl` into a shell.

1. **Download it** in your browser (browsers are not affected) from the [Releases](https://github.com/DzmitryYablonski/emudhra-cli-trust-check/releases) page, or clone over SSH: `git clone git@github.com:DzmitryYablonski/emudhra-cli-trust-check.git`.
2. **Check the SHA-256** against `SHA256SUMS` as shown on GitHub in your browser:
   ```bash
   shasum -a 256 emudhra-cli-trust-check.sh
   ```
3. **Read it.** It is one bash file. It uses no sudo, installs nothing, and writes only to a temporary directory that it removes on exit.
4. **Run it:**
   ```bash
   bash emudhra-cli-trust-check.sh
   bash emudhra-cli-trust-check.sh --scan ~/code --scan ~/work
   bash emudhra-cli-trust-check.sh --help
   bash emudhra-cli-trust-check.sh --strict  # also fail on incomplete/outdated checks
   ```

It takes 20 to 60 seconds, longer with `--scan` over large folders, and needs bash 3.2 or later, so the default macOS bash works. Content checks use `python3` or, failing that, `openssl`.

## Verdicts and exit codes

| Verdict | Meaning |
| --- | --- |
| `OK` | Rejects all 4 test chains and still reaches pypi.org; trust store content is clean |
| `VERSION_OK` | Version check passed; not a live TLS test |
| `VULNERABLE` | Accepts a compromised chain, or a trust store it uses still holds one of the roots |
| `OUTDATED` | Older than the fixed release, or a finding to review |
| `INCONCLUSIVE` | A test host or the control site was unreachable. Check the network and run it again |
| `BROKEN` | The interpreter or venv could not run the probe |

The exit code is `0` when nothing is vulnerable, `1` when something is, and `2` on a usage error. With `--strict`, it also returns `3` for inconclusive/broken checks or `4` for outdated/manual-review findings. Vulnerable findings still take precedence (`1`). The default exit codes remain unchanged. At the end the script prints the exact fix commands for your machine. It never runs them.

## Example

The `amazon/aws-cli:latest` container on 2026-10-25, trimmed:

```text
== eMudhra CA compromise: Linux check (read-only), emudhra-cli-trust-check 7.2.0 ==
  Amazon Linux 2023.12.20261021 | 2026-10-25 19:14 | fixed versions as of 2026-10-25
  tracker: https://emudhra.we-have-a-problem.com
  OK (TLS) = rejects all 4 test chains and still reaches https://pypi.org/
  VERSION_OK = version check only; bundle/content checks are labelled separately
  Scope: discovered tools only; browsers, containers and all project environments are not covered by default
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

## Fixed versions (as of 2026-10-25)

| Component | Fixed in |
| --- | --- |
| certifi | 2026.10.23 |
| pip | 26.2.2 |
| uv | 0.13.5 |
| Node.js | 22.23.4, 24.22.1, 26.12.1 |
| Bun | 1.4.4 |
| AWS CLI v2 | 2.38.4 ([aws/aws-cli@011f84b](https://github.com/aws/aws-cli/commit/011f84bfaf)) |
| botocore | 1.43.117 ([boto/botocore@0a6c7b6](https://github.com/boto/botocore/commit/0a6c7b6b3e)) |
| Java | No fixed release yet: the fix will list JDK-8395690 ([CVE-2026-114820](https://nvd.nist.gov/vuln/detail/CVE-2026-114820)) in its release notes. Until then, remove the roots as described in the [OpenJDK guidance](https://openjdk.org/emudhra). Releases older than October 2026 (8u511, 11.0.33, 17.0.21, 21.0.13, 25.0.5, 27.0.1) also lack the [CVE-2026-91403](https://nvd.nist.gov/vuln/detail/CVE-2026-91403) fix |
| Perl Mozilla::CA | 20261020 |
| Deno | 2.9.8 |
| GitHub CLI | 2.102.1 |
| Docker CLI | 29.9.2 |
| conda | 26.9.4 |
| rustup | 1.29.2 |
| Go | 1.26.10, 1.27.3 |
| VS Code | 1.143.1 |
| Docker Desktop | 4.96.2 |
| Obsidian | 1.14.5 |
| Claude Code | 2.1.303 |

`--version` prints the date these were last checked. Newer releases may exist by the time you read this. The TLS tests and content checks do not depend on this list.

## Common fixes

The script prints the fix for each finding. These come up most often:

- **Python project venvs:** `uv lock --upgrade-package certifi && uv sync`, or `pip install -U "certifi>=2026.10.23"`.
- **Node.js:** upgrade to 22.23.4, 24.22.1 or 26.12.1 or later. Old installs left outside PATH still run from cron, launchd or systemd, so remove them.
- **Bun:** `bun upgrade` to 1.4.4 or later. Bun carries its own root store, so updating `ca-certificates` or passing `--use-system-ca` does not remove the roots.
- **AWS CLI v2 before 2.38.4:** update it. Until then, `export AWS_CA_BUNDLE=/etc/ssl/cert.pem` on macOS or point it at your distro bundle, provided the script reports that bundle as `OK`.
- **System CA bundle:** update `ca-certificates`. If the distro has not shipped the removal yet, blocklist the roots (`/etc/ca-certificates.conf` on Debian and Ubuntu, `/etc/pki/ca-trust/source/blocklist/` on RHEL and Amazon Linux).
- **Java:** no release fixes JDK-8395690 yet. Remove the four aliases `emsignrootcag1`, `emsignrootcag2`, `emsigneccrootcag3` and `comodoaaaca` from `cacerts` as the [OpenJDK guidance](https://openjdk.org/emudhra) shows, or remove the Java if nothing needs it. Update to a release from October 2026 or later, and again when a vendor ships JDK-8395690.

## Limits

- `OK` means "rejects the 4 known test chains, and the trust stores checked are clean today". It is not a full security assessment of the machine.
- The test hosts belong to the incident tracker. If they are unreachable, TLS rows report `INCONCLUSIVE`. Their certificates expire on 2027-05-03. After that date a client would reject them as expired, which looks the same as rejecting the compromised chain, so TLS tests report `INCONCLUSIVE` and only the content and version checks remain.
- Until a JDK ships JDK-8395690, every Java whose `cacerts` still holds one of the roots shows `OUTDATED`, even when its TLS test passes. The test chains cover only the 8 known intermediates, and the October 2026 builds block those while keeping the roots.
- `--scan` prints file names and line numbers, never matching source lines. Output can still contain local paths and software versions; review it before sharing.
- Not covered: Windows, browsers, mobile apps and other machines. For a Docker image or a CI runner, run the script inside it.
- Code-signing trust (Windows Authenticode, `jarsigner`) is not checked. Programs that embed their own root list, such as Rust binaries built with webpki-roots before 1.0.10 or Electron apps before 44.9.1, 43.8.1 or 42.11.16, are covered only for the tools listed above.
- Network use: the 4 test hosts, pypi.org, and github.com (as git's control). The AWS CLI test sends unsigned requests (`--no-sign-request`), so no AWS credentials are loaded or sent. There is no telemetry.

## Related advisories

These IDs help you match scanner findings to this incident:

- [GHSA-6q48-6c7w-9gw2](https://github.com/advisories/GHSA-6q48-6c7w-9gw2): certifi. The advisory names 2026.10.19 as fixed; this script requires 2026.10.23, which also follows Mozilla's later removals.
- [CVE-2026-91403](https://nvd.nist.gov/vuln/detail/CVE-2026-91403): Oracle Java SE and GraalVM.
- [CVE-2026-114820](https://nvd.nist.gov/vuln/detail/CVE-2026-114820) / JDK-8395690: Java SE, OpenJDK ([guidance](https://openjdk.org/emudhra)). It also covers builds released after CVE-2026-91403.
- [CVE-2026-114406](https://nvd.nist.gov/vuln/detail/CVE-2026-114406): the Red Hat `ca-certificates` package.
- [CVE-2026-113812](https://nvd.nist.gov/vuln/detail/CVE-2026-113812): Perl Mozilla::CA.

## Other tools

- [ikow/emudhra-ca-checker](https://github.com/ikow/emudhra-ca-checker): system bundle, certifi, and runtime versions.
- [0xAJStrike/emsign-trust-scan](https://github.com/0xAJStrike/emsign-trust-scan): offline scan of trust stores, Java `cacerts`, NSS and container images.
- [hybridsakura/emsign-trust-check](https://github.com/hybridsakura/emsign-trust-check): browser probes for an intranet.

This one focuses on the CLI tools and runtimes on a developer machine, and tests them with real TLS connections.

## Version history

- **7.2.0** (2026-10-25): Java is judged by its `cacerts` content. No release fixes JDK-8395690 (CVE-2026-114820) yet, so any of the roots OpenJDK says to remove is `OUTDATED`, including emSign Root CA - G1 and G2, even when the TLS test passes. Releases older than October 2026 are `OUTDATED` too. New checks cover Perl Mozilla::CA and the versions of Bun, Deno, GitHub CLI, Docker CLI, conda and rustup. The README gained a list of related advisories.
- **7.1.0** (2026-10-25): diagnostic hardening. Incomplete probes, malformed bundles and failed Java checks no longer pass. Probes have time limits and no longer pick up your git credentials, `.netrc` or `.curlrc`, and `~/.curlrc` is checked on its own for `insecure` and `cacert`. `--scan` prints only file names and line numbers. Environment variables that turn TLS verification off are reported. `VERSION_OK` marks version-only checks, and `--strict` adds exit codes 3 and 4. Regression tests and CI were added.
- **7.0.0** (2026-10-24): the first public release. Compared with v6 it adds the AWS CLI check (TLS test, bundled `cacert.pem` and version) and botocore's fallback bundle in venvs without certifi. TLS tests also stop reporting OK once the test certificates expire.
- **1 to 6:** used internally as `certificate-check-vN.sh` before the public release.

## Development

Tests and CI are development tooling only: `python3 tests/check.py`, `shellcheck emudhra-cli-trust-check.sh`. GitHub Actions runs these on macOS and Linux. Release users still need only the script and its single SHA-256 entry.

## Credits

The test hosts and the incident data come from the [eMudhra incident tracker](https://emudhra.we-have-a-problem.com/).
[Stanislav Stolberg](https://github.com/stanistolberg) contributed diagnostic hardening, regression tests and CI.

<!-- TODO before publishing: credit the contributor who added Linux support. -->

## License

[MIT](LICENSE). Provided as is, without warranty. Not affiliated with eMudhra, Sectigo or the authors of the tracker.

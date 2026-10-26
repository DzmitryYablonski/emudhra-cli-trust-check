#!/bin/bash
# emudhra-cli-trust-check.sh: eMudhra intermediate CA compromise (2026-10-20), read-only check for macOS and Linux.
# Changes nothing: it only tests and reports, and prints the commands to fix what it finds.
# Run `bash emudhra-cli-trust-check.sh --help` for usage. Reference: https://emudhra.we-have-a-problem.com
# https://github.com/DzmitryYablonski/emudhra-cli-trust-check (MIT License)
set -u
set -o pipefail
umask 077
export HOMEBREW_NO_AUTO_UPDATE=1

# Versions 1 to 6 were used internally (certificate-check-vN.sh); 7.0.0 is the first public release.
VERSION="7.2.0"
# The fixed versions below were checked on this date; newer releases may have shipped since.
AS_OF="2026-10-25"
TRACKER="https://emudhra.we-have-a-problem.com"
TEST_URLS=(
  "https://dv-g3b-emudhra.we-have-a-problem.com/"
  "https://dv-g3b-aaa-emudhra.we-have-a-problem.com/"
  "https://dv-g3b-noct-emudhra.we-have-a-problem.com/"
  "https://dv-g3b-aaa-noct-emudhra.we-have-a-problem.com/"
)
# A small page: /simple/ is ~47 MB, which every full GET (requests, curl) would download.
CONTROL_URL="https://pypi.org/"
NH=${#TEST_URLS[@]}
# The test hosts' own certificates expire on 2027-05-03..05 (UTC). After that every client rejects them
# as expired, which would read as "rejects the compromised chains", so TLS tests stop reporting OK.
TEST_CERTS_NOT_AFTER=20270503
TLS_EXPIRED=0
[ "$(date -u +%Y%m%d)" -ge "$TEST_CERTS_NOT_AFTER" ] && TLS_EXPIRED=1

# 2026.10.18 dropped every emSign root, 2026.10.19 restored the unaffected C3/C1/G1, and 2026.10.23
# (Mozilla sync) dropped C3 and C1 again: the floor matches current Mozilla trust.
FIXED_CERTIFI="2026.10.23"
FIXED_PIP="26.2.2"
FIXED_UV="0.13.5"
# aws-cli 011f84bf and botocore 0a6c7b6b removed AAA Certificate Services from their own CA bundles.
FIXED_AWSCLI="2.38.4"
FIXED_BOTOCORE="1.43.117"
FIXED_VSCODE="1.143.1"
FIXED_DOCKER="4.96.2"
FIXED_OBSIDIAN="1.14.5"
FIXED_CLAUDE="2.1.303"
FIXED_MOZILLA_CA="20261020"  # Perl, CVE-2026-113812
# Bun ships its own root store ("root certificates are updated to NSS 3.131.1" in 1.4.4): 1.3.x accepts
# the direct G3 test chains, 1.4.4 rejects all 4 as revoked.
FIXED_BUN="1.4.4"
# Version-only checks for tools that ship their own root store or TLS stack (tracker list).
FIXED_DENO="2.9.8"; FIXED_GH="2.102.1"; FIXED_DOCKER_CLI="29.9.2"; FIXED_CONDA="26.9.4"; FIXED_RUSTUP="1.29.2"

# The roots the compromised intermediates chain to, one "SHA-256 of the DER certificate:name" per
# line: the single list behind every content check (Python probe, system bundles, Java cacerts,
# the AWS CLI's own bundle).
DISTRUSTED_ROOTS="D7A7A0FB5D7E2731D771E9484EBCDEF71D5F0C3E0A2948782BC83EE0EA699EF4:AAA
86A1ECBA089C4A8D3BBE2734C612BA341D813E043CF9E8A862CD5C57A36BBE6B:emSign-ECC-G3
7DD78D5F4F13459A83DFF9ABBBA62EDBAF6F2D102BF257FD712F4D9F2746ED8D:emSign-TLS-G3
F2EDAAFF3D9B701FB4D14C9F285F8C0BAD90FC3BCC1FA07D47F4718EDABA34A5:emSign-CS-G3"
export DISTRUSTED_ROOTS
# OpenJDK (https://openjdk.org/emudhra) also removes emSign Root CA - G1 and G2 from cacerts. Mozilla's
# store and certifi keep trusting them, so only the Java check uses these two.
JAVA_EXTRA_ROOTS="40F6AF0346A99AA1CD1D555A4E9CCE62C7F9634603EE406615833DC8C8D00367:emSign-G1
1AA0C2709E831BD6E3B5129A00BA41F7EEEF020872F1E6504BF0F6C3F24F3AF3:emSign-G2"

usage() {
  cat <<'EOF'
emudhra-cli-trust-check.sh: read-only check for the eMudhra CA compromise (2026-10-20) on macOS and Linux.

Usage:
  bash emudhra-cli-trust-check.sh               check this machine
  bash emudhra-cli-trust-check.sh --scan DIR    also check Python virtualenvs under DIR and list
                                                places in DIR that disable TLS verification
                                                (--scan can be given several times)
  bash emudhra-cli-trust-check.sh --strict      nonzero for incomplete/outdated results too
  bash emudhra-cli-trust-check.sh --version     print the version
  bash emudhra-cli-trust-check.sh --help        this text

What it checks:
  curl, git, every Python interpreter (stdlib TLS, pip, certifi, requests), every Node.js,
  every Bun and the AWS CLI are tested against the incident's 4 test chains. uv, AWS CLI v2,
  Go, Deno, GitHub CLI, Docker CLI, conda, rustup, VS Code, Docker Desktop, Obsidian and
  Claude Code are compared with their fixed releases. Perl's Mozilla::CA bundle is checked
  by content.
  ~/.curlrc is checked separately for insecure (-k) and cacert/capath, since the probes skip it.
  Trust stores are judged by content: the system CA bundles, certifi, pip's vendored certifi,
  botocore's own bundle (used when certifi is absent), the AWS CLI's bundle and every Java
  cacerts are searched for the 4 distrusted roots by SHA-256, so a distro-patched certifi that
  reads the system bundle (Debian, Ubuntu, Fedora) is not flagged for its old version number.
  Java: no release fixes JDK-8395690 yet, so cacerts decides. Any of the roots OpenJDK says to
  remove (the 4 above plus emSign Root CA - G1 and G2) is OUTDATED; with javac, a TLS test too.
  On Linux the app bundle checks are replaced by `code --version`; Docker Desktop and
  Obsidian are not checked.

Verdicts:
  OK            rejects all 4 test chains and still reaches https://pypi.org
  VULNERABLE    accepts a compromised chain, or carries a trust store that still has the roots
  OUTDATED      older than the fixed release, or a finding to review
  INCONCLUSIVE  a test host or the control site was unreachable: check the network, run again
  BROKEN        the interpreter or venv could not run the probe

Safety: read-only, no sudo, no installs. Network use: TLS requests to the 4 test hosts, plus
pypi.org and github.com as controls. The AWS CLI test sends unsigned requests
(--no-sign-request), so no AWS credentials are loaded or sent.
Limits: OK means "rejects the 4 known test chains today", not "this machine is safe". The test
hosts' certificates expire on 2027-05-03; after that TLS tests report INCONCLUSIVE.
Exit code: 0 nothing vulnerable, 1 vulnerable, 2 usage error (default).
With --strict: also 3 inconclusive/broken checks, 4 outdated or manual review required.
VERSION_OK means version check only, not a live TLS test.
--scan prints file names and line numbers, never matching source lines.
Reference: https://emudhra.we-have-a-problem.com
EOF
}

STRICT=0
SCAN_DIRS=""
while [ $# -gt 0 ]; do
  case "$1" in
    --strict) STRICT=1 ;;
    --scan)
      if [ "$#" -lt 2 ] || [ ! -d "$2" ]; then
        echo "--scan needs an existing directory" >&2
        exit 2
      fi
      SCAN_DIRS="$SCAN_DIRS$(cd "$2" && pwd -P)
"
      shift ;;
    -h|--help) usage; exit 0 ;;
    -V|--version) echo "emudhra-cli-trust-check $VERSION (fixed versions as of $AS_OF)"; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

TMP=$(mktemp -d "${TMPDIR:-/tmp}/emudhra.XXXXXX") || exit 1
trap 'rm -rf "$TMP"' EXIT
: > "$TMP/actions"
printf '%s\n' "$DISTRUSTED_ROOTS" > "$TMP/distrusted.txt"
printf '%s\n' "$DISTRUSTED_ROOTS" "$JAVA_EXTRA_ROOTS" > "$TMP/java-distrusted.txt"

if [ -t 1 ]; then RED=$'\033[31m'; GRN=$'\033[32m'; YEL=$'\033[33m'; BLD=$'\033[1m'; RST=$'\033[0m'
else RED=""; GRN=""; YEL=""; BLD=""; RST=""; fi
VULN=0; WARN=0; INCONC=0
OS=$(uname -s)

has(){ command -v "$1" >/dev/null 2>&1; }
section() { printf '\n%s== %s ==%s\n' "$BLD" "$1" "$RST"; }
action() { printf '%s\n' "$*" >> "$TMP/actions"; }
# shellcheck disable=SC2088  # the literal "~" is display text
short() { case "$1" in "$HOME"/*) printf '~/%s' "${1#"$HOME"/}" ;; *) printf '%s' "$1" ;; esac; }

row() { # row VERDICT LABEL [DETAILS]
  local c="$RST"
  case "$1" in
    OK) c="$GRN" ;;
    VULNERABLE) c="$RED"; VULN=$((VULN + 1)) ;;
    OUTDATED) c="$YEL"; WARN=$((WARN + 1)) ;;
    INCONCLUSIVE|BROKEN) c="$YEL"; INCONC=$((INCONC + 1)) ;;
  esac
  printf '  %s%-12s%s %s\n' "$c" "$1" "$RST" "$2"
  if [ -n "${3:-}" ]; then printf '  %-12s %s\n' "" "$3"; fi
}

rank() { case "$1" in VULNERABLE) echo 4 ;; BROKEN|INCONCLUSIVE) echo 3 ;; OUTDATED) echo 2 ;; OK) echo 1 ;; *) echo 0 ;; esac; }
worse() { if [ "$(rank "$1")" -ge "$(rank "$2")" ]; then echo "$1"; else echo "$2"; fi; }

ver_ge() { # Compare stable numeric releases; unknown/prerelease versions never establish a fix.
  local a=$1 b=$2
  a=${a#go}; a=${a#v}; b=${b#go}; b=${b#v}
  [[ "$a" =~ ^[0-9]+(\.[0-9]+)*(\+[0-9A-Za-z.-]+)?(-LTS)?$ ]] || return 1
  [[ "$b" =~ ^[0-9]+(\.[0-9]+)*$ ]] || return 1
  a=${a%%+*}; a=${a%-LTS}
  awk -v a="$a" -v b="$b" 'BEGIN {
    n = split(a, x, /[^0-9]+/); m = split(b, y, /[^0-9]+/); k = (n > m) ? n : m
    for (i = 1; i <= k; i++) {
      xi = (i <= n) ? x[i] + 0 : 0; yi = (i <= m) ? y[i] + 0 : 0
      if (xi > yi) exit 0
      if (xi < yi) exit 1
    }
    exit 0 }'
}

resolve() { # resolve PATH: follow symlinks, print the physical path
  local p="$1" l d n=0
  while [ -L "$p" ] && [ $n -lt 40 ]; do
    l=$(readlink "$p"); n=$((n + 1))
    case "$l" in /*) p="$l" ;; *) p="$(dirname "$p")/$l" ;; esac
  done
  # -P: resolve ".." physically. AL2023 links /etc/ssl/certs/ca-certificates.crt -> ../tls-ca-bundle.pem
  # inside the symlinked /etc/ssl/certs, which a logical cd lands in the wrong directory for.
  d=$(cd -P "$(dirname "$p")" 2>/dev/null && pwd -P) || d=$(dirname "$p")
  printf '%s/%s\n' "$d" "$(basename "$p")"
}

verdict() { # verdict REJECTED CONNECTED ERRORS CONTROL_OK
  local value
  [ "$#" -eq 4 ] || { echo INCONCLUSIVE; return; }
  for value in "$@"; do
    case "$value" in ""|*[!0-9]*) echo INCONCLUSIVE; return ;; esac
    [ "${#value}" -le 2 ] || { echo INCONCLUSIVE; return; }
  done
  if [ "$((10#$1 + 10#$2 + 10#$3))" -ne "$NH" ] || [ "$4" -gt 1 ]; then
    echo INCONCLUSIVE; return
  fi
  if [ "$2" -gt 0 ]; then echo VULNERABLE
  elif [ "$1" -eq "$NH" ] && [ "$4" -eq 1 ] && [ "$TLS_EXPIRED" = 0 ]; then echo OK
  else echo INCONCLUSIVE; fi
}
brief() { # brief VERDICT REJECTED CONTROL_OK
  case "$1" in
    OK) echo "rejects $2/$NH test chains" ;;
    VULNERABLE) echo "ACCEPTS compromised chains" ;;
    *) if [ "$TLS_EXPIRED" = 1 ]; then echo "inconclusive (the test certificates have expired)"
       elif [ "$3" = 1 ]; then echo "inconclusive ($2/$NH rejected, rest errored)"; else echo "inconclusive (control site unreachable)"; fi ;;
  esac
}

BREW_PREFIX="/nonexistent"
has brew && BREW_PREFIX=$(brew --prefix 2>/dev/null)

# ---------------------------------------------------------------- probes

run_timed() {
  (
    seconds="$1"; job=""; timer=""; rc=0
    shift
    # Separate job groups let the deadline stop helpers and inherited output pipes too.
    set -m
    "$@" & job=$!
    ( sleep "$seconds"; kill -TERM -- -"$job" 2>/dev/null; sleep 2; kill -KILL -- -"$job" 2>/dev/null ) </dev/null >/dev/null 2>&1 & timer=$!
    trap 'kill -KILL -- -"$job" -"$timer" 2>/dev/null; wait "$timer" 2>/dev/null' EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM HUP
    wait "$job" 2>/dev/null; rc=$?
    exit "$rc"
  )
}

git_tls() { # Keep TLS/proxy choices, exclude credentials, cookies, hooks and URL rewrites.
  local url="$1" key value
  # Empty Authorization suppresses automatic HTTP auth even on curl versions predating NETRC.
  local args=(-c credential.helper= -c credential.interactive=false -c core.askPass=
    -c http.extraHeader=Authorization: -c http.followRedirects=false -c http.lowSpeedLimit=1 -c http.lowSpeedTime=10)
  git config --list >/dev/null 2>&1 || return 2
  for key in http.sslVerify http.sslCAInfo http.sslCAPath http.sslBackend http.sslVersion \
             http.schannelUseSSLCAInfo http.schannelCheckRevoke http.proxy http.proxySSLCAInfo \
             http.proxySSLCAPath http.proxySSLVerify; do
    case "$key" in
      *CAInfo|*CAPath) value=$(git config --path --get-urlmatch "$key" "$url" 2>/dev/null) || continue ;;
      *) value=$(git config --get-urlmatch "$key" "$url" 2>/dev/null) || continue ;;
    esac
    args+=(-c "$key=$value")
  done
  GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_COUNT=0 GIT_CONFIG_PARAMETERS='' \
    NETRC=/dev/null LC_ALL=C GIT_TERMINAL_PROMPT=0 GIT_ASKPASS=/usr/bin/false run_timed 25 \
    env -u GIT_DIR -u GIT_WORK_TREE -u GIT_COMMON_DIR -u GIT_CONFIG \
      -u GIT_SSL_CERT -u GIT_SSL_KEY -u GIT_SSL_CERT_PASSWORD_PROTECTED \
      git -C "$TMP" "${args[@]}" ls-remote "$@"
}

cat > "$TMP/probe.py" <<'PY'
import hashlib
import os
import re
import ssl
import sys

TIMEOUT = 10
CONTROL = sys.argv[1]
HOSTS = sys.argv[2:]
CERT_MARKERS = ("CERTIFICATE_VERIFY_FAILED", "certificate verify failed", "revoked",
                "unable to get local issuer certificate")
# "SHA256:name" lines from the shell's DISTRUSTED_ROOTS, the one list every check uses.
DISTRUSTED = {}
for entry in os.environ.get("DISTRUSTED_ROOTS", "").split():
    fp, _, name = entry.partition(":")
    DISTRUSTED[fp.lower()] = name
if not DISTRUSTED:
    sys.exit("DISTRUSTED_ROOTS is empty")  # an empty list would pass every bundle
PEM = re.compile(r"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", re.S)


def version_of(module):
    try:
        mod = __import__(module, fromlist=["__version__"])
    except Exception:
        return "-"
    return str(getattr(mod, "__version__", "?"))


def bundle_roots(path):
    """'clean', 'empty', or the '+'-joined names of the distrusted roots found in a PEM bundle."""
    try:
        with open(path, encoding="ascii", errors="ignore") as fh:
            blocks = PEM.findall(fh.read())
        # Decodable base64 alone does not establish a valid X.509 certificate.
        ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT).load_verify_locations(cafile=path)
    except Exception:
        return "empty"
    if not blocks:
        return "empty"  # a bundle with nothing to inspect is not a pass
    hits = set()
    parsed = 0
    for block in blocks:
        try:
            der = ssl.PEM_cert_to_DER_cert(block)
        except Exception:
            return "empty"  # malformed certificates must never pass
        parsed += 1
        name = DISTRUSTED.get(hashlib.sha256(der).hexdigest())
        if name:
            hits.add(name)
    return "+".join(sorted(hits)) if hits else ("clean" if parsed else "empty")


def certifi_info(module):
    """(version, roots, where) for certifi or pip's vendored copy; "-" fields when it is absent."""
    try:
        mod = __import__(module, fromlist=["where"])
        where = mod.where()
    except Exception:
        return "-", "-", "-"
    return str(getattr(mod, "__version__", "?")), bundle_roots(where), where


def botocore_info():
    """(version, roots) of botocore's own CA bundle, which it reads only when certifi is absent."""
    try:
        import botocore
        from botocore.httpsession import DEFAULT_CA_BUNDLE
    except Exception:
        return "-", "-"
    return str(getattr(botocore, "__version__", "?")), bundle_roots(DEFAULT_CA_BUNDLE)


def classify(exc):
    text = "{!r} {}".format(exc, exc)
    return "B" if any(marker in text for marker in CERT_MARKERS) else "E"


def via_stdlib(url):
    import urllib.error
    import urllib.request
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None
    try:
        urllib.request.build_opener(NoRedirect).open(url, timeout=TIMEOUT).close()
    except urllib.error.HTTPError as exc:
        exc.close()
        return "C"  # the TLS handshake succeeded; the server answered with an HTTP error
    except urllib.error.URLError as exc:
        return classify(exc.reason if exc.reason is not None else exc)
    except Exception as exc:
        return classify(exc)
    return "C"


def via_requests(url):
    import requests
    try:
        # Suppress automatic .netrc credentials, retain proxy/CA environment settings.
        requests.get(url, timeout=TIMEOUT, stream=True, allow_redirects=False,
                     auth=lambda request: request).close()
    except Exception as exc:
        return classify(exc)
    return "C"


def tally(probe):
    results = [probe(url) for url in HOSTS]
    control = 1 if probe(CONTROL) == "C" else 0
    return [str(results.count("B")), str(results.count("C")), str(results.count("E")), str(control)]


if CONTROL == "--bundles":  # content check of system bundles only, no network
    for path in HOSTS:
        print("{}\t{}".format(path, bundle_roots(path)))
    sys.exit(0)

try:
    import requests  # noqa: F401
    HAVE_REQUESTS = True
except Exception:
    HAVE_REQUESTS = False

pipc_version, pipc_roots, _ = certifi_info("pip._vendor.certifi")
cert_version, cert_roots, cert_where = certifi_info("certifi")
fields = [sys.version.split()[0], version_of("pip"), pipc_version, pipc_roots, cert_version, cert_roots, cert_where]
fields += tally(via_stdlib)
fields += tally(via_requests) if HAVE_REQUESTS else ["-", "-", "-", "-"]
fields += botocore_info() if cert_version == "-" else ["-", "-"]
print("\t".join(fields))
PY

cat > "$TMP/probe.js" <<'JS'
const https = require('https');
const args = process.argv.slice(2);
const control = args[0];
const hosts = args.slice(1);
const CERT_CODE = /^(CERT_|UNABLE_TO_|SELF_SIGNED|DEPTH_ZERO)/;
function probe(url) {
  return new Promise(resolve => {
    let done = false;
    const finish = r => { if (!done) { done = true; resolve(r); } };
    const req = https.get(url, res => { res.destroy(); finish('C'); });
    req.setTimeout(10000, () => req.destroy(new Error('timeout')));
    req.on('error', e => finish(CERT_CODE.test(String(e.code || '')) ? 'B' : 'E'));
  });
}
(async () => {
  const r = [];
  for (const h of hosts) r.push(await probe(h));
  const c = await probe(control);
  const n = x => r.filter(v => v === x).length;
  console.log([n('B'), n('C'), n('E'), c === 'C' ? 1 : 0].join('\t'));
  process.exit(0);
})();
setTimeout(() => process.exit(1), 65000).unref();
JS

py_probe() { run_timed 125 "$1" -I "$TMP/probe.py" "$CONTROL_URL" "${TEST_URLS[@]}" 2>/dev/null </dev/null | tail -1; }

curlrc_file() { # the config curl reads by default: first of $CURL_HOME/.curlrc, $XDG_CONFIG_HOME/curlrc, ~/.curlrc
  local f
  for f in ${CURL_HOME:+"$CURL_HOME/.curlrc"} ${XDG_CONFIG_HOME:+"$XDG_CONFIG_HOME/curlrc"} "$HOME/.curlrc"; do
    if [ -f "$f" ]; then printf '%s\n' "$f"; return; fi
  done
}

check_curlrc() { # The probes run with -q so .curlrc cannot send credentials to the test hosts; judge it here.
  local f v=OK det="" ca res
  f=$(curlrc_file)
  [ -n "$f" ] || return 0
  if grep -Eq '^[[:space:]]*((--)?(proxy-)?insecure([[:space:]=:]|$)|-k([[:space:]]|$))' "$f"; then
    v=VULNERABLE; det="turns off certificate verification for every curl call"
    action "Remove insecure (or -k) from $(short "$f")"
  fi
  ca=$(sed -n 's/^[[:space:]]*\(--\)\{0,1\}cacert[[:space:]=:]\{1,\}//p' "$f" | tail -1 | tr -d '"')
  if [ -n "$ca" ]; then
    res=""; [ -f "$ca" ] && res=$(bundle_check "$ca")
    case "$res" in
      clean) det="${det:+$det | }cacert $(short "$ca") clean" ;;
      ""|empty) v=$(worse "$v" OUTDATED); det="${det:+$det | }cacert $(short "$ca") could not be checked" ;;
      *) v=$(worse "$v" VULNERABLE); det="${det:+$det | }cacert $(short "$ca") trusts $res"
         action "$(short "$f") points curl at $(short "$ca"), which trusts $res: remove the cacert line or point it at a clean bundle" ;;
    esac
  fi
  if grep -Eq '^[[:space:]]*(--)?capath([[:space:]=:]|$)' "$f"; then
    v=$(worse "$v" OUTDATED); det="${det:+$det | }capath is set: check that directory by hand"
  fi
  row "$v" "$(short "$f")" "${det:-no certificate overrides}"
}

curl_probe() { # prints: rejected connected errors control_ok
  local bin="$1" u rc b=0 c=0 e=0 ctl=0
  for u in "${TEST_URLS[@]}"; do
    "$bin" -q -sS --head -o /dev/null --connect-timeout 8 --max-time 15 "$u" >/dev/null 2>&1 </dev/null; rc=$?
    case $rc in 0) c=$((c + 1)) ;; 51|60|83|91) b=$((b + 1)) ;; *) e=$((e + 1)) ;; esac
  done
  "$bin" -q -sS --head -o /dev/null --connect-timeout 8 --max-time 15 "$CONTROL_URL" >/dev/null 2>&1 </dev/null && ctl=1
  echo "$b $c $e $ctl"
}

git_probe() { # prints: rejected connected errors control_ok
  local u out b=0 c=0 e=0 ctl=0
  for u in "${TEST_URLS[@]}"; do
    out=$(git_tls "${u}probe.git" 2>&1 </dev/null)
    case "$out" in
      *"SSL certificate problem"*|*"certificate verify failed"*|*"server certificate verification failed"*|*"revoked"*) b=$((b + 1)) ;;
      *"repository"*"not found"*|*"requested URL returned error: 404"*|*"not valid: is this a git repository"*|*"not appear to be a git repository"*) c=$((c + 1)) ;;
      *) e=$((e + 1)) ;;
    esac
  done
  git_tls https://github.com/git/git.git HEAD >/dev/null 2>&1 </dev/null && ctl=1
  echo "$b $c $e $ctl"
}

aws_hit() { # aws_hit AWS URL: B certificate rejected, C handshake done (any HTTP answer), E anything else
  local out
  # Unsigned: no credentials are loaded or sent. One attempt, no instance metadata lookup, no pager.
  out=$(AWS_MAX_ATTEMPTS=1 AWS_RETRY_MODE=standard AWS_PAGER="" AWS_EC2_METADATA_DISABLED=true \
    run_timed 25 "$1" s3api list-buckets --no-sign-request --region us-east-1 --endpoint-url "$2" \
    --cli-connect-timeout 8 --cli-read-timeout 10 2>&1 </dev/null)
  case "$out" in
    *CERTIFICATE_VERIFY_FAILED*|*"certificate verify failed"*) echo B ;;
    *"SSL validation failed"*|*"Could not connect"*|*"timeout"*|*"Connection was closed"*) echo E ;;
    *"An error occurred ("*|*"Unable to parse"*|*'"Buckets"'*) echo C ;;
    *) echo E ;;
  esac
}

aws_probe() { # prints: rejected connected errors control_ok
  local u b=0 c=0 e=0 ctl=0
  for u in "${TEST_URLS[@]}"; do
    case "$(aws_hit "$1" "$u")" in B) b=$((b + 1)) ;; C) c=$((c + 1)) ;; *) e=$((e + 1)) ;; esac
  done
  [ "$(aws_hit "$1" "$CONTROL_URL")" = C ] && ctl=1
  echo "$b $c $e $ctl"
}

aws_override() { # aws_override AWS: the CA bundle setting that replaces the CLI's own bundle, if any
  local cab
  if [ -n "${AWS_CA_BUNDLE:-}" ]; then echo "AWS_CA_BUNDLE=$AWS_CA_BUNDLE"; return; fi
  cab=$(run_timed 10 "$1" configure get ca_bundle 2>/dev/null </dev/null)
  [ -n "$cab" ] && echo "ca_bundle=$cab in ~/.aws/config"
}

# ---------------------------------------------------------------- python helpers

py_candidates() {
  {
    # bash's own `type`, not `which`: minimal images (AL2023, Lambda, SageMaker) ship no `which`.
    type -ap python3 python 2>/dev/null
    # shellcheck disable=SC2010  # Homebrew bin names are plain; drops python3.x-config
    ls -1 "$BREW_PREFIX"/bin/python3.[0-9]* 2>/dev/null | grep -E '/python3\.[0-9]+$'
    ls -1 /Library/Frameworks/Python.framework/Versions/*/bin/python3 2>/dev/null
    ls -1 "$HOME"/.pyenv/versions/*/bin/python3 2>/dev/null
    ls -1 "$HOME"/miniconda3/bin/python3 "$HOME"/anaconda3/bin/python3 "$HOME"/miniforge3/bin/python3 2>/dev/null
    # uv prints paths relative to the current directory when it can, so make them absolute.
    has uv && uv python list --only-installed --managed-python --no-cache 2>/dev/null </dev/null \
      | awk -v pwd="$PWD" '{ p = $2; if (substr(p, 1, 1) != "/") p = pwd "/" p; print p }'
  } | awk 'NF && !seen[$0]++'
}

is_apple_python() { [ "$OS" = Darwin ] || return 1; case "$(resolve "$1")" in /usr/bin/python3|/Library/Developer/CommandLineTools/*|/Applications/Xcode*) return 0 ;; esac; return 1; }

python_actions() { # python_actions PYTHON KIND VERSION
  local py="$1" kind="$2" ver="$3" vdir proj rp f
  if [ "$kind" = venv ]; then
    vdir=$(dirname "$(dirname "$py")"); proj=$(dirname "$vdir")
    if [ -f "$proj/uv.lock" ]; then
      action "$(short "$proj"): uv lock --upgrade-package certifi && uv sync   (then open a PR with the lock)"
    elif ls "$proj"/requirements*.txt >/dev/null 2>&1; then
      action "$(short "$proj"): add certifi>=$FIXED_CERTIFI to requirements and reinstall"
    else
      action "$(short "$vdir"): $(short "$py") -m pip install -U 'certifi>=$FIXED_CERTIFI'"
    fi
    return
  fi
  if is_apple_python "$py"; then
    action "Apple python3: its pip cannot be updated (pip $FIXED_PIP needs Python 3.10+, Apple ships 3.9). Do not install with /usr/bin/pip3; use Homebrew or uv Python"
    return
  fi
  rp=$(resolve "$py")
  case "$rp" in
    */Cellar/python@*)
      f=$(echo "$rp" | sed -n 's|.*/Cellar/\(python@[0-9.]*\)/.*|\1|p')
      action "brew update && brew upgrade $f" ;;
    */uv/python/*)
      action "uv Python $ver: its bundled pip trusts old roots. Install with uv, not python -m pip. If a newer build is installed: rm -rf .venv && uv sync in projects still on $ver, then uv python uninstall $ver" ;;
    /Library/Frameworks/Python.framework/*)
      action "$(short "$py"): run 'Install Certificates.command' (in /Applications/Python 3.x), then $(short "$py") -m pip install -U 'pip>=$FIXED_PIP' 'certifi>=$FIXED_CERTIFI'" ;;
    /usr/bin/*|/bin/*)
      action "System Python $(short "$py"): update it with the distro package manager (ca-certificates, python3-certifi, python3-pip, python3-requests); do not pip install into it" ;;
    *)
      action "$(short "$py") -m pip install -U 'pip>=$FIXED_PIP' 'certifi>=$FIXED_CERTIFI'" ;;
  esac
}

bundle_note() { # bundle_note WHERE: name the bundle when certifi reads one outside the package
  case "$1" in -|*/site-packages/*|*/dist-packages/*) : ;; *) printf ' (reads %s)' "$1" ;; esac
}

check_python() { # check_python PYTHON KIND(interp|venv) LABEL
  local py="$1" kind="$2" label="$3" out ver pip pipc pipr cert certr certw sb sc se sctl rb rc re rctl bcv bcr v t det sev
  out=$(py_probe "$py")
  if [ -z "$out" ]; then row BROKEN "$label" "this interpreter could not run the probe"; return; fi
  IFS=$'\t' read -r ver pip pipc pipr cert certr certw sb sc se sctl rb rc re rctl bcv bcr <<< "$out"
  t=$(verdict "$sb" "$sc" "$se" "$sctl"); v=$t
  det="py $ver | stdlib $(brief "$t" "$sb" "$sctl")"
  # Bundles are judged by content (the distrusted roots' SHA-256), not by version number: distro
  # certifi packages keep an old version but read the system bundle.
  if [ "$pip" != "-" ]; then
    case "$pipr" in
      -) v=$(worse "$v" INCONCLUSIVE); det="$det | pip $pip bundle not inspected" ;;
      clean) det="$det | pip $pip bundle clean" ;;
      empty) v=$(worse "$v" INCONCLUSIVE); det="$det | pip $pip bundle unreadable or empty" ;;
      *)
        sev=VULNERABLE
        det="$det | pip $pip bundle (certifi $pipc) trusts $pipr"
        # Apple's pip cannot be updated; it only matters when it is the pip3 people actually run.
        if [ "$kind" = interp ] && is_apple_python "$py" && [ "$(command -v pip3)" != /usr/bin/pip3 ]; then
          sev=OUTDATED; det="$det (not the default pip3)"
        fi
        v=$(worse "$v" "$sev") ;;
    esac
  fi
  case "$certr" in
    -) : ;;
    clean) det="$det | certifi $cert clean$(bundle_note "$certw")" ;;
    empty) v=$(worse "$v" INCONCLUSIVE); det="$det | certifi $cert bundle unreadable or empty$(bundle_note "$certw")" ;;
    *) v=$(worse "$v" VULNERABLE); det="$det | certifi $cert trusts $certr$(bundle_note "$certw")" ;;
  esac
  # botocore (boto3, AWS CLI v1) reads its own cacert.pem when certifi is not installed.
  case "${bcr:--}" in
    -|clean) : ;;
    *) if [ -n "${AWS_CA_BUNDLE:-}" ]; then det="$det | botocore $bcv: AWS_CA_BUNDLE overrides its own bundle"
       elif [ "$bcr" = empty ]; then v=$(worse "$v" INCONCLUSIVE); det="$det | botocore $bcv bundle unreadable or empty"
       else v=$(worse "$v" VULNERABLE); det="$det | botocore $bcv (no certifi) reads its own cacert.pem, which trusts $bcr (fixed in $FIXED_BOTOCORE)"; fi ;;
  esac
  if [ "$rb" != "-" ]; then
    t=$(verdict "$rb" "$rc" "$re" "$rctl"); v=$(worse "$v" "$t")
    det="$det | requests $(brief "$t" "$rb" "$rctl")"
  fi
  row "$v" "$label" "$det"
  [ "$v" = OK ] || python_actions "$py" "$kind" "$ver"
}

venv_list() { # venv_list DIR: virtualenv directories under DIR
  find "$1" -maxdepth 6 \( -name node_modules -o -name .git -o -name cdk.out -o -name .terraform -o -name site-packages \) -prune \
    -o -type f -name pyvenv.cfg -print 2>/dev/null | sed 's|/pyvenv.cfg$||' | sort
}

# ---------------------------------------------------------------- node helpers

# Majors above the newest listed line are compared with it, so they pass; the TLS probe is the real test.
node_fixed() {
  case "$1" in
    22) echo 22.23.4 ;; 24) echo 24.22.1 ;; 26) echo 26.12.1 ;;
    *[!0-9]*|"") echo "" ;;
    *) if [ "$1" -gt 26 ]; then echo 26.12.1; else echo ""; fi ;;
  esac
}
ACTIVE_NODE=""; ACTIVE_NODE_BAD=0; GOOD_BREW_NODE=""

check_node() { # check_node NODE RESOLVED_PATH
  local n="$1" rp="$2" ver maj fixed out b c e ctl v where det note=""
  ver=$("$n" --version 2>/dev/null </dev/null)
  out=$("$n" "$TMP/probe.js" "$CONTROL_URL" "${TEST_URLS[@]}" 2>/dev/null </dev/null | tail -1)
  # An old Node exits at startup on a NODE_OPTIONS flag it does not know: probe it without them.
  if [ -z "$out" ] && [ -n "${NODE_OPTIONS:-}" ]; then
    ver=$(env -u NODE_OPTIONS "$n" --version 2>/dev/null </dev/null)
    out=$(env -u NODE_OPTIONS "$n" "$TMP/probe.js" "$CONTROL_URL" "${TEST_URLS[@]}" 2>/dev/null </dev/null | tail -1)
    [ -n "$out" ] && note=" (probed without NODE_OPTIONS, which this Node rejects)"
  fi
  ver=${ver#v}
  if [ -z "$out" ]; then row BROKEN "node $ver  $(short "$n")" "could not run the probe"; return; fi
  IFS=$'\t' read -r b c e ctl <<< "$out"
  v=$(verdict "$b" "$c" "$e" "$ctl")
  if [ "$rp" = "$ACTIVE_NODE" ]; then where="active"
  elif echo "$PATH" | tr ':' '\n' | grep -qxF "$(dirname "$n")"; then where="shadowed in PATH"
  else where="not in PATH"; fi
  det="TLS $(brief "$v" "$b" "$ctl")$note"
  maj=${ver%%.*}; fixed=$(node_fixed "$maj")
  if [ -z "$fixed" ]; then v=$(worse "$v" OUTDATED); det="$det | v$maj has no fixed release, use 22/24/26"
  elif ! ver_ge "$ver" "$fixed"; then v=$(worse "$v" OUTDATED); det="$det | fixed in $fixed"; fi
  row "$v" "node $ver  $(short "$n")  [$where]" "$det"
  if [ "$v" = OK ]; then
    case "$rp" in "$BREW_PREFIX"/Cellar/node*)
      [ -n "$GOOD_BREW_NODE" ] || GOOD_BREW_NODE=$(echo "$rp" | sed -n 's|.*/Cellar/\(node[^/]*\)/.*|\1|p') ;;
    esac
    return
  fi
  if [ "$where" = active ]; then ACTIVE_NODE_BAD=1
  else action "Node $ver at $(short "$n") is not the default but still runs via absolute path, $([ "$OS" = Darwin ] && echo launchd || echo systemd) or cron: upgrade or remove it"; fi
}

# ---------------------------------------------------------------- trust store helpers

DISTRO_FAMILY="other"
if [ "$OS" = Darwin ]; then DISTRO_FAMILY=macos
elif [ -r /etc/os-release ]; then
  # shellcheck disable=SC1091  # os-release exists only at runtime
  ids=$( { . /etc/os-release; printf ' %s %s ' "${ID:-}" "${ID_LIKE:-}"; } 2>/dev/null )
  case "$ids" in
    *" amzn "*) DISTRO_FAMILY=amzn ;;
    *" debian "*|*" ubuntu "*) DISTRO_FAMILY=debian ;;
    *" rhel "*|*" fedora "*|*" centos "*) DISTRO_FAMILY=rhel ;;
    *" alpine "*) DISTRO_FAMILY=alpine ;;
    *" suse "*|*" opensuse "*|*" sles "*) DISTRO_FAMILY=suse ;;
  esac
fi

ca_fix_hint() { # ca_fix_hint ROOTS: how to stop the system store trusting ROOTS on this OS
  case "$DISTRO_FAMILY" in
    macos)  echo "install macOS updates (softwareupdate -l); Homebrew tools follow brew's ca-certificates (brew upgrade ca-certificates)" ;;
    debian) echo "apt-get update && apt-get install --only-upgrade ca-certificates; if the store still trusts $1, prefix the matching lines in /etc/ca-certificates.conf with ! and run update-ca-certificates" ;;
    amzn)   echo "upgrade ca-certificates (AL2023: dnf --releasever=latest upgrade ca-certificates; AL2: yum update ca-certificates); if the store still trusts $1, put the matching PEMs into /etc/pki/ca-trust/source/blocklist/ and run update-ca-trust extract" ;;
    rhel)   echo "dnf upgrade ca-certificates; if the store still trusts $1, put the matching PEMs into /etc/pki/ca-trust/source/blocklist/ and run update-ca-trust extract" ;;
    alpine) echo "apk upgrade ca-certificates && update-ca-certificates" ;;
    suse)   echo "zypper update ca-certificates-mozilla && update-ca-certificates" ;;
    *)      echo "update ca-certificates with the distro package manager and rebuild the CA bundle" ;;
  esac
}

roots_in_fps() { # roots_in_fps FILE [LIST]: FILE holds one SHA-256 per line; prints clean, empty or ROOT+ROOT
  [ -s "$1" ] || { echo empty; return; }
  awk -F: 'NR == FNR { have[toupper($0)] = 1; next } ($1 in have) { out = out (out ? "+" : "") $2 }
    END { print (out ? out : "clean") }' "$1" "${2:-$TMP/distrusted.txt}"
}

bundle_roots_openssl() { # bundle_roots_openssl FILE: the Python checker's answer, via the openssl CLI
  local dir="$TMP/split" c invalid=0
  rm -rf "$dir"; mkdir -p "$dir"
  awk -v d="$dir" '/-----BEGIN CERTIFICATE-----/ { n++; f = d "/" n ".pem" } f { print > f }
    /-----END CERTIFICATE-----/ { close(f); f = "" }' "$1"
  for c in "$dir"/*.pem; do
    [ -f "$c" ] || continue
    openssl x509 -in "$c" -noout -fingerprint -sha256 2>/dev/null | sed 's/.*=//; s/://g' || invalid=1
  done > "$TMP/split.fps"
  [ "$invalid" -eq 0 ] || { echo empty; return; }
  roots_in_fps "$TMP/split.fps"
}

bundle_check() { # bundle_check FILE: clean, empty, ROOT+ROOT, or "" when neither python3 nor openssl can read it
  if [ -n "$BUNDLE_PY" ]; then "$BUNDLE_PY" -I "$TMP/probe.py" --bundles "$1" 2>/dev/null </dev/null | cut -f2
  elif has openssl; then bundle_roots_openssl "$1"; fi
}

java_store_roots() { # java_store_roots STORE KEYTOOL: clean, empty or ROOT+ROOT
  if ! run_timed 25 "$2" -J-Duser.language=en -list -v -keystore "$1" -storepass changeit 2>/dev/null </dev/null \
    | awk '/^[[:space:]]*SHA256:/ { sub(/.*SHA256:[[:space:]]*/, ""); gsub(/:/, ""); print }' > "$TMP/java.fps"; then
    echo empty; return
  fi
  roots_in_fps "$TMP/java.fps" "$TMP/java-distrusted.txt"
}

cat > "$TMP/T.java" <<'JAVA'
import java.net.URL;
import javax.net.ssl.HttpsURLConnection;

// args[0] is the control URL, the rest are the test chains; prints "rejected connected errors control_ok".
public class T {
    public static void main(String[] args) {
        int b = 0, c = 0, e = 0, ctl = 0;
        for (int i = 0; i < args.length; i++) {
            String r = probe(args[i]);
            if (i == 0) { ctl = r.equals("C") ? 1 : 0; continue; }
            if (r.equals("B")) b++; else if (r.equals("C")) c++; else e++;
        }
        System.out.println(b + "\t" + c + "\t" + e + "\t" + ctl);
    }

    static String probe(String url) {
        try {
            HttpsURLConnection conn = (HttpsURLConnection) new URL(url).openConnection();
            conn.setConnectTimeout(8000);
            conn.setReadTimeout(10000);
            conn.getResponseCode();  // any HTTP status means the handshake succeeded
            conn.disconnect();
            return "C";
        } catch (Exception ex) {
            String m = ex + " " + ex.getCause();
            return (m.contains("PKIX") || m.contains("certification path") || m.contains("CertPathValidator")
                    || m.contains("revoked") || m.contains("CertificateException")) ? "B" : "E";
        }
    }
}
JAVA

brew_affected_installed() {
  brew list --formula -1 2>/dev/null | grep -E '^(bun|ca-certificates|curl|git|uv|node(@[0-9]+)?|python@3\.[0-9]+)$' | tr '\n' ' '
}

# ---------------------------------------------------------------- report

# shellcheck disable=SC1091  # os-release exists only at runtime
if [ "$OS" = Darwin ]; then OS_LABEL="macOS $(sw_vers -productVersion 2>/dev/null)"
else OS_LABEL="$( { . /etc/os-release && printf '%s' "$PRETTY_NAME"; } 2>/dev/null || uname -sr)"; fi
echo "${BLD}== eMudhra CA compromise: $OS check (read-only), emudhra-cli-trust-check $VERSION ==${RST}"
echo "  $OS_LABEL | $(date '+%Y-%m-%d %H:%M') | fixed versions as of $AS_OF"
echo "  tracker: $TRACKER"
echo "  OK (TLS) = rejects all $NH test chains and still reaches $CONTROL_URL"
echo "  VERSION_OK = version check only; bundle/content checks are labelled separately"
echo "  Scope: discovered tools only; browsers, containers and all project environments are not covered by default"
if [ "$TLS_EXPIRED" = 1 ]; then
  echo "  ${YEL}The test hosts' certificates expired on 2027-05-03: TLS tests can no longer tell a trusting"
  echo "  client from a rejecting one and report INCONCLUSIVE. Trust store content and version checks still apply.${RST}"
fi

section "TLS verification overrides"
for override in GIT_SSL_NO_VERIFY NODE_TLS_REJECT_UNAUTHORIZED PYTHONHTTPSVERIFY; do
  value="${!override-}"
  case "$override:$value" in
    GIT_SSL_NO_VERIFY:1|GIT_SSL_NO_VERIFY:true|GIT_SSL_NO_VERIFY:yes|NODE_TLS_REJECT_UNAUTHORIZED:0|PYTHONHTTPSVERIFY:0)
      row VULNERABLE "$override" "environment disables certificate verification; remove the override" ;;
  esac
done

section "Homebrew"
if has brew; then
  list=$(brew_affected_installed)
  if [ -n "$list" ]; then
    read -r -a brew_formulae <<< "$list"
    brew list --formula --versions "${brew_formulae[@]}" 2>/dev/null | sed 's/^/  /'
    outdated=$(brew outdated --formula --verbose "${brew_formulae[@]}" 2>/dev/null)
    if [ -n "$outdated" ]; then
      row OUTDATED "affected formulae" "$(echo "$outdated" | tr '\n' ';' | sed 's/;$//; s/;/; /g')"
      action "brew update && brew upgrade $(echo "$outdated" | awk '{print $1}' | tr '\n' ' ')"
    else
      row VERSION_OK "affected formulae" "no upgrade shown by local Homebrew metadata; run brew update separately to refresh"
    fi
  fi
else
  if [ "$OS" = Darwin ]; then echo "  Homebrew not found: install macOS updates and update tools with their own installers"
  else echo "  Homebrew not found: update ca-certificates, curl, git and Python with the distro package manager"; fi
fi

section "System CA bundles (content)"
BUNDLE_PY=""; CLEAN_BUNDLE=""
while IFS= read -r p <&3; do
  [ -x "$p" ] || continue
  if [ "$OS" = Darwin ] && [ "$p" = /usr/bin/python3 ] && ! xcode-select -p >/dev/null 2>&1; then continue; fi
  if "$p" -I -c 'import hashlib, ssl' >/dev/null 2>&1 </dev/null; then BUNDLE_PY=$p; break; fi
done 3<<EOF
$(py_candidates)
EOF
for f in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt /etc/ssl/cert.pem \
         /etc/pki/ca-trust/extracted/pem/*.pem "$BREW_PREFIX"/etc/ca-certificates/cert.pem \
         "$BREW_PREFIX"/etc/openssl@3/cert.pem "$BREW_PREFIX"/etc/openssl@4/cert.pem; do
  [ -f "$f" ] && resolve "$f"
done | awk '!s[$0]++' > "$TMP/bundles"
if [ ! -s "$TMP/bundles" ]; then echo "  no system CA bundle found"; fi
while IFS= read -r bf <&3; do
  res=$(bundle_check "$bf")
  case "$bf" in *email*|*objsign*) tls=0 ;; *) tls=1 ;; esac
  case "$res" in
    "") row INCONCLUSIVE "$(short "$bf")" "not checked: needs python3 or openssl" ;;
    clean) row OK "$(short "$bf")" "none of the distrusted roots"
           [ "$tls" = 1 ] && [ -z "$CLEAN_BUNDLE" ] && CLEAN_BUNDLE=$bf ;;
    empty) [ "$tls" = 1 ] && row INCONCLUSIVE "$(short "$bf")" "no certificates found in this bundle" ;;
    *)
      if [ "$tls" = 1 ]; then row VULNERABLE "$(short "$bf")" "contains $res: TLS clients that read this bundle trust them"
      else row OUTDATED "$(short "$bf")" "contains $res: not a TLS bundle, but a blocklist should cover it too"; fi
      case "$bf" in
        "$BREW_PREFIX"/*) action "$(short "$bf") contains $res: brew update && brew upgrade ca-certificates" ;;
        *) action "$(short "$bf") contains $res: $(ca_fix_hint "$res")" ;;
      esac ;;
  esac
done 3< "$TMP/bundles"

section "curl"
echo "  probes skip .curlrc (checked below); proxy and CA environment settings apply"
for cb in /usr/bin/curl "$BREW_PREFIX/opt/curl/bin/curl"; do
  [ -x "$cb" ] || continue
  read -r b c e ctl <<< "$(curl_probe "$cb")"
  v=$(verdict "$b" "$c" "$e" "$ctl")
  row "$v" "curl $("$cb" --version 2>/dev/null | awk 'NR == 1 {print $2}')  $(short "$cb")" "TLS $(brief "$v" "$b" "$ctl")"
  if [ "$v" = VULNERABLE ]; then
    case "$cb" in
      /usr/bin/curl)
        if [ "$OS" = Darwin ]; then action "Apple curl accepts the chains: install macOS updates (softwareupdate -l); the tracker documents a temporary /etc/ssl/cert.pem workaround"
        else action "System curl accepts the chains: $(ca_fix_hint "the emSign/AAA roots")"; fi ;;
      *) action "brew update && brew upgrade ca-certificates curl" ;;
    esac
  fi
done
check_curlrc

section "git"
if has git; then
  read -r b c e ctl <<< "$(git_probe)"
  v=$(verdict "$b" "$c" "$e" "$ctl")
  row "$v" "git $(git --version | awk '{print $3}')  $(short "$(command -v git)")" "TLS $(brief "$v" "$b" "$ctl")"
  if [ "$v" = VULNERABLE ]; then
    if [ "$OS" = Darwin ]; then action "git accepts the chains: brew upgrade git ca-certificates curl (Homebrew git) or install macOS updates (Apple git)"
    else action "git accepts the chains: $(ca_fix_hint "the emSign/AAA roots")$(has brew && echo " (Homebrew git: brew upgrade git ca-certificates)")"; fi
  fi
  # git treats false/no/off/0 as off; --get-regexp prints "key value".
  insecure=$( { git config --global --get-regexp '^http\..*sslverify$'; git config --system --get-regexp '^http\..*sslverify$'; } 2>/dev/null | grep -iE '[[:space:]](false|no|off|0)$')
  if [ -n "$insecure" ]; then
    row VULNERABLE "git config" "TLS verification is disabled in a global/system git setting (values redacted)"
    action "Remove http.sslVerify=false from your git config (git config --global --unset http.sslVerify)"
  fi
else
  echo "  git not found"
fi

section "Python interpreters (stdlib TLS, pip, certifi, requests)"
seen="|"
while IFS= read -r py <&3; do
  [ -x "$py" ] || continue
  # Apple's /usr/bin/python3 is a stub that pops up an installer dialog when the CLT are missing.
  if [ "$OS" = Darwin ] && [ "$py" = /usr/bin/python3 ] && ! xcode-select -p >/dev/null 2>&1; then continue; fi
  rp=$(resolve "$py")
  case "$seen" in *"|$rp|"*) continue ;; esac
  seen="$seen$rp|"
  check_python "$py" interp "$(short "$py")"
done 3<<EOF
$(py_candidates)
EOF
[ "$seen" = "|" ] && echo "  no Python found"

section "uv"
if has uv; then
  uvv=$(uv --version 2>/dev/null | awk '{print $2}')
  if ver_ge "$uvv" "$FIXED_UV"; then
    row VERSION_OK "uv $uvv" "its bundled root store is fixed from $FIXED_UV"
  else
    row VULNERABLE "uv $uvv" "uv ships its own root store; fixed in $FIXED_UV"
    case "$(resolve "$(command -v uv)")" in
      */Cellar/*) action "brew update && brew upgrade uv" ;;
      *) action "uv self update   (or update uv with the tool that installed it)" ;;
    esac
  fi
else
  echo "  uv not found"
fi

section "AWS CLI (TLS test with unsigned requests)"
seen="|"
while IFS= read -r a <&3; do
  [ -x "$a" ] || continue
  rp=$(resolve "$a")
  case "$seen" in *"|$rp|"*) continue ;; esac
  seen="$seen$rp|"
  av=$(run_timed 10 "$a" --version 2>&1 </dev/null | awk '{print $1}'); av=${av#aws-cli/}
  read -r b c e ctl <<< "$(aws_probe "$a")"
  v=$(verdict "$b" "$c" "$e" "$ctl")
  det="TLS $(brief "$v" "$b" "$ctl")"
  ovr=$(aws_override "$a")
  if [ -n "$ovr" ]; then
    det="$det | via $ovr"
  else
    # AWS CLI v2 is a frozen bundle without certifi: botocore reads awscli/botocore/cacert.pem.
    own="$(dirname "$rp")/awscli/botocore/cacert.pem"
    if [ -f "$own" ]; then
      res=$(bundle_check "$own")
      case "$res" in
        clean) : ;;
        ""|empty) v=$(worse "$v" INCONCLUSIVE); det="$det | its own CA bundle could not be inspected" ;;
        *) v=$(worse "$v" VULNERABLE); det="$det | its own botocore/cacert.pem trusts $res" ;;
      esac
    fi
  fi
  # v2 ships its own bundle; v1 runs on the botocore of its Python, which the Python checks cover.
  case "$av" in
    2.*) if ver_ge "$av" "$FIXED_AWSCLI"; then det="$det | fixed from $FIXED_AWSCLI"
         else v=$(worse "$v" OUTDATED); det="$det | fixed in $FIXED_AWSCLI"; fi ;;
  esac
  row "$v" "aws $av  $(short "$a")" "$det"
  if [ "$v" != OK ]; then
    case "$av" in
      2.*) if ! ver_ge "$av" "$FIXED_AWSCLI"; then
             if [ "$OS" = Darwin ]; then ahint="the AWS pkg installer, or brew upgrade awscli for Homebrew"
             else ahint="the AWS installer with --update"; fi
             action "Update AWS CLI $av ($(short "$a")) to $FIXED_AWSCLI or later ($ahint)"
           fi ;;
    esac
    if [ "$v" = VULNERABLE ]; then
      fixb=${CLEAN_BUNDLE:-"<a CA bundle without these roots, e.g. the path printed by: python3 -m certifi (certifi>=$FIXED_CERTIFI)>"}
      action "Until the AWS CLI is updated: export AWS_CA_BUNDLE=$fixb in your shell profile (or ca_bundle in every profile of ~/.aws/config), then re-run this check"
    fi
  fi
done 3<<EOF
$(type -ap aws 2>/dev/null)
EOF
[ "$seen" = "|" ] && echo "  AWS CLI not found"

section "Node.js"
if has node; then ACTIVE_NODE=$(resolve "$(command -v node)"); fi
{ type -ap node 2>/dev/null; ls -1d "$BREW_PREFIX"/opt/node*/bin/node 2>/dev/null; } | awk 'NF && !s[$0]++' > "$TMP/node_paths"
seen="|"
while IFS= read -r n <&3; do
  [ -x "$n" ] || continue
  rp=$(resolve "$n")
  case "$seen" in *"|$rp|"*) continue ;; esac
  seen="$seen$rp|"
  check_node "$n" "$rp"
done 3< "$TMP/node_paths"
[ "$seen" = "|" ] && echo "  Node.js not found"
if [ "$ACTIVE_NODE_BAD" = 1 ]; then
  if [ -n "$GOOD_BREW_NODE" ]; then
    action "Make the fixed Homebrew Node the default: brew link --force --overwrite $GOOD_BREW_NODE && hash -r && node --version"
  elif has brew; then
    action "Install a fixed Node (22.23.4+, 24.22.1+ or 26.12.1+): brew install node@24 && brew link --force --overwrite node@24 (or via nvm/volta/fnm)"
  else
    action "Install a fixed Node (22.23.4+, 24.22.1+ or 26.12.1+) with the tool that manages the active one (nvm/volta/fnm or the distro package), then hash -r && node --version"
  fi
fi

section "Bun"
# ~/.bun/bin is the installer's default and is often missing from a non-interactive PATH.
{ type -ap bun 2>/dev/null; ls -1 "$HOME/.bun/bin/bun" "$BREW_PREFIX/opt/bun/bin/bun" 2>/dev/null; } | awk 'NF && !s[$0]++' > "$TMP/bun_paths"
seen="|"
while IFS= read -r bn <&3; do
  [ -x "$bn" ] || continue
  rp=$(resolve "$bn")
  case "$seen" in *"|$rp|"*) continue ;; esac
  seen="$seen$rp|"
  bv=$(run_timed 10 "$bn" --version 2>/dev/null </dev/null)
  out=$(run_timed 70 "$bn" "$TMP/probe.js" "$CONTROL_URL" "${TEST_URLS[@]}" 2>/dev/null </dev/null | tail -1)
  if [ -z "$out" ]; then row BROKEN "bun $bv  $(short "$bn")" "could not run the probe"; continue; fi
  IFS=$'\t' read -r b c e ctl <<< "$out"
  v=$(verdict "$b" "$c" "$e" "$ctl")
  det="TLS $(brief "$v" "$b" "$ctl")"
  if ver_ge "$bv" "$FIXED_BUN"; then det="$det | fixed from $FIXED_BUN"
  else v=$(worse "$v" OUTDATED); det="$det | fixed in $FIXED_BUN (its root store is built in: ca-certificates and --use-system-ca do not remove the roots)"; fi
  row "$v" "bun $bv  $(short "$bn")" "$det"
  [ "$v" = OK ] && continue
  case "$rp" in
    */Cellar/bun/*) action "brew update && brew upgrade bun" ;;
    */node_modules/bun/*) action "Bun at $(short "$bn"): npm install -g bun@latest (or update it with the tool that installed it)" ;;
    *) action "$(short "$bn") upgrade   (Bun $bv; fixed in $FIXED_BUN)" ;;
  esac
done 3< "$TMP/bun_paths"
[ "$seen" = "|" ] && echo "  Bun not found"

section "Java (cacerts content; TLS test when javac is present)"
if [ "$OS" = Darwin ]; then
  /usr/libexec/java_home -V 2>&1 | sed -n 's|.*[[:space:]]\(/.*\)$|\1|p' > "$TMP/jvms.raw"
else
  # /usr/lib/jvm holds several symlinked aliases per JDK; dedup on the resolved path below.
  # shellcheck disable=SC2012  # JDK dir names are plain
  { ls -1d /usr/lib/jvm/*/ /usr/java/*/ "$HOME"/.sdkman/candidates/java/*/ 2>/dev/null | sed 's|/$||'
    [ -n "${JAVA_HOME:-}" ] && echo "$JAVA_HOME"
    has java && dirname "$(dirname "$(resolve "$(command -v java)")")"
  } > "$TMP/jvms.raw"
fi
while IFS= read -r jh; do
  [ -n "$jh" ] && [ -d "$jh" ] && (cd "$jh" && pwd -P)
done < "$TMP/jvms.raw" | awk '!s[$0]++' > "$TMP/jvms"
if [ -s "$TMP/jvms" ]; then
  while IFS= read -r jh <&3; do
    [ -x "$jh/bin/java" ] || continue
    jv=$("$jh/bin/java" -version 2>&1 </dev/null | awk -F'"' '/version/ {print $2; exit}')
    # Version is only a lower bound, the October 2026 release of each line. No vendor has shipped
    # JDK-8395690 (CVE-2026-114820) yet, so the cacerts content decides, not the version.
    case "$jv" in
      1.8.0_*) cmp="8.0.${jv#1.8.0_}"; floor="8.0.511"; shown="8u511" ;;
      *) cmp="$jv"
         case "${jv%%.*}" in 11) floor=11.0.33 ;; 17) floor=17.0.21 ;; 21) floor=21.0.13 ;; 25) floor=25.0.5 ;; 27) floor=27.0.1 ;; *) floor="" ;; esac
         # Lines newer than 27 postdate the incident: compare them with 27.0.1 so they pass.
         if [ -z "$floor" ] && ver_ge "$jv" 28; then floor=27.0.1; fi
         shown="$floor" ;;
    esac
    case "$OS:$jv" in
      Darwin:1.8.0_*) jhint=" (e.g. brew install --cask corretto@8)" ;;
      Darwin:*) jhint="" ;;
      *) jhint=" (distro openjdk package or the vendor build)" ;;
    esac
    v=OK; det=""; roots=""; tls=""
    # Trust store content. JSSE reads jssecacerts instead of cacerts when it exists.
    kt=""; for k in "$jh/bin/keytool" "$jh/jre/bin/keytool"; do [ -x "$k" ] && { kt=$k; break; }; done
    store=""; for s in "$jh/lib/security/jssecacerts" "$jh/jre/lib/security/jssecacerts" \
                       "$jh/lib/security/cacerts" "$jh/jre/lib/security/cacerts"; do [ -f "$s" ] && { store=$s; break; }; done
    if [ -n "$kt" ] && [ -n "$store" ]; then
      res=$(java_store_roots "$store" "$kt")
      case "$res" in
        clean) det="$(basename "$store") clean" ;;
        empty) v=$(worse "$v" INCONCLUSIVE); det="$(basename "$store") unreadable or empty" ;;
        *) roots=$res; det="$(basename "$store") still has $res" ;;
      esac
    else
      v=$(worse "$v" INCONCLUSIVE); det="trust store not checked (keytool or store missing)"
    fi
    # Real TLS test, only where a compiler ships (a JDK; a plain JRE cannot run source files).
    if [ -x "$jh/bin/javac" ]; then
      jdir="$TMP/java.$(printf '%s' "$jh" | cksum | cut -d' ' -f1)"; mkdir -p "$jdir"
      out=""
      if run_timed 25 "$jh/bin/javac" -nowarn -d "$jdir" "$TMP/T.java" >/dev/null 2>&1 </dev/null; then
        out=$(run_timed 65 "$jh/bin/java" -cp "$jdir" T "$CONTROL_URL" "${TEST_URLS[@]}" 2>/dev/null </dev/null | tail -1)
      fi
      if [ -n "$out" ]; then
        IFS=$'\t' read -r b c e ctl <<< "$out"
        tls=$(verdict "$b" "$c" "$e" "$ctl"); v=$(worse "$v" "$tls"); det="$det | TLS $(brief "$tls" "$b" "$ctl")"
      else
        v=$(worse "$v" INCONCLUSIVE); det="$det | TLS test did not run"
      fi
    fi
    if [ -z "$floor" ]; then
      v=$(worse "$v" OUTDATED); det="$det | no supported release line; move to 21/25/27"
    elif ! ver_ge "$cmp" "$floor"; then
      v=$(worse "$v" OUTDATED); det="$det | older than the October 2026 release ($shown)"
      action "Java $jv ($(short "$jh")): update to $shown or later$jhint, or remove it if unused"
    fi
    # The test chains cover only the 8 intermediates, so a rejecting TLS test does not clear the roots.
    if [ -n "$roots" ]; then
      v=$(worse "$v" OUTDATED); det="$det | OpenJDK advises removing them until a release lists JDK-8395690"
      action "Java $jv ($(short "$jh")): remove $roots from $(short "$store"): keytool -delete -keystore <store> -storepass changeit -alias <alias> (aliases in keytool -list -v; see https://openjdk.org/emudhra)"
    fi
    row "$v" "Java $jv  $(short "$jh")" "$det"
  done 3< "$TMP/jvms"
else
  echo "  no Java runtime installed"
fi

section "Go (version check only)"
if has go; then
  gv=$(go version 2>/dev/null | awk '{print $3}'); gv=${gv#go}
  # 1.26.x needs 1.26.10; anything else is compared with 1.27.3, so 1.28+ passes and <1.26 does not.
  case "$gv" in 1.26.*) fixed=1.26.10 ;; *) fixed=1.27.3 ;; esac
  if ver_ge "$gv" "$fixed"; then row VERSION_OK "go $gv" "fixed from $fixed"
  else
    if [ "$OS" = Darwin ]; then gnote="on macOS Go uses the system verifier; matters for Linux builds"
    else gnote="on Linux Go reads the system CA bundle, so also keep ca-certificates updated"; fi
    row OUTDATED "go $gv" "fixed in 1.27.3 / 1.26.10 ($gnote)"
    action "Update Go to 1.27.3 or 1.26.10+"
  fi
else
  echo "  Go not found"
fi

section "Perl Mozilla::CA (fallback CA bundle)"
pca=""
# shellcheck disable=SC2016  # Perl code: perl expands it, not the shell
has perl && pca=$(run_timed 10 perl -MMozilla::CA -e 'print "$Mozilla::CA::VERSION\t", Mozilla::CA::SSL_ca_file()' 2>/dev/null </dev/null)
if [ -z "$pca" ]; then echo "  Mozilla::CA not installed for the default perl"
else
  IFS=$'\t' read -r pcv pcf <<< "$pca"
  case "$(bundle_check "$pcf")" in
    clean) row OK "Mozilla::CA $pcv" "bundle clean" ;;
    ""|empty) row INCONCLUSIVE "Mozilla::CA $pcv" "$(short "$pcf") could not be inspected" ;;
    *) row OUTDATED "Mozilla::CA $pcv" "bundle trusts the distrusted roots; IO::Socket::SSL tries the system store first, so it is a fallback (fixed in $FIXED_MOZILLA_CA)"
       action "Update Perl Mozilla::CA $pcv to $FIXED_MOZILLA_CA or later (cpanm Mozilla::CA, or the distro package)" ;;
  esac
fi

tool_check() { # tool_check NAME FIXED PREFIX CMD...: version-only check; skipped when CMD is absent or unrecognised
  local name=$1 fixed=$2 prefix=$3 v; shift 3
  has "$1" || return 0
  v=$(run_timed 10 "$@" 2>/dev/null </dev/null | grep -oE "${prefix}[0-9]+(\.[0-9]+)+" | head -1 | grep -oE '[0-9]+(\.[0-9]+)+$')
  [ -n "$v" ] || return 0
  if ver_ge "$v" "$fixed"; then row VERSION_OK "$name $v" "fixed from $fixed"
  else row OUTDATED "$name $v" "fixed in $fixed"; action "Update $name to $fixed or later"; fi
}

section "Other tools (version check only)"
tool_check Deno "$FIXED_DENO" "^deno " deno --version
tool_check "GitHub CLI" "$FIXED_GH" "gh version " gh --version
tool_check "Docker CLI" "$FIXED_DOCKER_CLI" "Docker version " docker --version
tool_check conda "$FIXED_CONDA" "^conda " conda --version
tool_check rustup "$FIXED_RUSTUP" "^rustup " rustup --version

section "Apps"
app_check() { # app_check NAME FIXED BUNDLE_NAME
  local app v
  for app in "/Applications/$3" "$HOME/Applications/$3"; do
    [ -d "$app" ] || continue
    v=$(/usr/libexec/PlistBuddy -c 'Print CFBundleShortVersionString' "$app/Contents/Info.plist" 2>/dev/null)
    [ -n "$v" ] || continue
    if ver_ge "$v" "$2"; then row VERSION_OK "$1 $v" "fixed from $2"
    else row OUTDATED "$1 $v" "fixed in $2"; action "Update $1 to $2 or later (built-in updater)"; fi
    return
  done
}
if [ "$OS" = Darwin ]; then
  app_check "Visual Studio Code" "$FIXED_VSCODE" "Visual Studio Code.app"
  app_check "Docker Desktop" "$FIXED_DOCKER" "Docker.app"
  app_check "Obsidian" "$FIXED_OBSIDIAN" "Obsidian.app"
else
  if has code; then
    cv=$(code --version 2>/dev/null </dev/null | head -1)
    if [ -z "$cv" ]; then :
    elif ver_ge "$cv" "$FIXED_VSCODE"; then row VERSION_OK "Visual Studio Code $cv" "fixed from $FIXED_VSCODE"
    else row OUTDATED "Visual Studio Code $cv" "fixed in $FIXED_VSCODE"; action "Update Visual Studio Code to $FIXED_VSCODE or later (distro package or built-in updater)"; fi
  fi
  echo "  Docker Desktop and Obsidian are not checked on Linux: compare their versions with the tracker by hand."
fi
if has claude; then
  cv=$(claude --version 2>/dev/null </dev/null | awk '{print $1}')
  if ver_ge "$cv" "$FIXED_CLAUDE"; then row VERSION_OK "Claude Code $cv" "fixed from $FIXED_CLAUDE"
  else row OUTDATED "Claude Code $cv" "fixed in $FIXED_CLAUDE"; action "Update Claude Code (claude update)"; fi
fi
echo "  Other Electron apps carry their own Chromium: keep them updated."

if [ -n "$SCAN_DIRS" ]; then
  while IFS= read -r d <&3; do
    [ -n "$d" ] || continue
    section "Virtualenvs under $(short "$d")"
    if ! venv_list "$d" > "$TMP/venvs"; then
      row INCONCLUSIVE "virtualenv discovery" "some paths could not be read"
    fi
    if [ ! -s "$TMP/venvs" ]; then echo "  none found"; fi
    while IFS= read -r vd <&4; do
      if [ -x "$vd/bin/python" ]; then check_python "$vd/bin/python" venv "$(short "$vd")"
      else row BROKEN "$(short "$vd")" "interpreter missing: recreate the venv"; fi
    done 4< "$TMP/venvs"

    section "Disabled TLS verification under $(short "$d")"
    # Source and config files only, size-capped: a plain recursive grep over data fixtures takes minutes.
    scan_status=0
    find "$d" \( -name .git -o -name node_modules -o -name .venv -o -name venv -o -name site-packages -o -name dist \
        -o -name build -o -name cdk.out -o -name .terraform -o -name .cache -o -name .claude -o -name __pycache__ \) -prune \
      -o -type f -size -512k \( -name '*.py' -o -name '*.js' -o -name '*.mjs' -o -name '*.cjs' -o -name '*.ts' \
        -o -name '*.go' -o -name '*.java' -o -name '*.sh' -o -name '*.yml' -o -name '*.yaml' -o -name '*.toml' \
        -o -name '*.cfg' -o -name '*.ini' -o -name '*.json' -o -name '*.tf' -o -name '*.properties' \
        -o -name '.env*' -o -name '.npmrc' -o -name 'Dockerfile*' -o -name 'Makefile' -o -name '*.mk' \
        -o -name '.condarc' -o -name '.wgetrc' -o -name 'pip.conf' -o -name 'pip.ini' -o -name 'Jenkinsfile' \) -print0 > "$TMP/source-files" 2>/dev/null || scan_status=1
    # shellcheck disable=SC2016  # expanded intentionally by the child shell
    xargs -0 /bin/sh -c '
      pattern=$1; shift
      [ "$#" -gt 0 ] || exit 0
      grep -HnIE "$pattern" "$@"
      result=$?
      [ "$result" -le 1 ]
    ' sh \
        'sslVerify[[:space:]]*=[[:space:]]*false|strict-ssl[[:space:]=]+false|NODE_TLS_REJECT_UNAUTHORIZED[^0-9A-Za-z]{0,4}0|PYTHONHTTPSVERIFY[^0-9A-Za-z]{0,4}0|verify[[:space:]]*=[[:space:]]*False|_create_unverified_context|rejectUnauthorized[[:space:]]*:[[:space:]]*false|InsecureSkipVerify[[:space:]]*:[[:space:]]*true|--no-check-certificate|check_certificate[[:space:]]*=[[:space:]]*off|curl[^#|;&]*[[:space:]](-[A-Za-z]*k[A-Za-z]*|--insecure)([[:space:]]|$)|--trusted-host|PIP_TRUSTED_HOST|trusted-host[[:space:]]*=|GIT_SSL_NO_VERIFY|ssl_verify[[:space:]]*:[[:space:]]*(false|no)' \
        < "$TMP/source-files" 2>/dev/null | awk 'match($0, /:[0-9]+:/) { print substr($0, 1, RSTART + RLENGTH - 2) }' > "$TMP/insecure" || scan_status=1
    # The wrapper maps grep's no-match result to success; read errors remain errors.
    if [ "$scan_status" -ne 0 ]; then row INCONCLUSIVE "source scan" "one or more files could not be inspected"; fi
    hits=$(wc -l < "$TMP/insecure" | tr -d ' ')
    if [ "$hits" -eq 0 ]; then
      row OK "no matches"
    else
      row OUTDATED "$hits match(es) to review" "a client with verification off accepts any certificate, compromised or not"
      P="$d/" awk 'BEGIN { p = ENVIRON["P"] } index($0, p) == 1 { $0 = substr($0, length(p) + 1) } { print }' "$TMP/insecure" | cut -c1-160 | head -25 | sed 's/^/      /'
      [ "$hits" -gt 25 ] && echo "      ... $((hits - 25)) more"
    fi
  done 3<<EOF
$SCAN_DIRS
EOF
fi

# ---------------------------------------------------------------- summary

section "Summary"
printf '  vulnerable: %s   outdated/review: %s   inconclusive: %s\n' "$VULN" "$WARN" "$INCONC"
if [ -s "$TMP/actions" ]; then
  echo
  echo "  Suggested fixes (this script changes nothing; run these yourself):"
  awk '!seen[$0]++ {print "  - " $0}' "$TMP/actions"
fi
[ "$INCONC" -gt 0 ] && echo "  Inconclusive rows mean a test host or the control site was unreachable: check the network and re-run."
[ "$VULN" -gt 0 ] && exit 1
if [ "$STRICT" -eq 1 ]; then
  [ "$INCONC" -gt 0 ] && exit 3
  [ "$WARN" -gt 0 ] && exit 4
fi
exit 0

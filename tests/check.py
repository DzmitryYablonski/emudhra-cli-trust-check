#!/usr/bin/env python3
"""Offline regression checks for diagnostics, malformed input and redacted output."""
import base64
import hashlib
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock
import types

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'emudhra-cli-trust-check.sh'
SOURCE = SCRIPT.read_text()
ROOTS = re.search(r'^DISTRUSTED_ROOTS="(.*?)"', SOURCE, re.M | re.S).group(1)
PROBE = SOURCE.split("<<'PY'\n", 1)[1].split('\nPY\n', 1)[0]
FIXTURES = ROOT / 'tests' / 'fixtures'


def function(name):
    single = re.search(r'^' + re.escape(name) + r'\(\) \{[^\n]*\}$', SOURCE, re.M)
    if single:
        return single.group(0)
    return re.search(r'^' + re.escape(name) + r'\(\) \{.*?^\}', SOURCE, re.M | re.S).group(0)


def bash(code, *args, timeout=10):
    return subprocess.run(['bash', '-c', code, '--', *args], capture_output=True,
                          text=True, timeout=timeout)


class Diagnostics(unittest.TestCase):
    def test_help_is_available_without_network(self):
        p = subprocess.run(['bash', str(SCRIPT), '--help'], capture_output=True, text=True, timeout=5)
        self.assertEqual(p.returncode, 0)
        self.assertIn('read-only', p.stdout)

    def test_invalid_cli_is_usage_error(self):
        for args in (['--unknown'], ['--scan'], ['--scan', '/nonexistent-emudhra-test']):
            with self.subTest(args=args):
                p = subprocess.run(['bash', str(SCRIPT), *args], capture_output=True, timeout=5)
                self.assertEqual(p.returncode, 2)

    def test_verdicts(self):
        cases = [(['4', '0', '0', '1'], 'OK'),
                 (['3', '1', '0', '1'], 'VULNERABLE'),
                 (['3', '0', '1', '1'], 'INCONCLUSIVE'),
                 (['4', '0', '0', '0'], 'INCONCLUSIVE'),
                 (['5', '0', '0', '1'], 'INCONCLUSIVE'),
                 (['garbage', '0', '0', '1'], 'INCONCLUSIVE'),
                 ([], 'INCONCLUSIVE')]
        for args, expected in cases:
            with self.subTest(args=args):
                p = bash('NH=4; TLS_EXPIRED=0\n' + function('verdict') + '\nverdict "$@"', *args)
                self.assertEqual(p.returncode, 0, p.stderr)
                self.assertEqual(p.stdout.strip(), expected)

    def test_summary_exit_codes(self):
        # Run the actual summary gates, without probing the host or network.
        gates = SOURCE[SOURCE.rindex('[ "$VULN" -gt 0 ] && exit 1'):]
        for strict in (0, 1):
            for vulnerable, inconclusive, warnings, strict_expected in (
                    (0, 0, 0, 0), (1, 0, 0, 1), (0, 1, 0, 3), (0, 0, 1, 4), (1, 1, 1, 1)):
                expected = strict_expected if strict or vulnerable else 0
                with self.subTest(strict=strict, expected=expected):
                    p = bash(f'STRICT={strict}; VULN={vulnerable}; INCONC={inconclusive}; WARN={warnings}\n' + gates)
                    self.assertEqual(p.returncode, expected)

    def test_release_requires_only_one_script_and_hash(self):
        import shutil
        lines = (ROOT / 'SHA256SUMS').read_text().splitlines()
        self.assertEqual(len(lines), 1)
        expected, filename = lines[0].split('  ', 1)
        self.assertEqual(filename, SCRIPT.name)
        self.assertEqual(hashlib.sha256(SCRIPT.read_bytes()).hexdigest(), expected)
        with tempfile.TemporaryDirectory() as d:
            shutil.copy2(SCRIPT, d)
            shutil.copy2(ROOT / 'SHA256SUMS', d)
            p = subprocess.run(['shasum', '-a', '256', '-c', 'SHA256SUMS'], cwd=d,
                               capture_output=True, text=True, timeout=5)
            self.assertEqual(p.returncode, 0, p.stderr)

    def test_strict_flag_remains_offline_with_help(self):
        p = subprocess.run(['bash', str(SCRIPT), '--strict', '--help'],
                           capture_output=True, text=True, timeout=5)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn('--strict', p.stdout)

    def test_upstream_expiry_guard_is_preserved(self):
        for tally, expected in [('4 0 0 1', 'INCONCLUSIVE'), ('3 1 0 1', 'VULNERABLE')]:
            p = bash('NH=4; TLS_EXPIRED=1\n' + function('verdict') + '\nverdict ' + tally)
            self.assertEqual(p.stdout.strip(), expected)

    def test_unsigned_aws_probe_stays_bounded_and_classifies_results(self):
        with tempfile.TemporaryDirectory() as d:
            fake = Path(d) / 'aws'
            fake.write_text('#!/bin/sh\n'
                            'case " $* " in *" --no-sign-request "*) ;; *) exit 99 ;; esac\n'
                            '[ "$AWS_EC2_METADATA_DISABLED" = true ] || exit 99\n'
                            '[ "$AWS_MAX_ATTEMPTS" = 1 ] || exit 99\n'
                            'case "$1" in s3api) echo "$EMUDHRA_AWS_FIXTURE" >&2 ;; esac\nexit 1\n')
            fake.chmod(0o700)
            code = function('run_timed') + '\n' + function('aws_hit') + '\naws_hit "$1" https://example/'
            for message, expected in [('CERTIFICATE_VERIFY_FAILED', 'B'),
                                      ('Could not connect to endpoint', 'E'),
                                      ('An error occurred (AccessDenied)', 'C')]:
                p = bash('export EMUDHRA_AWS_FIXTURE=$2\n' + code, str(fake), message)
                self.assertEqual(p.stdout.strip(), expected, p.stderr)

    def test_timeout_has_no_delayed_command_substitution(self):
        start = time.monotonic()
        p = bash(function('run_timed') + '\nout=$(run_timed 20 printf done); printf "%s" "$out"', timeout=5)
        self.assertEqual(p.stdout, 'done')
        self.assertLess(time.monotonic() - start, 5)

    def test_timeout_terminates_stalled_command(self):
        p = bash(function('run_timed') + '\nrun_timed 1 sleep 20', timeout=6)
        self.assertNotEqual(p.returncode, 0)

    def test_timeout_cleans_up_descendants_and_inherited_pipes(self):
        code = function('run_timed') + '\nrun_timed 1 bash -c \'sleep 20 & wait\''
        p = bash(code, timeout=6)
        self.assertNotEqual(p.returncode, 0)

    def test_versions_do_not_accept_prereleases_or_unknown_text(self):
        for actual, minimum, expected in [('v26.12.1', '26.12.1', 0),
                                          ('21.0.13+11-LTS', '21.0.13', 0),
                                          ('26.12.1-rc.1', '26.12.1', 1),
                                          ('unknown999', '1', 1), ('', '1', 1),
                                          ('24.22.0', '24.22.1', 1), ('1.10', '1.9', 0)]:
            with self.subTest(actual=actual):
                p = bash(function('ver_ge') + '\nver_ge "$1" "$2"', actual, minimum)
                self.assertEqual(p.returncode, expected, p.stderr)

    def test_curl_does_not_load_user_configuration(self):
        with tempfile.TemporaryDirectory() as d:
            fake = Path(d) / 'curl'
            fake.write_text('#!/bin/sh\n[ "$1" = -q ] || exit 99\nexit 60\n')
            fake.chmod(0o700)
            code = 'TEST_URLS=(a b c d); CONTROL_URL=e\n' + function('curl_probe')
            p = bash(code + '\ncurl_probe "$1"', str(fake))
            self.assertEqual(p.stdout.strip(), '4 0 0 0')

    def test_git_excludes_credentials_and_rewrites_but_preserves_tls_settings(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            config = root / 'gitconfig'
            config.write_text('[http]\nsslVerify = false\nextraHeader = SECRET\n'
                              '[credential]\nhelper = secret-helper\n'
                              '[url "https://secret.example/"]\ninsteadOf = https://example/\n')
            fake = root / 'git'
            real_git = subprocess.check_output(['which', 'git'], text=True).strip()
            fake.write_text('#!/bin/bash\nif [ "$1" = config ]; then exec "$REAL_GIT" "$@"; fi\n'
                            'printf "NETRC=%s\\n" "$NETRC"\n'
                            'args=(); while [ "$#" -gt 0 ]; do\n'
                            '  [ "$1" = ls-remote ] && break\n'
                            '  args+=("$1"); shift\ndone\n'
                            'exec "$REAL_GIT" "${args[@]}" config --list\n')
            fake.chmod(0o700)
            code = ('export REAL_GIT=$1 GIT_CONFIG_GLOBAL=$2\n'
                    'TMP=$3; export PATH="$TMP:$PATH"\n' + function('run_timed') + '\n' + function('git_tls') +
                    '\ngit_tls https://example/probe.git')
            p = bash(code, real_git, str(config), d)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertIn('http.sslverify=false', p.stdout)
            self.assertIn('NETRC=/dev/null', p.stdout)
            self.assertIn('http.extraheader=Authorization:', p.stdout)
            self.assertNotIn('SECRET', p.stdout)
            self.assertNotIn('secret-helper', p.stdout)
            self.assertNotIn('insteadof', p.stdout)

    def test_requests_does_not_send_netrc_credentials_or_follow_redirects(self):
        namespace = {}
        with mock.patch.dict(os.environ, DISTRUSTED_ROOTS=ROOTS), mock.patch.object(sys, 'argv', ['probe', 'control']):
            exec(PROBE.split('if CONTROL == "--bundles":', 1)[0], namespace)
        request = types.SimpleNamespace(headers={})
        def get(url, **options):
            # requests applies .netrc auth only when explicit auth is absent.
            if not options.get('auth'):
                request.headers['Authorization'] = 'SECRET'
            else:
                options['auth'](request)
            self.assertFalse(options['allow_redirects'])
            return types.SimpleNamespace(close=lambda: None)
        with mock.patch.dict(sys.modules, requests=types.SimpleNamespace(get=get)):
            self.assertEqual(namespace['via_requests']('https://example/'), 'C')
        self.assertNotIn('Authorization', request.headers)


class Java(unittest.TestCase):
    def test_failed_keytool_never_passes_partial_fingerprints(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / 'distrusted.txt').write_text(ROOTS)
            fake = root / 'keytool'
            fake.write_text('#!/bin/sh\necho " SHA256: 00:11:22"\nexit 1\n')
            fake.chmod(0o700)
            code = ('set -o pipefail\nTMP=$1\n' + function('run_timed') + '\n' +
                    function('roots_in_fps') + '\n' + function('java_store_roots'))
            p = bash(code + '\njava_store_roots unused "$2"', d, str(fake))
            self.assertEqual(p.stdout.strip(), 'empty', p.stderr)

    def test_unavailable_java_inspections_are_inconclusive(self):
        start = SOURCE.index('    jv=$("$jh/bin/java"')
        end = SOURCE.index('  done 3< "$TMP/jvms"', start)
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / 'bin').mkdir()
            java = root / 'bin/java'
            java.write_text('#!/bin/sh\necho \'openjdk version "21.0.13"\'\n')
            java.chmod(0o700)
            code = ('TMP=$1; jh=$1; OS=Linux\nrow(){ echo "$1"; }\naction(){ :; }\nshort(){ echo "$1"; }\n' +
                    function('rank') + '\n' + function('worse') + '\n' + function('ver_ge') + '\n' +
                    SOURCE[start:end])
            p = bash(code, d)
            self.assertEqual(p.stdout.strip(), 'INCONCLUSIVE', p.stderr)
            # A failed compiler is also incomplete even when the CA content check succeeds.
            javac = root / 'bin/javac'
            javac.write_text('#!/bin/sh\nexit 1\n'); javac.chmod(0o700)
            keytool = root / 'bin/keytool'
            keytool.write_text('#!/bin/sh\nexit 0\n'); keytool.chmod(0o700)
            (root / 'lib/security').mkdir(parents=True)
            (root / 'lib/security/cacerts').touch()
            p = bash('java_store_roots(){ echo clean; }\n' + function('run_timed') + '\n' + code, d)
            self.assertEqual(p.stdout.strip(), 'INCONCLUSIVE', p.stderr)

    def test_java_verdict_follows_cacerts_content(self):
        # No release ships JDK-8395690 yet: the version is a lower bound, the cacerts content decides.
        start = SOURCE.index('    jv=$("$jh/bin/java"')
        end = SOURCE.index('  done 3< "$TMP/jvms"', start)
        for version, roots, expected in [('1.8.0_512', 'clean', 'OK'), ('1.8.0_511', 'clean', 'OK'),
                                         ('1.8.0_501', 'clean', 'OUTDATED'), ('17.0.21.0.10', 'clean', 'OK'),
                                         ('17.0.20', 'clean', 'OUTDATED'), ('28.0.1', 'clean', 'OK'),
                                         ('11.0.20', 'clean', 'OUTDATED'), ('16.0.2', 'clean', 'OUTDATED'),
                                         ('1.8.0_512', 'AAA+emSign-G1', 'OUTDATED'),
                                         ('21.0.13.0.10', 'emSign-G2', 'OUTDATED')]:
            with self.subTest(version=version, roots=roots), tempfile.TemporaryDirectory() as d:
                root = Path(d)
                (root / 'bin').mkdir()
                (root / 'lib/security').mkdir(parents=True)
                (root / 'lib/security/cacerts').touch()
                java = root / 'bin/java'
                java.write_text(f'#!/bin/sh\necho \'openjdk version "{version}"\'\n')
                keytool = root / 'bin/keytool'
                keytool.write_text('#!/bin/sh\nexit 0\n')
                java.chmod(0o700); keytool.chmod(0o700)
                code = ('TMP=$1; jh=$1; OS=Linux; ROOTS_STUB=$2\nrow(){ echo "$1"; }\naction(){ :; }\nshort(){ echo "$1"; }\n'
                        'java_store_roots(){ echo "$ROOTS_STUB"; }\n' + function('rank') + '\n' + function('worse') + '\n' +
                        function('ver_ge') + '\n' + SOURCE[start:end])
                p = bash(code, d, roots)
                self.assertEqual(p.stdout.strip(), expected, p.stderr)

    def test_java_list_adds_openjdk_roots_only_for_java(self):
        self.assertIn('emSign-G1', SOURCE[SOURCE.index('JAVA_EXTRA_ROOTS='):SOURCE.index('JAVA_EXTRA_ROOTS=') + 300])
        self.assertNotIn('40F6AF0346A99AA1CD1D555A4E9CCE62C7F9634603EE406615833DC8C8D00367', ROOTS)


class Bundles(unittest.TestCase):
    def check_bundles(self, contents):
        with tempfile.TemporaryDirectory() as d:
            probe = Path(d) / 'probe.py'
            probe.write_text(PROBE)
            paths = []
            for i, value in enumerate(contents):
                p = Path(d) / f'bundle-{i}.pem'
                p.write_text(value)
                paths.append(str(p))
            env = dict(os.environ, DISTRUSTED_ROOTS=ROOTS)
            out = subprocess.run([sys.executable, '-I', str(probe), '--bundles', *paths],
                                 env=env, capture_output=True, text=True, check=True, timeout=10)
            return [line.split('\t')[1] for line in out.stdout.splitlines()]

    def test_public_affected_fixture_identity(self):
        import ssl
        der = ssl.PEM_cert_to_DER_cert((FIXTURES / 'emsign-ecc-g3.pem').read_text())
        self.assertEqual(hashlib.sha256(der).hexdigest(),
                         '86a1ecba089c4a8d3bbe2734c612ba341d813e043cf9e8a862cd5c57a36bbe6b')

    def test_affected_and_clean_bundles(self):
        self.assertEqual(self.check_bundles([(FIXTURES / 'emsign-ecc-g3.pem').read_text(),
                                            (FIXTURES / 'control-root.pem').read_text()]),
                         ['emSign-ECC-G3', 'clean'])

    def test_empty_invalid_and_mixed_bundles_never_pass(self):
        invalid = '-----BEGIN CERTIFICATE-----\n' + base64.b64encode(b'not X.509').decode() + '\n-----END CERTIFICATE-----\n'
        mixed = (FIXTURES / 'control-root.pem').read_text() + invalid
        self.assertEqual(self.check_bundles(['', invalid, mixed]), ['empty', 'empty', 'empty'])

    def test_openssl_fallback_rejects_partial_parse(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'mixed.pem'
            p.write_text((FIXTURES / 'control-root.pem').read_text() +
                         '\n-----BEGIN CERTIFICATE-----\nbm90IFguNTA5\n-----END CERTIFICATE-----\n')
            (Path(d) / 'distrusted.txt').write_text(ROOTS + '\n')
            code = 'set -o pipefail\nTMP=$1\n' + function('roots_in_fps') + '\n' + function('bundle_roots_openssl')
            out = bash(code + '\nbundle_roots_openssl "$2"', d, str(p))
            self.assertEqual(out.stdout.strip(), 'empty', out.stderr)


class Redaction(unittest.TestCase):
    def run_scan(self, root, tmp):
        start = SOURCE.index('    scan_status=0\n')
        end = SOURCE.index('    hits=$(wc -l', start)
        code = ('set -o pipefail\nTMP=$1\nd=$2\n'
                'row(){ printf "%s\\n" "$1"; }\n' + SOURCE[start:end] + '\ncat "$TMP/insecure"')
        return bash(code, str(tmp), str(root))

    def test_source_content_is_redacted_and_spaces_work(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d) / 'source'; root.mkdir()
            p = root / 'settings with spaces.py'
            p.write_text('verify=False; SECRET="must-not-be-printed"\n')
            out = self.run_scan(root, Path(d))
            self.assertEqual(out.stdout.strip(), str(p) + ':1')
            self.assertNotIn('SECRET', out.stdout)
            self.assertNotIn('must-not-be-printed', out.stdout)

    def test_empty_scan_has_no_error(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d) / 'source'; root.mkdir()
            self.assertEqual(self.run_scan(root, Path(d)).stdout.strip(), '')

    def test_unreadable_root_is_inconclusive(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertIn('INCONCLUSIVE', self.run_scan(Path(d) / 'missing', Path(d)).stdout)


class Curlrc(unittest.TestCase):
    """curl probes run with -q, so an insecure or custom-CA .curlrc must be reported on its own."""

    def check(self, home, contents=None, bundle_result='clean', curl_home=''):
        if contents is not None:
            (home / '.curlrc').write_text(contents)
        code = ('export BUNDLE_RESULT=$2 HOME=$1 CURL_HOME=$3; unset XDG_CONFIG_HOME\n'
                '[ -n "$CURL_HOME" ] || unset CURL_HOME\n'
                'row(){ printf "%s|%s\\n" "$1" "$3"; }\naction(){ :; }\nshort(){ printf "%s" "$1"; }\n'
                'bundle_check(){ printf "%s" "$BUNDLE_RESULT"; }\n' +
                function('rank') + '\n' + function('worse') + '\n' +
                function('curlrc_file') + '\n' + function('check_curlrc') + '\ncheck_curlrc')
        p = bash(code, str(home), bundle_result, curl_home)
        self.assertEqual(p.returncode, 0, p.stderr)
        return p.stdout.strip()

    def test_insecure_settings_are_vulnerable(self):
        for contents in ('insecure\n', '--insecure\n', '-k\n', 'proxy-insecure\n'):
            with self.subTest(contents=contents), tempfile.TemporaryDirectory() as d:
                self.assertTrue(self.check(Path(d), contents).startswith('VULNERABLE|'))

    def test_plain_or_missing_config_passes(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(self.check(Path(d)), '')
            self.assertEqual(self.check(Path(d), '# insecure\nsilent\n'), 'OK|no certificate overrides')

    def test_cacert_bundle_is_judged_by_content(self):
        with tempfile.TemporaryDirectory() as d:
            bundle = Path(d) / 'old bundle.pem'
            bundle.write_text('placeholder')
            self.assertEqual(self.check(Path(d), f'cacert = "{bundle}"\n', 'emSign-ECC-G3'),
                             f'VULNERABLE|cacert {bundle} trusts emSign-ECC-G3')
            self.assertEqual(self.check(Path(d), f'cacert {bundle}\n', 'clean'), f'OK|cacert {bundle} clean')
            self.assertTrue(self.check(Path(d), 'cacert /nonexistent.pem\n').startswith('OUTDATED|'))
            self.assertTrue(self.check(Path(d), 'capath /etc/ssl/certs\n').startswith('OUTDATED|'))

    def test_curl_home_takes_precedence(self):
        with tempfile.TemporaryDirectory() as d, tempfile.TemporaryDirectory() as c:
            (Path(c) / '.curlrc').write_text('silent\n')
            self.assertEqual(self.check(Path(d), 'insecure\n', curl_home=c), 'OK|no certificate overrides')


class Tools(unittest.TestCase):
    def run_tool(self, name, output, *args):
        with tempfile.TemporaryDirectory() as d:
            fake = Path(d) / name
            fake.write_text('#!/bin/sh\nprintf "%s\\n" "$FAKE_OUTPUT"\n')
            fake.chmod(0o700)
            code = ('export PATH="$1:$PATH" FAKE_OUTPUT=$2; shift 2\n'
                    'has(){ command -v "$1" >/dev/null 2>&1; }\nrow(){ echo "$1 $2"; }\naction(){ :; }\n' +
                    function('run_timed') + '\n' + function('ver_ge') + '\n' + function('tool_check') + '\ntool_check "$@"')
            p = bash(code, d, output, *args)
            self.assertEqual(p.returncode, 0, p.stderr)
            return p.stdout.strip()

    def test_versions_are_compared_with_the_fix(self):
        self.assertEqual(self.run_tool('gh', 'gh version 2.101.0 (2026-10-01)', 'GitHub CLI', '2.102.1', 'gh version ', 'gh', '--version'),
                         'OUTDATED GitHub CLI 2.101.0')
        self.assertEqual(self.run_tool('gh', 'gh version 2.102.1 (2026-10-22)', 'GitHub CLI', '2.102.1', 'gh version ', 'gh', '--version'),
                         'VERSION_OK GitHub CLI 2.102.1')
        self.assertEqual(self.run_tool('bun', '1.4.3', 'Bun', '1.4.4', '^', 'bun', '--version'), 'OUTDATED Bun 1.4.3')

    def test_unrecognised_output_is_skipped(self):
        # A podman alias answering as "docker" must not be compared with Docker's version floor.
        self.assertEqual(self.run_tool('docker', 'podman version 4.9.3', 'Docker CLI', '29.9.2', 'Docker version ', 'docker', '--version'), '')


if __name__ == '__main__':
    unittest.main(verbosity=2)

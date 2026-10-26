#!/usr/bin/env python3
"""Build the two release files from one Git commit; development tooling only."""
import hashlib
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = 'emudhra-cli-trust-check.sh'


def build(destination, repo=ROOT):
    def git(*arguments):
        return subprocess.check_output(['git', '-C', str(repo), *arguments])
    commit = git('rev-parse', 'HEAD').decode().strip()
    script = git('show', commit + ':' + SCRIPT)
    manifest = git('show', commit + ':SHA256SUMS')
    expected = (hashlib.sha256(script).hexdigest() + '  ' + SCRIPT + '\n').encode()
    if manifest != expected:
        raise ValueError('Committed SHA256SUMS must contain exactly the matching script hash.')
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=False)
    (destination / SCRIPT).write_bytes(script)
    (destination / SCRIPT).chmod(0o755)
    (destination / 'SHA256SUMS').write_bytes(manifest)
    return commit


if __name__ == '__main__':
    if len(sys.argv) != 2:
        sys.exit('Usage: python3 tools/build-release.py NEW_OUTPUT_DIRECTORY')
    print('Release files built from commit ' + build(sys.argv[1]))

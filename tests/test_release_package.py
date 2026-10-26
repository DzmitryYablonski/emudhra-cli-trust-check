#!/usr/bin/env python3
"""Prove packages use committed bytes and reject stale or expanded manifests."""
import hashlib
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('release', ROOT / 'tools/build-release.py')
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


class Package(unittest.TestCase):
    def fixture(self, root, manifest=None):
        repo = root / 'repo'; repo.mkdir()
        subprocess.run(['git', 'init', '--quiet', str(repo)], check=True)
        content = b'#!/bin/bash\necho fixture\n'
        (repo / release.SCRIPT).write_bytes(content)
        checksum = hashlib.sha256(content).hexdigest() + '  ' + release.SCRIPT + '\n'
        (repo / 'SHA256SUMS').write_text(checksum if manifest is None else manifest)
        subprocess.run(['git', '-C', str(repo), 'add', release.SCRIPT, 'SHA256SUMS'], check=True)
        subprocess.run(['git', '-C', str(repo), '-c', 'user.name=Fixture', '-c',
                        'user.email=fixture@example.invalid', '-c', 'commit.gpgsign=false', '-c', 'core.hooksPath=/dev/null', 'commit', '--quiet', '-m', 'fixture'], check=True)
        return repo, content

    def test_only_committed_script_and_manifest_are_packaged(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); repo, content = self.fixture(root)
            (repo / release.SCRIPT).write_text('uncommitted changes must not ship')
            destination = root / 'out'
            commit = release.build(destination, repo)
            self.assertEqual(len(commit), 40)
            self.assertEqual(sorted(p.name for p in destination.iterdir()), sorted([release.SCRIPT, 'SHA256SUMS']))
            self.assertEqual((destination / release.SCRIPT).read_bytes(), content)
            self.assertTrue((destination / release.SCRIPT).stat().st_mode & 0o100)
            result = subprocess.run(['shasum', '-a', '256', '-c', 'SHA256SUMS'], cwd=destination,
                                    capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_invalid_or_expanded_manifest_is_rejected(self):
        for manifest in ('0' * 64 + '  ' + release.SCRIPT + '\n', 'extra file\n'):
            with self.subTest(manifest=manifest), tempfile.TemporaryDirectory() as d:
                root = Path(d); repo, _ = self.fixture(root, manifest)
                with self.assertRaises(ValueError):
                    release.build(root / 'out', repo)
                self.assertFalse((root / 'out').exists())

    def test_existing_output_is_preserved(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); repo, _ = self.fixture(root)
            destination = root / 'out'; destination.mkdir()
            (destination / 'keep.txt').write_text('keep')
            with self.assertRaises(FileExistsError):
                release.build(destination, repo)
            self.assertEqual((destination / 'keep.txt').read_text(), 'keep')


if __name__ == '__main__':
    unittest.main(verbosity=2)

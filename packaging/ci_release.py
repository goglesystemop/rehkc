#!/usr/bin/env python3
"""Build/test pinned inputs, then publish one new release from GitHub Actions."""
import argparse
import ast
import hashlib
import json
import os
import re
from pathlib import Path
import subprocess
import sys
import tarfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]


def run(*args, **kwargs):
    return subprocess.run(list(map(str, args)), cwd=ROOT, check=True, **kwargs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work-dir', required=True, type=Path)
    parser.add_argument('--build-only', action='store_true')
    args = parser.parse_args()
    work = args.work_dir.resolve()
    work.mkdir(parents=True, exist_ok=True)
    metadata_path = ROOT/'packaging/release.json'
    previous_bytes = metadata_path.read_bytes()
    previous = json.loads(previous_bytes)
    version = json.loads((ROOT/'packaging/version.json').read_text())['version']
    if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', version):
        raise SystemExit('Expected a stable major.minor.patch version.')
    boot = ast.parse((ROOT/'app/rehkc_boot.py').read_text())
    boot_version = next(node.value.value for node in boot.body if isinstance(node, ast.Assign)
                        and any(isinstance(target, ast.Name) and target.id == 'VERSION' for target in node.targets))
    if boot_version != version:
        raise SystemExit('Launcher and package versions differ.')
    tag = 'v' + version
    if not args.build_only:
        if (os.environ.get('GITHUB_REPOSITORY') != 'goglesystemop/rehkc'
                or os.environ.get('GITHUB_REF') != 'refs/heads/main'):
            raise SystemExit('Publishing is restricted to the REHKC main branch.')
        existing = subprocess.run(['gh', 'release', 'view', tag], cwd=ROOT,
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if existing.returncode == 0:
            raise SystemExit('Release already exists; choose a new version. No assets replaced.')
    vendor_archive = work/'verified-vendor.tar.gz'
    if not vendor_archive.exists():
        urllib.request.urlretrieve(previous['url'], vendor_archive)
    with vendor_archive.open('rb') as source:
        actual = hashlib.file_digest(source, 'sha256').hexdigest()
    if actual != previous['sha256']:
        raise SystemExit('Vendor archive checksum mismatch.')
    vendor = work/'vendor'
    vendor.mkdir(exist_ok=True)
    with tarfile.open(vendor_archive) as archive:
        archive.extractall(vendor, filter='data')
    vendor_root = vendor/previous['asset'].removesuffix('.tar.gz')
    stage = work/('rehkc-' + version + '-linux-x86_64')
    output = work/'dist'
    try:
        run(sys.executable, 'packaging/build_release.py', '--engine', vendor_root/'app/rea.bin',
            '--assets', vendor_root/'app', '--stage', stage, '--output', output)
        run(sys.executable, 'tests/test_tool_environment.py')
        run(sys.executable, 'tests/test_local_build.py')
        run(sys.executable, 'tests/test_system_dependencies.py')
        run(stage/'runtime/python/bin/python3', ROOT/'tests/test_managed_tools.py')
        run(stage/'runtime/python/bin/python3', ROOT/'tests/test_tool_ui.py')
        run(stage/'runtime/python/bin/python3', ROOT/'tests/test_mcp_timeouts.py')
        run(stage/'runtime/python/bin/python3', ROOT/'tests/test_staged_analysis.py')
        run(stage/'runtime/python/bin/python3', ROOT/'tests/test_static_inspection.py')
        run(stage/'runtime/python/bin/python3', ROOT/'tests/test_analysis_sessions.py')
        run(stage/'runtime/python/bin/python3', ROOT/'tests/test_analysis_progress.py')
        run(stage/'runtime/python/bin/python3', ROOT/'tests/test_code_export.py')
        run(sys.executable, 'tests/test_distribution.py', '--package', stage)
        run(sys.executable, 'tests/test_managed_engines_live.py', '--package', stage, '--report', work/'managed-engines.json')
        run(stage/'run', '--smoke-test', '--report', work/'smoke.json',
            env=dict(os.environ, QT_QPA_PLATFORM='offscreen'))
        run(stage/'run', '--engine', 'mcp', 'doctor', '--json')
        if args.build_only:
            return
        metadata = json.loads(metadata_path.read_text())
        archive = output/metadata['asset']
        run('git', 'config', 'user.name', 'github-actions[bot]')
        run('git', 'config', 'user.email', '41898282+github-actions[bot]@users.noreply.github.com')
        run('git', 'add', 'packaging/release.json')
        run('git', 'commit', '-m', 'release: pin verified ' + version + ' archive')
        # A normal fast-forward push refuses concurrent edits; no force push.
        run('git', 'push', 'origin', 'HEAD:main')
        commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
        run('gh', 'release', 'create', tag, '--draft', '--target', commit,
            '--title', 'REHKC ' + version + ' — Linux desktop',
            '--notes-file', 'docs/RELEASE-' + version + '.md', archive, output/'SHA256SUMS')
        run('gh', 'release', 'edit', tag, '--draft=false', '--latest')
    finally:
        if args.build_only:
            metadata_path.write_bytes(previous_bytes)


if __name__ == '__main__':
    main()

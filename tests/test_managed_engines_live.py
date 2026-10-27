"""Network/real-engine acceptance: empty prefix, normal launcher, no external engines.

Run separately from unit tests. Official engine archives total about 975 MB.
"""
import argparse
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--package', type=Path, required=True)
parser.add_argument('--report', type=Path)
args = parser.parse_args()
package = args.package.resolve()
result = {}
with tempfile.TemporaryDirectory(prefix='rehkc-managed-live-') as temporary:
    base = Path(temporary)
    prefix = base/'application'
    env = {k:v for k,v in os.environ.items() if k not in (
        'JAVA_HOME','GHIDRA_INSTALL_DIR','RETDEC_INSTALL_DIR','REHKC_INSTALL_ROOT',
        'REHKC_TOOLS_DIR','LD_LIBRARY_PATH','R2_PREFIX','PYTHONPATH','PYTHONHOME')}
    env.update(PATH='/usr/bin:/bin', REHKC_CONFIG_DIR=str(base/'config'), REHKC_DATA_DIR=str(base/'data'))
    def run(*command, timeout=600, extra_env=None, **kwargs):
        completed = subprocess.run(list(map(str, command)), env=dict(env, **(extra_env or {})), stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, text=True, timeout=timeout, **kwargs)
        if completed.returncode:raise AssertionError(completed.stdout[-6000:])
        return completed.stdout
    # No --without-tools: exercise the public installer default, not just a helper.
    output = run('/bin/sh', package/'install.sh', '--data-dir', prefix,
                 '--bin-dir', base/'bin', '--desktop-dir', base/'applications', '--no-desktop')
    assert 'Installed REHKC' in output, output
    result['default_install'] = True
    launcher = base/'bin/rehkc'
    status = json.loads(run(launcher, '--tools', 'status'))
    assert status['managed'] and status['health']['ok'], status
    result['status'] = status
    doctor = json.loads(run(launcher, '--doctor'))
    assert doctor['ghidra_configured'], doctor
    assert str(prefix/'tools') in doctor['optional_tools']['radare2'], doctor
    assert str(prefix/'tools') in doctor['optional_tools']['java'], doctor
    assert str(prefix/'tools') in doctor['optional_tools']['retdec-decompiler'], doctor
    result['menu_path_discovery'] = True
    # Verify the actual bundled REA/Ghidra bridge on a generated, never executed ELF.
    target = base/'probe.elf'
    code = bytes.fromhex('488d047f4801f0c3')
    header = struct.pack('<16sHHIQQQIHHHHHH',b'\x7fELF\x02\x01\x01'+b'\0'*9,
                         2,62,1,0x400078,64,0,0,64,56,1,64,0,0)
    segment = struct.pack('<IIQQQQQQ',1,5,0,0x400000,0x400000,128,128,4096)
    target.write_bytes(header+segment+code)
    decompiled = run(launcher, '--engine', 'decompile', target, '0x400078', '--provider', 'ghidra', '--format', 'json', timeout=240)
    assert 'return' in decompiled and 'ghidra' in decompiled.lower(), decompiled[-5000:]
    result['rea_ghidra_bridge'] = True
    result['decompile_excerpt'] = decompiled[-2500:]
    # Exercise the same staged/cache/fallback path used by GUI and MCP, through
    # the installed normal launcher. All selected target bytes are generated here.
    import shlex
    adapter = base/'normal-engine'
    adapter.write_text('#!/bin/sh\nexec '+shlex.quote(str(launcher))+' --engine "$@"\n')
    adapter.chmod(0o755)
    staged_report = base/'staged.json'
    run(package/'runtime/python/bin/python3', Path(__file__).with_name('staged_live_probe.py'),
        '--package', prefix/'current', '--engine', adapter, '--target', target,
        '--procedure', '0x400078', '--report', staged_report, timeout=600,
        extra_env={'REHKC_INSTALL_ROOT':str(prefix)})
    result['staged_analysis'] = json.loads(staged_report.read_text())
    # Reinstall is idempotent and a second dependency check remains valid.
    run('/bin/sh', package/'install.sh', '--data-dir', prefix,
        '--bin-dir', base/'bin', '--desktop-dir', base/'applications', '--no-desktop')
    result['idempotent'] = json.loads(run(launcher,'--tools','status'))['release'] == status['release']
    run('/bin/sh', prefix/'current/install.sh', '--data-dir', prefix,
        '--bin-dir', base/'bin', '--desktop-dir', base/'applications', '--no-desktop', '--check')
    result['installed_check'] = True
if args.report:args.report.write_text(json.dumps(result,indent=2,ensure_ascii=False)+'\n')
print(json.dumps(result,indent=2,ensure_ascii=False))

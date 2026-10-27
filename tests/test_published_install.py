"""Accept the public release through README's source-bootstrap command, never a local build.

Run on a disposable Debian/Arch host as an unprivileged user with sudo allowed
for its package manager. System dependency installation is real. CI answers the
package manager's normal confirmation via stdin; product prompts stay enabled.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import struct
import subprocess
import sys
import urllib.request

parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--work-dir',required=True,type=Path)
parser.add_argument('--expected-version',required=True)
parser.add_argument('--family',required=True,choices=['debian','arch'])
args=parser.parse_args()
if os.geteuid()==0:raise SystemExit('Run the published installer acceptance test as a desktop user, not root.')
work=args.work_dir.resolve()
work.mkdir(parents=True,exist_ok=False)
version=args.expected_version
source=work/'source'
env={k:v for k,v in os.environ.items() if k not in (
 'JAVA_HOME','GHIDRA_INSTALL_DIR','RETDEC_INSTALL_DIR','REHKC_INSTALL_ROOT','REHKC_TOOLS_DIR',
 'REHKC_ARCHIVE','LD_LIBRARY_PATH','R2_PREFIX','PYTHONPATH','PYTHONHOME','QT_QPA_PLATFORM')}
env.update(PATH='/usr/bin:/bin',XDG_CACHE_HOME=str(work/'cache'),XDG_DATA_HOME=str(work/'data'),
 XDG_CONFIG_HOME=str(work/'config'),REHKC_CONFIG_DIR=str(work/'config/rehkc'),
 REHKC_DATA_DIR=str(work/'user-data'),XDG_RUNTIME_DIR=str(work/'runtime'))
(work/'runtime').mkdir(mode=0o700)
launcher=Path.home()/'.local/bin/rehkc'
assert not launcher.exists(),'This test requires a clean desktop user without an existing REHKC launcher'
result={'expected_version':version,'family':args.family,'os_release':platform.freedesktop_os_release(),
 'empty_cache':True,'root':False,'source_bootstrap':True}

def save():
 (work/'result.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
def run(label,command,timeout=1200,confirm=False,extra_env=None):
 print(label,flush=True)
 with (work/(label+'.log')).open('w') as output:
  process=subprocess.run(list(map(str,command)),env=dict(env,**(extra_env or {})),
   stdout=output,stderr=subprocess.STDOUT,text=True,timeout=timeout,input='y\n'*100 if confirm else None)
 text=(work/(label+'.log')).read_text()
 if process.returncode:raise AssertionError(label+' failed:\n'+text[-7000:])
 return text

def digest(path):
 with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()

run('github-clone',['git','clone','https://github.com/goglesystemop/rehkc.git',source])
result['source_commit']=subprocess.check_output(['git','-C',str(source),'rev-parse','HEAD'],text=True).strip()
meta=json.loads((source/'packaging/release.json').read_text())
assert meta['version']==version,meta
result['release_metadata']=meta
# This is README's real install command, including automatic system packages.
assert not (work/'cache').exists()
output=run('readme-install',['/bin/sh',source/'install.sh','--install-system-deps'],timeout=1800,confirm=True)
manager='apt-get' if args.family=='debian' else 'pacman'
assert 'System dependencies: sudo '+manager in output,output[-6000:]
assert 'Installed REHKC '+version in output,output[-6000:]
result['actual_package_manager']=manager
result['readme_install_success']=True
prefix=work/'data/rehkc'
package=work/'cache/rehkc'/meta['sha256']/meta['asset'].removesuffix('.tar.gz')
archive=work/'cache/rehkc'/meta['asset']
assert digest(archive)==meta['sha256']
for relative in ['installer.py','app/rehkc_boot.py']:
 assert digest(prefix/'current'/relative)==digest(source/relative),relative
result['archive_and_source_hashes_verified']=True
with urllib.request.urlopen('https://github.com/goglesystemop/rehkc/releases/download/v'+version+'/SHA256SUMS',timeout=60) as response:
 checksums=response.read().decode()
assert checksums.strip().split()[0]==meta['sha256']
result['published_checksum_verified']=True
observed=run('version',[launcher,'--version']).strip()
assert observed=='REHKC '+version+' / REA 6.7.0',observed
result['installed_version']=observed
status=json.loads(run('tools-status',[launcher,'--tools','status']))
assert status['managed'] and status['health']['ok'],status
result['tools']=status
catalog=json.loads((prefix/'current/app/analysis-tools.json').read_text())
for name,spec in catalog['tools'].items():
 path=work/'cache/rehkc/engines'/spec['sha256']
 assert path.stat().st_size==spec['bytes'] and digest(path)==spec['sha256'],name
result['engine_archive_hashes_verified']=True
report=json.loads(run('doctor',[launcher,'--doctor']))
assert not report['missing_x11_libraries'] and report['ghidra_configured'],report
for name in ['radare2','r2','rabin2','retdec-decompiler','java','javac']:
 assert str(prefix/'tools') in report['optional_tools'][name],(name,report['optional_tools'][name])
result['managed_launcher_paths_verified']=True
printed=run('system-deps',['/bin/sh',prefix/'current/install.sh','--print-system-deps'])
assert printed.startswith('sudo '+manager+' '),printed
result['distribution_command_verified']=True
run('installed-check',['/bin/sh',prefix/'current/install.sh','--check'])
active=(prefix/'tools/active.json').read_bytes()
updates=json.loads(run('update-check',[launcher,'--tools','check-updates'],timeout=600))
assert not updates['errors'],updates
assert updates['next_check']-updates['checked_at']==7*86400
assert not updates['approved_update_available'] and not updates['automatically_installed']
assert updates['installed_health']['health']['ok']
assert (prefix/'tools/active.json').read_bytes()==active
result['update_check']=updates
cached=json.loads(run('weekly-cache',[launcher,'--tools','check-updates','--if-due']))
assert cached['skipped'];result['weekly_cache_verified']=True
fixture=work/'probe.elf'
code=bytes.fromhex('488d047f4801f0c3')
header=struct.pack('<16sHHIQQQIHHHHHH',b'\x7fELF\x02\x01\x01'+b'\0'*9,2,62,1,0x400078,64,0,0,64,56,1,64,0,0)
segment=struct.pack('<IIQQQQQQ',1,5,0,0x400000,0x400000,128,128,4096)
fixture.write_bytes(header+segment+code)
code=run('real-rea-ghidra',[launcher,'--engine','decompile',fixture,'0x400078','--provider','ghidra','--format','json'],timeout=300)
assert 'return in_RDI * 3 + in_RSI;' in code,code[-5000:]
result['rea_ghidra_real_analysis']=True
run('gui-startup',[launcher,'--smoke-test','--report',work/'gui.json'],extra_env={'QT_QPA_PLATFORM':'offscreen'},timeout=90)
gui=json.loads((work/'gui.json').read_text());assert gui['ok'] and gui['version']==version,gui
result['gui']=gui
result['ok']=True
save()
print('PUBLISHED_INSTALL_RESULT='+json.dumps(result,ensure_ascii=False,sort_keys=True),flush=True)

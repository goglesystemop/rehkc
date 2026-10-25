"""User-only, versioned installer. Existing REA, configuration, accounts and sessions are retained."""
import argparse,base64,fcntl,hashlib,json,os,pathlib,platform,shlex,shutil,subprocess,sys,tempfile,uuid
SOURCE=pathlib.Path(__file__).resolve().parent
APP_ID='io.github.goglesystemop.rehkc'

def sha(path):
 h=hashlib.sha256()
 with path.open('rb') as f:
  for block in iter(lambda:f.read(1024*1024),b''):h.update(block)
 return h.hexdigest()

def write_atomic(path,data,mode=0o600):
 path.parent.mkdir(parents=True,exist_ok=True)
 tmp=path.with_name('.'+path.name+'-'+uuid.uuid4().hex)
 try:
  fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL,mode)
  with os.fdopen(fd,'wb') as f:f.write(data);f.flush();os.fsync(f.fileno())
  os.replace(tmp,path)
 finally:
  if tmp.exists():tmp.unlink()

def payload_manifest(root):
 d=json.loads((root/'MANIFEST.json').read_text())
 if d.get('application')!='rehkc' or not isinstance(d.get('files'),dict):raise ValueError('Invalid REHKC manifest')
 for name,record in d['files'].items():
  relative=pathlib.PurePosixPath(name)
  if relative.is_absolute() or '..' in relative.parts:raise ValueError('Invalid manifest path')
  p=root/name
  if not p.resolve().is_relative_to(root.resolve()):raise ValueError('Escaping package path: '+name)
  if 'link' in record:
   if not p.is_symlink() or os.readlink(p)!=record['link']:raise ValueError('Symlink mismatch: '+name)
  elif not p.is_file() or sha(p)!=record['sha256']:raise ValueError('Checksum mismatch: '+name)
 return d

def desktop_string(value):
 if any(c in value for c in '\n\r\0'):raise ValueError('Unsupported newline/NUL in installation path')
 return value.replace('\\','\\\\')

def desktop_exec(path):
 s=str(path).replace('%','%%')
 # Exec has its own quoting layer in addition to Desktop Entry escaping.
 s=s.replace('\\','\\\\').replace('"','\\"').replace('`','\\`').replace('$','\\$')
 return desktop_string('"'+s+'"')

def bindings(args,root):
 launcher=args.bin_dir/'rehkc';desktop=args.desktop_dir/(APP_ID+'.desktop')
 command=('#!/bin/sh\nexport REHKC_INSTALL_ROOT='+shlex.quote(str(root))+'\nexec '+shlex.quote(str(root/'current/run'))+' "$@"\n').encode()
 text='\n'.join(['[Desktop Entry]','Type=Application','Name=REHKC','Comment=REA reverse engineering desktop',
  'Exec='+desktop_exec(launcher)+' %f','TryExec='+desktop_string(str(launcher)),
  'Icon='+desktop_string(str(root/'current/app/ai-icon.png')),'Terminal=false','Categories=Development;Utility;',
  'StartupNotify=true','StartupWMClass=REHKC','MimeType=application/x-executable;application/x-sharedlib;application/x-object;application/x-dosexec;',''])
 result={str(launcher):(command,0o755)}
 if not args.no_desktop:result[str(desktop)]=(text.encode(),0o644)
 return result

def system_dependencies():
 # Optional analysis engines are deliberately not installed by this command.
 return ['sudo','apt-get','install','--no-install-recommends','libglib2.0-0','libgl1','libegl1','libxkbcommon-x11-0','libxcb-shape0','libxcb-xinerama0','libxcb-cursor0','libxcb-icccm4','libxcb-image0','libxcb-keysyms1','libxcb-render-util0','libxcb-xkb1','libxrender1','libxi6','libxrandr2','libxfixes3','libfontconfig1','libdbus-1-3','libx11-xcb1','binutils','xdg-utils']

def uninstall(root,receipt):
 kept=[]
 for name,record in receipt['bindings'].items():
  p=pathlib.Path(name)
  if not p.exists():continue
  if p.is_symlink() or sha(p)!=record['installed_sha256']:kept.append(name);continue
  previous=record['previous']
  if previous is None:p.unlink()
  else:write_atomic(p,base64.b64decode(previous['content']),previous['mode'])
 current=root/'current'
 if current.is_symlink() and os.readlink(current)==receipt['current_link']:current.unlink()
 for version,manifest_sha in receipt['releases'].items():
  release=root/'releases'/version
  manifest=release/'MANIFEST.json'
  if not manifest.is_file() or sha(manifest)!=manifest_sha:kept.append(str(release));continue
  d=json.loads(manifest.read_text())
  for name,record in sorted(d['files'].items(),reverse=True):
   p=release/name
   if not p.resolve().is_relative_to(release.resolve()):kept.append(str(p));continue
   if not (p.exists() or p.is_symlink()):continue
   if ('link' in record and p.is_symlink() and os.readlink(p)==record['link']) or ('sha256' in record and p.is_file() and not p.is_symlink() and sha(p)==record['sha256']):p.unlink()
   else:kept.append(str(p))
  if not any(str(p).startswith(str(release)) for p in kept):manifest.unlink()
  for directory in sorted((p for p in release.rglob('*') if p.is_dir() and not p.is_symlink()),key=lambda p:len(p.parts),reverse=True):
   try:directory.rmdir()
   except OSError:pass
  try:release.rmdir()
  except OSError:pass
 receipt['uninstalled']=True;write_atomic(root/'installation.json',json.dumps(receipt,indent=2).encode())
 print(json.dumps({'uninstalled':True,'preserved_modified_files':kept,'user_configuration_and_sessions':'untouched'},indent=2))
 return 0

def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--data-dir',type=pathlib.Path,default=pathlib.Path(os.environ.get('XDG_DATA_HOME',pathlib.Path.home()/'.local/share'))/'rehkc')
 p.add_argument('--bin-dir',type=pathlib.Path,default=pathlib.Path.home()/'.local/bin')
 p.add_argument('--desktop-dir',type=pathlib.Path,default=pathlib.Path(os.environ.get('XDG_DATA_HOME',pathlib.Path.home()/'.local/share'))/'applications')
 p.add_argument('--no-desktop',action='store_true');p.add_argument('--check',action='store_true');p.add_argument('--uninstall',action='store_true')
 p.add_argument('--print-system-deps',action='store_true');p.add_argument('--install-system-deps',action='store_true');p.add_argument('--replace-existing',action='store_true')
 args=p.parse_args()
 if args.print_system_deps:print(shlex.join(system_dependencies()));return 0
 if args.install_system_deps:
  if not shutil.which('apt-get'):raise ValueError('This first release automates system dependencies only for Debian/Ubuntu/Mint. See docs/INSTALL.md.')
  subprocess.run(system_dependencies(),check=True)
 root=args.data_dir.expanduser().resolve();args.bin_dir=args.bin_dir.expanduser().absolute();args.desktop_dir=args.desktop_dir.expanduser().absolute()
 if root in [pathlib.Path('/'),pathlib.Path.home(),pathlib.Path.home()/'.local/share'] or (not (args.uninstall or args.check) and (SOURCE.is_relative_to(root) or root.is_relative_to(SOURCE))):raise ValueError('Installation directory must be separate from source and user home roots')
 receipt_path=root/'installation.json';receipt=None
 if receipt_path.exists():
  receipt=json.loads(receipt_path.read_text())
  if receipt.get('application')!='rehkc':raise ValueError('Foreign installation receipt; nothing replaced')
 if args.uninstall:
  if not receipt:raise ValueError('No REHKC installation receipt at '+str(root))
  return uninstall(root,receipt)
 d=payload_manifest(SOURCE)
 if platform.system()!='Linux' or platform.machine() not in ('x86_64','amd64'):raise ValueError('This release requires x86_64 Linux')
 probe=subprocess.run([str(SOURCE/'run'),'--doctor'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=25)
 if probe.returncode:
  print(probe.stdout+probe.stderr,file=sys.stderr);raise ValueError('Missing desktop dependencies. Run ./install.sh --print-system-deps; optionally --install-system-deps.')
 if args.check:print('Package checksums and desktop dependencies OK');return 0
 if os.geteuid()==0:raise ValueError('Run the application installer as your desktop user, without sudo. --install-system-deps invokes sudo only for required system libraries.')
 new_bindings=bindings(args,root)
 records=receipt['bindings'].copy() if receipt and not receipt.get('uninstalled') else {}
 for name,(content,mode) in new_bindings.items():
  path=pathlib.Path(name)
  if path.is_symlink():raise ValueError('Refusing to replace a launcher/desktop symlink: '+name)
  if path.exists() and (name not in records or sha(path)!=records[name]['installed_sha256']) and not args.replace_existing:raise ValueError('Existing file differs; use --replace-existing to back up and replace: '+name)
  if name not in records:
   records[name]={'previous':{'content':base64.b64encode(path.read_bytes()).decode(),'mode':path.stat().st_mode&0o777} if path.exists() else None}
  records[name]['installed_sha256']=hashlib.sha256(content).hexdigest()
 root.mkdir(parents=True,exist_ok=True,mode=0o700)
 if root.is_symlink():raise ValueError('Refusing symlink installation directory')
 lock=os.open(root/'.install.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
 try:
  fcntl.flock(lock,fcntl.LOCK_EX)
  observed=json.loads(receipt_path.read_text()) if receipt_path.exists() else None
  if observed!=receipt:raise ValueError('Installation changed concurrently; retry with the current receipt')
  version=d['version'];destination=root/'releases'/version;destination.parent.mkdir(exist_ok=True)
  if destination.exists():
   if not (destination/'MANIFEST.json').is_file() or sha(destination/'MANIFEST.json')!=sha(SOURCE/'MANIFEST.json'):raise ValueError('Version directory differs; existing installation retained')
   payload_manifest(destination)
  else:
   stage=destination.with_name('.stage-'+uuid.uuid4().hex)
   try:
    shutil.copytree(SOURCE,stage,symlinks=True,ignore=shutil.ignore_patterns('__pycache__','*.pyc','.git'))
    payload_manifest(stage);os.replace(stage,destination)
   finally:
    if stage.exists():shutil.rmtree(stage)
  current=root/'current'
  if current.exists() and not current.is_symlink():raise ValueError('Foreign current directory retained')
  current_link='releases/'+version;temp=root/('.current-'+uuid.uuid4().hex);temp.symlink_to(current_link);os.replace(temp,current)
  for name,(content,mode) in new_bindings.items():write_atomic(pathlib.Path(name),content,mode)
  releases=receipt.get('releases',{}).copy() if receipt else {};releases[version]=sha(destination/'MANIFEST.json')
  record={'application':'rehkc','version':version,'current_link':current_link,'releases':releases,'bindings':records}
  write_atomic(receipt_path,json.dumps(record,indent=2).encode())
 finally:os.close(lock)
 update=shutil.which('update-desktop-database')
 if update and not args.no_desktop:subprocess.run([update,str(args.desktop_dir)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
 print('Installed REHKC '+version+'\nLaunch: '+str(args.bin_dir/'rehkc')+'\nExisting REA, model files and accounts were not modified.')
 return 0
if __name__=='__main__':
 try:raise SystemExit(main())
 except (ValueError,OSError,subprocess.SubprocessError) as e:print('REHKC installation: '+str(e),file=sys.stderr);raise SystemExit(1)

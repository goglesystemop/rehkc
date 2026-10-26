#!/usr/bin/env python3
"""Build an offline runtime bundle from pinned public inputs and the recorded REA motor."""
import argparse,hashlib,json,os,pathlib,shutil,subprocess,tarfile,urllib.request
ROOT=pathlib.Path(__file__).resolve().parents[1]
def digest(path):
 h=hashlib.sha256()
 with path.open('rb') as f:
  for block in iter(lambda:f.read(1024*1024),b''):h.update(block)
 return h.hexdigest()
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--engine',required=True,type=pathlib.Path);p.add_argument('--stage',required=True,type=pathlib.Path);p.add_argument('--output',required=True,type=pathlib.Path);p.add_argument('--runtime-archive',type=pathlib.Path);p.add_argument('--assets',type=pathlib.Path)
 a=p.parse_args();release=json.loads((ROOT/'packaging/version.json').read_text());version=release['version'];package_name='rehkc-'+version+'-linux-x86_64';spec=json.loads((ROOT/'packaging/doctor-runtime-spec.json').read_text());meta=json.loads((ROOT/'packaging/python-runtime.json').read_text())
 if digest(a.engine)!=spec['binary_sha256']:raise SystemExit('Unexpected REA motor; existing motor was not replaced.')
 a.stage.mkdir(parents=True,exist_ok=True);a.output.mkdir(parents=True,exist_ok=True)
 archive=a.runtime_archive or a.output/meta['name']
 if not archive.exists():urllib.request.urlretrieve(meta['url'],archive)
 if digest(archive)!=meta['digest'].split(':',1)[1]:raise SystemExit('Python runtime checksum mismatch')
 python=a.stage/'runtime/python/bin/python3'
 if not python.exists():
  (a.stage/'runtime').mkdir(exist_ok=True)
  with tarfile.open(archive) as t:t.extractall(a.stage/'runtime',filter='data')
 env={k:v for k,v in os.environ.items() if not k.startswith(('PIP_','PYTHON'))};env.update(PYTHONNOUSERSITE='1',PIP_CONFIG_FILE='/dev/null',PIP_INDEX_URL='https://pypi.org/simple',PIP_DISABLE_PIP_VERSION_CHECK='1')
 subprocess.run([str(python.resolve()),'-m','pip','install','--only-binary=:all:','--require-hashes','-r',str(ROOT/'packaging/requirements.lock')],env=env,check=True)
 app=a.stage/'app';app.mkdir(exist_ok=True)
 for source in (ROOT/'app').iterdir():
  if source.is_file() and (source.suffix=='.py' or source.name in ('rea-engine','ai-icon.png')):shutil.copy2(source,app/source.name)
 shutil.copytree(ROOT/'app/bridge',app/'bridge',dirs_exist_ok=True)
 shutil.copy2(ROOT/'app/analysis-tools.json',app/'analysis-tools.json')
 shutil.copy2(ROOT/'packaging/requirements.lock',app/'python-requirements.lock')
 shutil.copy2(a.engine,app/'rea.bin');(app/'rea.bin').chmod(0o755)
 raw=a.engine.read_bytes();bundle=raw[spec['offset']:spec['offset']+spec['length']]
 if hashlib.sha256(bundle).hexdigest()!=spec['bundle_sha256']:raise SystemExit('Embedded motor bundle mismatch')
 (app/'doctor-runtime/scripts').mkdir(parents=True,exist_ok=True);(app/'doctor-runtime/scripts/entry-binary.mjs').write_bytes(bundle)
 (app/'doctor-runtime/bundle-manifest.json').write_text(json.dumps(spec,indent=2))
 shutil.copy2(ROOT/'licenses/REA-MIT.txt',app/'doctor-runtime/LICENSE-REA')
 for item in spec['companion_files']:
  source=a.assets/item['destination'] if a.assets else None
  if source and source.exists():data=source.read_bytes()
  else:
   url=spec['companion_repository'].replace('https://github.com/','https://raw.githubusercontent.com/')+'/'+spec['companion_commit']+'/'+item['source'];data=urllib.request.urlopen(url,timeout=30).read()
  if hashlib.sha256(data).hexdigest()!=item['sha256']:raise SystemExit('Companion mismatch: '+item['destination'])
  dest=app/item['destination'];dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(data)
 for name in ['run','install.sh','installer.py','README.md','LICENSE','THIRD_PARTY_NOTICES.md']:
  shutil.copy2(ROOT/name,a.stage/name)
 shutil.copytree(ROOT/'docs',a.stage/'docs',dirs_exist_ok=True);shutil.copytree(ROOT/'licenses',a.stage/'licenses',dirs_exist_ok=True)
 (a.stage/'build-info.json').write_text(json.dumps({'application':'rehkc','version':version,'platform':'linux-x86_64','glibc_minimum':'2.28','desktop_verified_scope':release['desktop_verified_scope'],'engine_sha256':spec['binary_sha256'],'engine_version':'6.7.0','python_runtime':meta,'requirements_lock_sha256':digest(ROOT/'packaging/requirements.lock')},indent=2))
 entries={}
 for f in sorted(a.stage.rglob('*')):
  rel=f.relative_to(a.stage).as_posix()
  if '__pycache__' in f.parts or rel=='MANIFEST.json':continue
  if f.name in ('accounts.json','gui_settings.json') or f.name.endswith('.rea.json'):raise SystemExit('Private state in payload: '+rel)
  if f.is_symlink():
   if not f.resolve().is_relative_to(a.stage.resolve()):raise SystemExit('Escaping runtime symlink: '+rel)
   entries[rel]={'link':os.readlink(f)}
  elif f.is_file():entries[rel]={'sha256':digest(f),'mode':f.stat().st_mode&0o777}
 (a.stage/'MANIFEST.json').write_text(json.dumps({'application':'rehkc','version':version,'files':entries},sort_keys=True,indent=2))
 target=a.output/(package_name+'.tar.gz')
 with tarfile.open(target,'w:gz',compresslevel=6) as t:
  for f in sorted(a.stage.rglob('*')):
   if '__pycache__' not in f.parts:t.add(f,arcname=package_name+'/' +f.relative_to(a.stage).as_posix(),recursive=False)
 sha=digest(target);(a.output/'SHA256SUMS').write_text(sha+'  '+target.name+'\n')
 (ROOT/'packaging/release.json').write_text(json.dumps({'version':version,'asset':target.name,'url':'https://github.com/goglesystemop/rehkc/releases/download/v'+version+'/'+target.name,'sha256':sha},indent=2)+'\n')
 print(json.dumps({'archive':str(target),'bytes':target.stat().st_size,'sha256':sha,'files':len(entries)},indent=2))
if __name__=='__main__':main()

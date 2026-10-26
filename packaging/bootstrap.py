#!/usr/bin/env python3
"""Fetch this repository's checksum-pinned release; never execute an unchecked download."""
import hashlib,json,os,pathlib,shutil,subprocess,sys,tarfile,tempfile,urllib.request
ROOT=pathlib.Path(__file__).resolve().parents[1]
def sha(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
 return h.hexdigest()
def main():
 meta=json.loads((ROOT/'packaging/release.json').read_text());cache=pathlib.Path(os.environ.get('XDG_CACHE_HOME',pathlib.Path.home()/'.cache'))/'rehkc';cache.mkdir(parents=True,exist_ok=True,mode=0o700)
 archive=pathlib.Path(os.environ.get('REHKC_ARCHIVE',str(cache/meta['asset'])))
 if not archive.exists():
  print('Downloading REHKC '+meta['version']+'...',flush=True)
  if not meta['url'].startswith('https://github.com/goglesystemop/rehkc/releases/download/'):raise ValueError('Unexpected release origin')
  temporary=archive.with_name(archive.name+'.partial')
  try:
   with urllib.request.urlopen(meta['url'],timeout=60) as response,temporary.open('wb') as output:
    size=0
    while True:
     block=response.read(1024*1024)
     if not block:break
     size+=len(block)
     if size>2*1024**3:raise ValueError('Release exceeds 2 GiB')
     output.write(block)
   if sha(temporary)!=meta['sha256']:raise ValueError('Release checksum mismatch; nothing installed')
   os.replace(temporary,archive)
  finally:
   if temporary.exists():temporary.unlink()
 if sha(archive)!=meta['sha256']:raise ValueError('Release checksum mismatch; nothing installed')
 destination=cache/meta['sha256'];package=destination/meta['asset'].removesuffix('.tar.gz')
 if not package.exists():
  if not hasattr(tarfile,'data_filter'):raise ValueError('This source bootstrap needs an updated Python tarfile data filter. Download the release archive and follow docs/INSTALL.md instead.')
  with tempfile.TemporaryDirectory(prefix='unpack-',dir=cache) as temporary:
   with tarfile.open(archive) as t:t.extractall(temporary,filter='data')
   os.replace(temporary,destination)
 manifest=json.loads((package/'MANIFEST.json').read_text())
 for name,record in manifest['files'].items():
  p=package/name
  if pathlib.PurePosixPath(name).is_absolute() or '..' in pathlib.PurePosixPath(name).parts or not p.resolve().is_relative_to(package.resolve()):raise ValueError('Invalid package path')
  if 'link' in record:
   if not p.is_symlink() or os.readlink(p)!=record['link']:raise ValueError('Invalid runtime symlink')
  elif not p.is_file() or sha(p)!=record['sha256']:raise ValueError('Corrupt cached file: '+name)
 os.execv('/bin/sh',['sh',str(package/'install.sh'),*sys.argv[1:]])
if __name__=='__main__':
 try:main()
 except Exception as e:print('REHKC bootstrap: '+str(e),file=sys.stderr);raise SystemExit(1)

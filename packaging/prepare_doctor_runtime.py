#!/usr/bin/python3
"""Reproduce diagnostic support from this exact shipped binary and pinned companion files.
Never replace a motor or an agent's active skills. --output is an application data directory.
"""
import argparse,hashlib,json,pathlib,urllib.request
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--binary',required=True,type=pathlib.Path)
parser.add_argument('--output',required=True,type=pathlib.Path)
args=parser.parse_args()
spec=json.loads(pathlib.Path(__file__).with_name('doctor-runtime-spec.json').read_text())
raw=args.binary.read_bytes()
if hashlib.sha256(raw).hexdigest()!=spec['binary_sha256']:
 raise SystemExit('This support package requires the recorded REA 6.7.0 binary; motor was not changed.')
bundle=raw[spec['offset']:spec['offset']+spec['length']]
if hashlib.sha256(bundle).hexdigest()!=spec['bundle_sha256']:
 raise SystemExit('Embedded bundle integrity mismatch.')
assets={'doctor-runtime/scripts/entry-binary.mjs':bundle}
for item in spec['companion_files']:
 url=spec['companion_repository'].replace('https://github.com/','https://raw.githubusercontent.com/')+'/'+spec['companion_commit']+'/'+item['source']
 data=urllib.request.urlopen(url,timeout=30).read()
 if hashlib.sha256(data).hexdigest()!=item['sha256'] or hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()!=item['git_blob']:
  raise SystemExit('Pinned companion integrity mismatch: '+item['source'])
 assets[item['destination']]=data
assets['doctor-runtime/bundle-manifest.json']=json.dumps(spec,indent=2).encode()
# Validate the complete plan before writing any support file.
for name,data in assets.items():
 target=args.output/name
 if target.exists() and target.read_bytes()!=data:raise SystemExit('Existing support file differs; back it up first: '+str(target))
for name,data in assets.items():
 target=args.output/name;target.parent.mkdir(parents=True,exist_ok=True)
 if not target.exists():target.write_bytes(data)
print('Diagnostic assets prepared; motor, app config and active agent skills unchanged.')

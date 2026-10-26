"""User-scoped analysis engines, atomic activation and weekly release diagnostics.

Only a reviewed, hash-pinned catalog can be installed. Upstream release discovery
never executes downloads or guesses dependency compatibility.
"""
from contextlib import contextmanager
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import struct
import sys
import tarfile
import tempfile
import time
import urllib.parse
import urllib.request
import uuid
import zipfile

APP = Path(__file__).resolve().parent
CATALOG = APP/'analysis-tools.json'
CATALOG_URL = 'https://raw.githubusercontent.com/goglesystemop/rehkc/main/app/analysis-tools.json'
REPOSITORIES = {'ghidra':'NationalSecurityAgency/ghidra', 'retdec':'avast/retdec',
                'radare2':'radareorg/radare2', 'jdk':'adoptium/temurin21-binaries'}
WEEK = 7 * 86400
RETRY = 86400


def tools_dir():
    if os.environ.get('REHKC_TOOLS_DIR'):
        return Path(os.environ['REHKC_TOOLS_DIR']).expanduser().resolve()
    prefix = os.environ.get('REHKC_INSTALL_ROOT')
    if not prefix:
        prefix = Path(os.environ.get('XDG_DATA_HOME', Path.home()/'.local/share'))/'rehkc'
    return Path(prefix).resolve()/'tools'


def atomic_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_name('.'+path.name+'-'+uuid.uuid4().hex)
    try:
        with temporary.open('x', encoding='utf-8') as output:
            os.chmod(temporary, 0o600)
            json.dump(data, output, indent=2, ensure_ascii=False)
            output.write('\n'); output.flush(); os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as source:
        for block in iter(lambda: source.read(1024*1024), b''):
            h.update(block)
    return h.hexdigest()


def catalog_id(catalog):
    return hashlib.sha256(json.dumps(catalog, sort_keys=True).encode()).hexdigest()


def version(value):
    match = re.search(r'\d+(?:\.\d+)*', value)
    if not match:
        raise ValueError('Version cannot be parsed: '+value)
    return tuple(map(int, match.group().split('.')))


def safe_relative(value):
    p = Path(value)
    if p.is_absolute() or '..' in p.parts or '\\' in value or '\0' in value:
        raise ValueError('Unsafe archive/catalog path: '+value)
    return p


def validate_catalog(catalog):
    if catalog.get('schema') != 1 or catalog.get('platform') != 'linux-x86_64' or not isinstance(catalog.get('revision'), int):
        raise ValueError('Unsupported analysis catalog schema/platform')
    if set(catalog.get('tools', {})) != set(REPOSITORIES):
        raise ValueError('Incomplete analysis engine set')
    for name, spec in catalog['tools'].items():
        expected = REPOSITORIES[name]
        # A new JDK major needs a deliberate compatibility/catalog code update.
        if spec['repo'] != expected:
            raise ValueError('Unexpected upstream repository: '+name)
        url = urllib.parse.urlsplit(spec['url'])
        if url.scheme != 'https' or url.netloc != 'github.com' or not url.path.startswith('/'+expected+'/releases/download/') or url.query or url.fragment:
            raise ValueError('Unexpected upstream download: '+name)
        if not re.fullmatch('[0-9a-f]{64}', spec['sha256']) or not 0 < spec['bytes'] < 2*1024**3:
            raise ValueError('Invalid pinned checksum/size: '+name)
        if spec['format'] not in ('zip', 'tar', 'deb'):
            raise ValueError('Unsupported archive format')
        safe_relative(spec['root'])
        if not re.fullmatch(r'[A-Za-z0-9_.+/ -]*', spec['root']):
            raise ValueError('Unsupported engine root directory')
        version(spec['version'])
    compatibility = catalog['compatibility']
    if not catalog['tools']['ghidra']['version'].startswith('12.1.'):
        raise ValueError('Bundled REA 6.7.0 supports only the Ghidra 12.1.x line')
    jdk = version(catalog['tools']['jdk']['version'])[0]
    if not compatibility['ghidra_java_minimum'] <= jdk < compatibility['ghidra_java_maximum_exclusive']:
        raise ValueError('Catalog JDK does not satisfy Ghidra requirements')
    for key in ('python_minimum', 'python_maximum_exclusive', 'glibc_minimum'):
        version(catalog[key])
    return catalog


def load_catalog(path=CATALOG):
    return validate_catalog(json.loads(path.read_text()))


def request(url):
    return urllib.request.urlopen(urllib.request.Request(url, headers={
        'User-Agent':'REHKC-analysis-manager', 'Accept':'application/vnd.github+json'}), timeout=20)


def fetch_json(url):
    with request(url) as response:
        data = response.read(4*1024**2+1)
    if len(data) > 4*1024**2:
        raise ValueError('Metadata response too large')
    return json.loads(data)


def download(spec, cache):
    cache.mkdir(parents=True, exist_ok=True, mode=0o700)
    destination = cache/spec['sha256']
    if destination.is_file() and destination.stat().st_size == spec['bytes'] and digest(destination) == spec['sha256']:
        return destination
    fd, name = tempfile.mkstemp(prefix='.download-', dir=cache)
    temporary = Path(name)
    try:
        with os.fdopen(fd, 'wb') as output, request(spec['url']) as response:
            size = 0
            while block := response.read(1024*1024):
                size += len(block)
                if size > spec['bytes']:
                    raise ValueError('Download exceeds pinned size')
                output.write(block)
        if temporary.stat().st_size != spec['bytes'] or digest(temporary) != spec['sha256']:
            raise ValueError('Engine download checksum/size mismatch')
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)
    return destination


def unpack_tar(source, destination):
    # Python3.12's data filter refuses escaping links, devices and ownership bits.
    with tarfile.open(fileobj=source, mode='r:*') as archive:
        members = archive.getmembers()
        if sum(m.size for m in members) > 8*1024**3:
            raise ValueError('Expanded engine archive too large')
        archive.extractall(destination, members=members, filter='data')


def unpack(archive, spec, destination):
    destination.mkdir(parents=True)
    if spec['format'] == 'zip':
        with zipfile.ZipFile(archive) as zipped:
            if sum(info.file_size for info in zipped.infolist()) > 8*1024**3:
                raise ValueError('Expanded engine archive too large')
            for info in zipped.infolist():
                relative = safe_relative(info.filename)
                mode = info.external_attr >> 16
                if mode & 0o170000 == 0o120000:
                    raise ValueError('Zip symlinks are unsupported')
                target = destination/relative
                zipped.extract(info, destination)
                if target.is_file():
                    target.chmod(0o755 if mode & 0o111 else 0o644)
    elif spec['format'] == 'tar':
        with archive.open('rb') as source:
            unpack_tar(source, destination)
    else:
        # Read the ar envelope directly: no dpkg, apt, root or maintainer scripts.
        with archive.open('rb') as source:
            if source.read(8) != b'!<arch>\n':
                raise ValueError('Invalid Debian archive')
            while header := source.read(60):
                if len(header) != 60 or header[58:] != b'`\n':
                    raise ValueError('Invalid Debian member')
                length = int(header[48:58])
                name = header[:16].decode().strip().rstrip('/')
                if length < 0 or length > spec['bytes']:
                    raise ValueError('Invalid Debian member length')
                if name.startswith('data.tar'):
                    unpack_tar(io.BytesIO(source.read(length)), destination)
                    return
                source.seek(length + length % 2, 1)
        raise ValueError('Debian archive lacks data payload')


def layout(root, catalog):
    return {name:root/name/spec['root'] for name, spec in catalog['tools'].items()}


def read_active(root=None):
    root = root or tools_dir()
    path = root/'active.json'
    if not path.exists():
        return None
    record = json.loads(path.read_text())
    catalog = validate_catalog(record['catalog'])
    identity = catalog_id(catalog)
    if record['release'] != identity:
        raise ValueError('Managed engine receipt does not match catalog')
    release = root/'releases'/identity
    if not release.resolve().is_relative_to((root/'releases').resolve()):
        raise ValueError('Managed engine release escapes installation')
    return release, catalog


def apply_environment(root=None, environ=None):
    env = os.environ if environ is None else environ
    active = read_active(root)
    if not active:
        return False
    release, catalog = active
    locations = layout(release, catalog)
    env.setdefault('GHIDRA_INSTALL_DIR', str(locations['ghidra']))
    env.setdefault('JAVA_HOME', str(locations['jdk']))
    env.setdefault('RETDEC_INSTALL_DIR', str(locations['retdec']))
    env['PATH'] = str(release/'bin')+os.pathsep+env.get('PATH', '/usr/bin:/bin')
    return True


def wrappers(release, catalog, python):
    binary = release/'bin'
    binary.mkdir()
    # Resolve relative to the script so staging -> final rename remains valid.
    for command in ('radare2', 'r2', 'rabin2'):
        prefix = '../radare2/'+catalog['tools']['radare2']['root']
        text = ('#!/bin/sh\nset -eu\nbase=$(CDPATH= cd -- "$(dirname -- "$0")/'+prefix+'" && pwd)\n'
                'export R2_PREFIX="$base"\nexport LD_LIBRARY_PATH="$base/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"\n'
                'exec "$base/bin/'+command+'" "$@"\n')
        (binary/command).write_text(text); (binary/command).chmod(0o755)
    # Native RetDec uses sibling share/lib resources. Its ancillary Python
    # scripts must resolve REHKC's bundled interpreter, never system pip.
    (binary/'python3').symlink_to(python.resolve())


def properties(path):
    return dict(line.split('=', 1) for line in path.read_text().splitlines()
                if '=' in line and not line.startswith('#'))


def run(command, env, timeout=30):
    process = subprocess.run(list(map(str, command)), env=env, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, text=True, timeout=timeout)
    if process.returncode:
        raise ValueError('Engine validation failed: '+str(command[0])+'\n'+process.stdout[-3000:])
    return process.stdout


def host_compatibility(catalog):
    if platform.system() != 'Linux' or platform.machine() not in ('x86_64', 'amd64'):
        raise ValueError('Managed engines require x86_64 Linux')
    libc, observed = platform.libc_ver()
    if libc != 'glibc' or version(observed) < version(catalog['glibc_minimum']):
        raise ValueError('Managed engines require glibc >= '+catalog['glibc_minimum']+
                         '; application-only install: --without-tools')
    if not version(catalog['python_minimum']) <= sys.version_info[:2] < version(catalog['python_maximum_exclusive']):
        raise ValueError('Engine set requires bundled Python '+catalog['python_minimum']+' <= version < '+catalog['python_maximum_exclusive'])
    compat = catalog['compatibility']
    if not version(compat['ghidra_python_minimum']) <= sys.version_info[:2] < version(compat['ghidra_python_maximum_exclusive']):
        raise ValueError('Bundled Python is outside the catalog Ghidra Python range')


def health(release, catalog):
    host_compatibility(catalog)
    loc = layout(release, catalog)
    env = {k:v for k,v in os.environ.items() if k not in ('JAVA_HOME', 'GHIDRA_INSTALL_DIR', 'RETDEC_INSTALL_DIR', 'LD_LIBRARY_PATH', 'R2_PREFIX')}
    env.update(JAVA_HOME=str(loc['jdk']), GHIDRA_INSTALL_DIR=str(loc['ghidra']),
               RETDEC_INSTALL_DIR=str(loc['retdec']), PATH=str(release/'bin')+os.pathsep+str(loc['jdk']/'bin')+':/usr/bin:/bin')
    props = properties(loc['ghidra']/'Ghidra/application.properties')
    java = run([loc['jdk']/'bin/java', '-version'], env)
    javac = run([loc['jdk']/'bin/javac', '-version'], env)
    major = version(javac)[0]
    compat = catalog['compatibility']
    if props['application.version'] != catalog['tools']['ghidra']['version']:
        raise ValueError('Unexpected installed Ghidra version')
    if major < int(props['application.java.min']) or (props.get('application.java.max') and major > int(props['application.java.max'])):
        raise ValueError('JDK does not satisfy extracted Ghidra requirements')
    if not compat['ghidra_java_minimum'] <= major < compat['ghidra_java_maximum_exclusive']:
        raise ValueError('JDK is outside tested Ghidra range')
    r2 = run([release/'bin/radare2', '-v'], env)
    rabin = run([release/'bin/rabin2', '-v'], env)
    retdec = run([loc['retdec']/'bin/retdec-decompiler', '--version'], env)
    if catalog['tools']['radare2']['version'] not in r2 or catalog['tools']['retdec']['version'] not in retdec:
        raise ValueError('Installed engine version differs from catalog')
    # Check all ELF dependencies of the key tools, including Java GUI and the
    # Ghidra native decompiler, before activation on this particular host.
    missing = []
    libraries = [loc['jdk']/'lib/libawt_xawt.so', loc['jdk']/'lib/server/libjvm.so',
                 loc['retdec']/'bin/retdec-decompiler',
                 loc['ghidra']/'Ghidra/Features/Decompiler/os/linux_x86_64/decompile']
    if not shutil.which('ldd'):
        raise ValueError('ldd is required to validate native engine libraries')
    for library in libraries:
        library_env = dict(env)
        if library.is_relative_to(loc['jdk']):
            # The JVM loads AWT with its private lib/server directory. ldd
            # outside that loader context otherwise reports a false libjvm miss.
            library_env['LD_LIBRARY_PATH'] = str(loc['jdk']/'lib')+':'+str(loc['jdk']/'lib/server')
        output = subprocess.run(['ldd', str(library)], env=library_env, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True, timeout=20)
        missing.extend(line.strip() for line in output.stdout.splitlines() if 'not found' in line)
        if output.returncode:
            raise ValueError('Native dependency check failed: '+str(library)+'\n'+output.stdout[-1500:])
    if missing:
        raise ValueError('Missing engine system libraries: '+'; '.join(sorted(set(missing))))
    return {'ok':True, 'python':platform.python_version(), 'glibc':platform.libc_ver(),
            'ghidra':props['application.version'], 'java':java.splitlines()[0],
            'javac':javac.strip(), 'radare2':r2.splitlines()[0], 'rabin2':rabin.splitlines()[0],
            'retdec':retdec.splitlines()[0], 'missing_libraries':missing}


def analysis_smoke(release, catalog):
    """Analyze a generated inert ELF; never execute the target program."""
    loc = layout(release, catalog)
    env = dict(os.environ, JAVA_HOME=str(loc['jdk']), GHIDRA_INSTALL_DIR=str(loc['ghidra']),
               RETDEC_INSTALL_DIR=str(loc['retdec']),
               PATH=str(release/'bin')+':'+str(loc['jdk']/'bin')+':/usr/bin:/bin')
    env.pop('LD_LIBRARY_PATH', None)
    with tempfile.TemporaryDirectory(prefix='rehkc-engine-probe-') as temporary:
        directory = Path(temporary)
        env['XDG_CONFIG_HOME'] = str(directory/'config')
        env['XDG_CACHE_HOME'] = str(directory/'cache')
        env.pop('JDK_JAVA_OPTIONS', None)
        env.pop('_JAVA_OPTIONS', None)
        env['JAVA_TOOL_OPTIONS'] = '-Duser.home='+str(directory)
        target = directory/'probe.elf'
        # ELF64 load segment containing `return 3*a+b` at its entry point.
        code = bytes.fromhex('488d047f4801f0c3')
        ident = b'\x7fELF\x02\x01\x01'+b'\0'*9
        header = struct.pack('<16sHHIQQQIHHHHHH', ident, 2, 62, 1, 0x400078,
                             64, 0, 0, 64, 56, 1, 64, 0, 0)
        segment = struct.pack('<IIQQQQQQ', 1, 5, 0, 0x400000, 0x400000, 120+len(code), 120+len(code), 4096)
        target.write_bytes(header+segment+code)
        r2 = run([release/'bin/radare2', '-q', '-c', 'aaa;afl', target], env)
        if '0x00400078' not in r2:
            raise ValueError('Radare2 could not analyze the probe entry point')
        output = directory/'probe.c'
        run([loc['retdec']/'bin/retdec-decompiler', '-o', output, target], env, timeout=120)
        if not output.is_file() or 'return' not in output.read_text():
            raise ValueError('RetDec did not produce probe decompilation')
        script = directory/'RehkcInstallProbe.java'
        script.write_text('import ghidra.app.script.GhidraScript;\n'
            'import ghidra.app.decompiler.DecompInterface;\n'
            'public class RehkcInstallProbe extends GhidraScript {\n'
            ' public void run() throws Exception {\n'
            '  DecompInterface d = new DecompInterface();\n'
            '  try { d.openProgram(currentProgram);\n'
            '   var f = currentProgram.getFunctionManager().getFunctions(true);\n'
            '   if (!f.hasNext()) throw new Exception("No probe function");\n'
            '   var r = d.decompileFunction(f.next(), 30, monitor);\n'
            '   if (!r.decompileCompleted()) throw new Exception(r.getErrorMessage());\n'
            '   println("REHKC_PROBE_OK");\n'
            '  } finally { d.dispose(); }\n'
            ' }\n}\n')
        text = run([loc['ghidra']/'support/analyzeHeadless', directory, 'ProbeProject',
                    '-import', target, '-scriptPath', directory, '-postScript', script.name,
                    '-analysisTimeoutPerFile', '30', '-deleteProject'], env, timeout=180)
        if 'REHKC_PROBE_OK' not in text:
            raise ValueError('Ghidra Java script/decompiler probe failed:\n'+text[-3000:])
        checks = {'radare2':True, 'retdec':True, 'ghidra_java_script_and_decompiler':True}
        if (APP/'rea.bin').is_file():
            # Provider gating and bridge contracts belong to REA, so a
            # standalone Ghidra success is insufficient for activation.
            env['REA_DIAGNOSTIC_ROOT'] = str(APP)
            text = run([APP/'rea-engine', 'decompile', target, '0x400078',
                        '--provider', 'ghidra', '--format', 'json'], env, timeout=240)
            if 'return' not in text:
                raise ValueError('REA/Ghidra integration probe failed:\n'+text[-3000:])
            checks['rea_ghidra_bridge'] = True
        return checks


@contextmanager
def lock(root, name, blocking=True):
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    with (root/name).open('a') as handle:
        fcntl.flock(handle, fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB))
        yield


def install(root=None, catalog=None, cache=None, python=None, progress=print):
    root = root or tools_dir()
    catalog = validate_catalog(catalog or load_catalog())
    host_compatibility(catalog)
    identity = catalog_id(catalog)
    cache = cache or Path(os.environ.get('XDG_CACHE_HOME', Path.home()/'.cache'))/'rehkc/engines'
    python = python or Path(sys.executable)
    with lock(root, '.install.lock'):
        destination = root/'releases'/identity
        if destination.exists():
            report = health(destination, catalog)
        else:
            destination.parent.mkdir(exist_ok=True)
            if shutil.disk_usage(root).free < 5*1024**3:
                raise ValueError('At least 5 GiB free space is required for analysis engine installation')
            stage = Path(tempfile.mkdtemp(prefix='.stage-', dir=destination.parent))
            try:
                for name, spec in catalog['tools'].items():
                    progress('Installing '+name+' '+spec['version']+' (verified upstream archive)...', flush=True)
                    archive = download(spec, cache)
                    unpack(archive, spec, stage/name)
                wrappers(stage, catalog, python)
                report = health(stage, catalog)
                report['analysis_probe'] = analysis_smoke(stage, catalog)
                atomic_json(stage/'catalog.json', catalog)
                os.replace(stage, destination)
            finally:
                if stage.exists():
                    shutil.rmtree(stage)
        # No process ever sees a half-installed set. Old sets remain usable by
        # already running analyses and can be explicitly selected for rollback.
        previous = json.loads((root/'active.json').read_text()) if (root/'active.json').exists() else None
        if previous and previous['release'] != identity:
            atomic_json(root/'previous.json', previous)
        atomic_json(root/'active.json', {'schema':1, 'release':identity, 'catalog':catalog})
        return report


def rollback(root=None):
    root = root or tools_dir()
    with lock(root, '.install.lock'):
        previous = json.loads((root/'previous.json').read_text())
        catalog = validate_catalog(previous['catalog'])
        identity = catalog_id(catalog)
        if previous['release'] != identity:
            raise ValueError('Invalid rollback receipt')
        report = health(root/'releases'/identity, catalog)
        current = json.loads((root/'active.json').read_text())
        atomic_json(root/'active.json', previous)
        atomic_json(root/'previous.json', current)
        return report


def status(root=None):
    active = read_active(root)
    if not active:
        return {'managed':False, 'message':'No managed engines installed; external discovery remains available.'}
    release, catalog = active
    return {'managed':True, 'release':release.name, 'versions':{
        name:spec['version'] for name,spec in catalog['tools'].items()},
        'requirements':catalog['compatibility'], 'health':health(release, catalog)}


def check_updates(root=None, if_due=False):
    root = root or tools_dir()
    try:
        with lock(root, '.updates.lock', blocking=False):
            path = root/'updates.json'
            previous = json.loads(path.read_text()) if path.exists() else {}
            now = time.time()
            if if_due and now < previous.get('next_check', 0):
                return dict(previous, skipped=True)
            active = read_active(root)
            catalog = active[1] if active else load_catalog()
            result = {'checked_at':now, 'next_check':now+WEEK, 'interval_days':7,
                      'updates':[], 'errors':[], 'automatically_installed':False}
            def fetch(label, url):
                try:
                    return fetch_json(url)
                except (OSError, ValueError) as exc:
                    result['errors'].append(label+': '+str(exc)); return None
            for name, spec in catalog['tools'].items():
                release = fetch(name, 'https://api.github.com/repos/'+spec['repo']+'/releases/latest')
                if not release or release.get('draft') or release.get('prerelease'):
                    continue
                tag = release['tag_name']
                if tag == spec['tag'] or version(tag) < version(spec['version']):
                    continue
                item = {'component':name, 'installed':spec['version'], 'latest_tag':tag,
                        'url':release['html_url'], 'compatibility':'requires_review',
                        'note':'Yeni sürümün bağımlılıkları ve REHKC entegrasyonu doğrulanmadan kurulmaz.'}
                if name == 'ghidra' and re.fullmatch(r'Ghidra_[0-9._]+_build', tag):
                    if not tag.startswith('Ghidra_12.1.'):
                        item['compatibility'] = 'unsupported_by_bundled_rea'
                        item['note'] = 'REA 6.7.0 yalnız Ghidra 12.1.x destekler; önce REA entegrasyon güncellemesi gerekir.'
                    url = 'https://raw.githubusercontent.com/NationalSecurityAgency/ghidra/'+tag+'/Ghidra/application.properties'
                    try:
                        with request(url) as response:
                            text = response.read(65537).decode()
                        props = dict(line.split('=',1) for line in text.splitlines() if '=' in line and not line.startswith('#'))
                        item['java_minimum'] = props.get('application.java.min', 'unknown')
                        item['java_maximum'] = props.get('application.java.max', '')
                        item['requirements_url'] = 'https://github.com/NationalSecurityAgency/ghidra/blob/'+tag+'/GhidraDocs/GettingStarted.md'
                    except (OSError, ValueError) as exc:
                        item['requirements_error'] = str(exc)
                result['updates'].append(item)
            # Python is coupled to this application's Qt/wheel lock. Check the
            # maintained minor line, not the unrelated newest Python major.
            tags = fetch('Python', 'https://api.github.com/repos/python/cpython/git/matching-refs/tags/v'+str(sys.version_info.major)+'.'+str(sys.version_info.minor)+'.')
            if tags is not None:
                stable = [tag['ref'].split('/')[-1][1:] for tag in tags
                          if re.fullmatch(r'refs/tags/v\d+\.\d+\.\d+', tag['ref'])]
                latest = max(stable, key=version) if stable else platform.python_version()
                if version(latest) > sys.version_info[:3]:
                    result['updates'].append({'component':'Python', 'installed':platform.python_version(),
                        'latest_tag':latest, 'compatibility':'requires_rehkc_release',
                        'url':'https://www.python.org/downloads/release/python-'+latest.replace('.','')+'/'})
            # Monitor the actual installed Python dependency set with declared
            # Requires-Python metadata, without touching system Python/pip.
            import importlib.metadata
            requirements = APP/'python-requirements.lock'
            if not requirements.exists():
                requirements = APP.parent/'packaging/requirements.lock'
            for line in requirements.read_text().splitlines():
                if '==' not in line:
                    continue
                name, pinned = line.split()[0].split('==')
                try:
                    observed = importlib.metadata.version(name)
                except importlib.metadata.PackageNotFoundError:
                    result['errors'].append(name+': installed package missing'); continue
                package = fetch(name, 'https://pypi.org/pypi/'+urllib.parse.quote(name)+'/json')
                if package and package['info']['version'] != observed:
                    result['updates'].append({'component':name, 'installed':observed,
                        'latest_tag':package['info']['version'], 'requires_python':package['info'].get('requires_python'),
                        'compatibility':'requires_rehkc_release', 'url':'https://pypi.org/project/'+name+'/'})
            approved = fetch('REHKC engine catalog', CATALOG_URL)
            if approved is not None:
                try:
                    validate_catalog(approved)
                    result['approved_update_available'] = approved['revision'] > catalog['revision']
                    result['approved_versions'] = {name:s['version'] for name,s in approved['tools'].items()}
                except (KeyError, TypeError, ValueError) as exc:
                    result['errors'].append('REHKC catalog: '+str(exc))
            try:
                result['installed_health'] = status(root)
            except (OSError, ValueError, subprocess.SubprocessError) as exc:
                result['errors'].append('Installed engines: '+str(exc))
            if result['errors']:
                result['next_check'] = now+RETRY
            atomic_json(path, result)
            return result
    except BlockingIOError:
        return {'skipped':True, 'reason':'Another update check is running'}


def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['install','status','check-updates','update','rollback'])
    parser.add_argument('--if-due', action='store_true')
    args = parser.parse_args(argv)
    if args.action == 'check-updates':
        result = check_updates(if_due=args.if_due)
    elif args.action == 'status':
        result = status()
    elif args.action == 'rollback':
        result = rollback()
    else:
        catalog = validate_catalog(fetch_json(CATALOG_URL)) if args.action == 'update' else load_catalog()
        active = read_active()
        if args.action == 'update' and active and catalog['revision'] < active[1]['revision']:
            raise ValueError('Remote catalog is older than installed engines; use rollback explicitly')
        result = install(catalog=catalog, progress=lambda *args, **kw:print(*args, file=sys.stderr, **kw))
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 1 if result.get('errors') else 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, subprocess.SubprocessError, tarfile.TarError, zipfile.BadZipFile) as exc:
        print('REHKC analysis tools: '+str(exc), file=sys.stderr)
        raise SystemExit(1)

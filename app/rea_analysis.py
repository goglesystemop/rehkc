"""Bounded static preflight, result cache and independent native engine adapters.

Targets are data: never executed, unpacked in place, or interpolated into shell text.
"""
from collections import Counter
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import time

from rehkc_paths import data_dir

REVISION = 1
MAX_TARGET = 512 * 1024 * 1024
MAX_RESULT = 8 * 1024 * 1024


class NativeTimeout(TimeoutError):
    def __init__(self, operation, limit, elapsed):
        self.operation,self.limit,self.elapsed=operation,limit,elapsed
        super().__init__(f'{operation}: native araç çağrısı zaman sınırı doldu (sınır {limit:g} sn, geçen {elapsed:.1f} sn).')

    def details(self):
        return {'operation':self.operation,'scope':'native araç çağrısı',
                'limit_seconds':self.limit,'elapsed_seconds':round(self.elapsed,3)}


def signature(path):
    s = Path(path).stat()
    import stat
    if not stat.S_ISREG(s.st_mode) or s.st_size > MAX_TARGET:
        raise ValueError('Statik analiz için en fazla 512 MiB normal dosya seçin.')
    return (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)


def digest_file(path, check=lambda: None, progress=None):
    digest = hashlib.sha256()
    started=time.monotonic();last=started-1;read=0;total=os.stat(path).st_size
    with open(path, 'rb') as stream:
        while True:
            check()
            block = stream.read(1024 * 1024)
            if not block:break
            digest.update(block);read+=len(block);now=time.monotonic()
            if progress and now-last>=1:
                try:progress({'operation':'Dosya SHA256 kontrolü','elapsed':round(now-started,2),
                          'bytes_read':read,'total_bytes':total,'status':'running','last_activity_seconds':0})
                except Exception:pass
                last=now
    if progress:
        try:progress({'operation':'Dosya SHA256 kontrolü','elapsed':round(time.monotonic()-started,2),
                          'bytes_read':read,'total_bytes':total,'status':'completed','last_activity_seconds':0})
        except Exception:pass
    return digest.hexdigest()


def memory_policy():
    """Respect available memory and cgroup limits; preserve explicit JVM overrides."""
    available = 2 * 1024**3
    try:
        fields = dict(line.split(':', 1) for line in Path('/proc/meminfo').read_text().splitlines())
        available = int(fields['MemAvailable'].split()[0]) * 1024
        limit = Path('/sys/fs/cgroup/memory.max').read_text().strip()
        if limit != 'max':
            used = int(Path('/sys/fs/cgroup/memory.current').read_text())
            available = min(available, max(0, int(limit)-used))
    except (OSError, ValueError, KeyError):pass
    heap_mib = max(256, min(4096, available // (3 * 1024**2)))
    return {'available_bytes':available, 'ghidra_heap':str(heap_mib)+'M',
            'native_memory_bytes':max(256 * 1024**2, min(4 * 1024**3, available//2))}


def engine_identity(binary=None, check=lambda:None):
    """Cache namespace covers engine artifacts, bridge revision and analysis settings."""
    h = hashlib.sha256(str(REVISION).encode())
    paths = [Path(__file__), Path(__file__).with_name('rea_mcp.py'), Path(__file__).with_name('rea_native_guard.py'),
             Path(__file__).with_name('analysis-tools.json')]
    if binary:
        p = Path(binary).resolve();paths += [p, p.parent/'rea.bin',
            p.parent/'bridge/ghidra/ReaGhidraBridge.java',p.parent/'bridge/ghidra/ReaGhidraNoReturnFix.java']
    for key in ('GHIDRA_INSTALL_DIR', 'RETDEC_INSTALL_DIR', 'JAVA_HOME'):
        root = os.environ.get(key)
        if root:
            p = Path(root)
            paths += [p/'Ghidra/application.properties', p/'release',p/'bin/java',
                      p/'Ghidra/Framework/Utility/lib/Utility.jar']
    for name in ('radare2', 'rabin2', 'retdec-decompiler'):
        p = shutil.which(name)
        if p:paths.append(Path(p).resolve())
    for p in paths:
        check()
        h.update(str(p).encode())
        if p.is_file():h.update(digest_file(p,check).encode())
    for k,v in sorted(os.environ.items()):
        if k.startswith(('REA_GHIDRA_', 'GHIDRA_', 'JAVA_')):
            h.update((k+'='+v).encode())
    return h.hexdigest()


class ResultCache:
    """Successful observations only; corruption is a miss, never an executable input."""
    def __init__(self, digest, identity, root=None, target='', read_enabled=True):
        target=str(Path(target).absolute()) if target else ''
        self.digest, self.identity = digest, identity+'|'+target
        self.target_id=hashlib.sha256(target.encode()).hexdigest()
        self.read_enabled=read_enabled
        self.root = Path(root) if root is not None else data_dir()/'analysis-cache'

    def path(self, operation, arguments):
        key = json.dumps([REVISION, self.digest, self.identity, operation, arguments], sort_keys=True)
        return self.root/(self.target_id+'-'+hashlib.sha256(key.encode()).hexdigest()+'.json')

    @staticmethod
    def clear_target(target, root=None):
        directory=Path(root) if root is not None else data_dir()/'analysis-cache'
        prefix=hashlib.sha256(str(Path(target).absolute()).encode()).hexdigest()
        count=0
        for path in directory.glob(prefix+'-*.json'):
            try:path.unlink();count+=1
            except OSError:pass
        return count

    def get(self, operation, arguments):
        if not self.read_enabled or os.environ.get('REHKC_DISABLE_ANALYSIS_CACHE') == '1':return None
        p = self.path(operation, arguments)
        try:
            if p.is_symlink() or p.stat().st_size > MAX_RESULT or time.time()-p.stat().st_mtime > 30*86400:return None
            envelope = json.loads(p.read_text())
            raw = json.dumps(envelope['result'], sort_keys=True, ensure_ascii=False)
            if hashlib.sha256(raw.encode()).hexdigest() != envelope['sha256']:return None
            result = envelope['result']
            if not isinstance(result, dict):return None
            value=result.get('structuredContent')
            if isinstance(value,dict) and value.get('fallback_from') and time.time()-p.stat().st_mtime>300:
                return None  # Retry the primary after a transient fallback, rather than pinning it for 30 days.
            return result
        except (OSError, ValueError, KeyError, TypeError):return None

    def put(self, operation, arguments, result):
        if os.environ.get('REHKC_DISABLE_ANALYSIS_CACHE') == '1':return
        raw = json.dumps(result, sort_keys=True, ensure_ascii=False)
        envelope = json.dumps({'result':result, 'sha256':hashlib.sha256(raw.encode()).hexdigest()}, ensure_ascii=False)
        if len(envelope.encode()) > MAX_RESULT:return
        temporary=None
        try:
            self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
            entries = sorted((p for p in self.root.glob('*.json') if not p.is_symlink()), key=lambda p:p.stat().st_mtime)
            total = sum(p.stat().st_size for p in entries)
            count = len(entries)
            for p in entries:
                size = p.stat().st_size
                if total+len(envelope.encode()) <= 256*1024**2 and count < 1024 and time.time()-p.stat().st_mtime <= 30*86400:break
                p.unlink();total -= size;count -= 1
            with tempfile.NamedTemporaryFile(mode='w', dir=self.root, delete=False) as f:
                temporary = Path(f.name);f.write(envelope)
            os.replace(temporary, self.path(operation, arguments))
        except OSError:pass  # An unwritable cache must not prevent analysis.
        finally:
            if temporary is not None:
                try:temporary.unlink(missing_ok=True)
                except OSError:pass


def evidence(engine, operation, value, limitations=None):
    return {'structuredContent':{'engine':engine, 'operation':operation, 'observed_result':value,
                                  'limitations':limitations or [], 'partial':bool(limitations)}}


def observation(result):
    value=result.get('structuredContent')
    if value is None:
        text='\n'.join(b.get('text','') for b in result.get('content',[]) if b.get('type')=='text')
        try:value=json.loads(text)
        except ValueError:value={'observed_result':text}
    if isinstance(value,dict) and 'data' in value:value=value['data']
    if not isinstance(value,dict):raise ValueError('Motor kanıt nesnesi geçersiz.')
    return value


class StaticAnalysis:
    def __init__(self, path, check=lambda:None, progress=None):
        self.path = str(Path(path).absolute());self.check = check
        self.progress=progress;self.last_progress=None
        self.before = signature(self.path)

    def pulse(self,operation,started,limit=None,activity=None,status='running',force=False,**fields):
        if not self.progress:return
        now=time.monotonic()
        if not force and self.last_progress and self.last_progress[0]==operation and now-self.last_progress[1]<1:return
        self.last_progress=(operation,now)
        event={'operation':operation,'elapsed':round(now-started,2),'limit_seconds':limit,
               'last_activity_seconds':None if activity is None else round(now-activity,2),'status':status,**fields}
        try:self.progress(event)
        except Exception:pass

    def unchanged(self):
        self.check()
        if signature(self.path) != self.before:raise ValueError('Hedef analiz sırasında değişti; sonuç kullanılmadı.')

    def preflight(self):
        self.check()
        with open(self.path, 'rb') as f:
            head = f.read(min(self.before[2], 1024*1024))
            result = {'bytes':self.before[2], 'format':'unknown', 'sections':[], 'packer_indicators':[],
                      'strings':[m.group().decode('ascii')[:160] for m in list(re.finditer(rb'[\x20-\x7e]{6,160}', head))[:128]],
                      'limitations':['Hızlı ön inceleme; string örneği ilk 1 MiB ile sınırlı. Paketleyici işaretleri korumanın kesin kanıtı değildir.'],
                      'resources':memory_policy()}
            if head.startswith(b'\x7fELF'):result['format']='ELF'
            if head.startswith(b'MZ') and len(head)>=64:
                pe = struct.unpack_from('<I', head, 0x3c)[0]
                if pe <= self.before[2]-24:
                    f.seek(pe);header = f.read(24)
                    if header[:4] == b'PE\0\0':
                        machine, count = struct.unpack_from('<HH', header, 4)
                        optional_size = struct.unpack_from('<H', header, 20)[0]
                        if not 0 < count <= 96 or not 64 <= optional_size <= 4096:raise ValueError('PE bölüm/başlık sınırı geçersiz.')
                        optional = f.read(optional_size)
                        if len(optional) != optional_size:raise ValueError('Kesik PE başlığı.')
                        magic = struct.unpack_from('<H', optional)[0]
                        if magic not in (0x10b, 0x20b):raise ValueError('Desteklenmeyen PE optional header.')
                        base = struct.unpack_from('<Q' if magic==0x20b else '<I', optional, 24 if magic==0x20b else 28)[0]
                        result.update(format='PE', architecture={0x14c:'x86',0x8664:'x86_64',0xaa64:'arm64'}.get(machine,hex(machine)),
                                      entry=hex(base+struct.unpack_from('<I',optional,16)[0]))
                        flags=struct.unpack_from('<H',optional,70)[0] if len(optional)>=72 else 0
                        directory_start=112 if magic==0x20b else 96
                        count_offset=108 if magic==0x20b else 92
                        directories=struct.unpack_from('<I',optional,count_offset)[0] if len(optional)>=count_offset+4 else 0
                        def directory(index):
                            offset=directory_start+index*8
                            return struct.unpack_from('<II',optional,offset) if directories>index and len(optional)>=offset+8 else (0,0)
                        relocation=directory(5);certificate=directory(4);clr=directory(14)
                        result['pe_security']={'dll_characteristics':hex(flags),'dynamic_base':bool(flags&0x40),
                            'nx_compatible':bool(flags&0x100),'guard_cf':bool(flags&0x4000),
                            'high_entropy_va':bool(flags&0x20),'no_seh':bool(flags&0x400),
                            'relocation_directory_declared':bool(relocation[0] and relocation[1]),
                            'certificate_table_declared':bool(certificate[0] and certificate[1]),
                            'certificate_table_in_file':bool(certificate[0] and certificate[1] and certificate[0]<=self.before[2] and certificate[1]<=self.before[2]-certificate[0]),
                            'clr_directory_declared':bool(clr[0] and clr[1]),'signature_verified':False}
                        table = f.read(count*40)
                        if len(table)!=count*40:raise ValueError('Kesik PE bölüm tablosu.')
                        for i in range(count):
                            self.check();section=table[i*40:(i+1)*40]
                            name=section[:8].split(b'\0')[0].decode('ascii','replace')
                            virtual_size,rva,size,offset=struct.unpack_from('<IIII',section,8)
                            flags=struct.unpack_from('<I',section,36)[0]
                            if size and (offset>self.before[2] or size>self.before[2]-offset):raise ValueError('PE bölümü dosya sınırını aşıyor.')
                            f.seek(offset);sample=f.read(min(size,65536))
                            entropy = -sum((n/len(sample))*math.log2(n/len(sample)) for n in Counter(sample).values()) if sample else 0
                            result['sections'].append({'name':name,'address':hex(base+rva),'virtual_size':virtual_size,
                                                       'raw_size':size,'entropy_sample':round(entropy,3),'executable':bool(flags&0x20000000),
                                                       'writable':bool(flags&0x80000000)})
                            if name.upper().startswith(('UPX', '.VMP', '.THEMIDA', '.ASPACK')):result['packer_indicators'].append('section:'+name)
                            if flags&0x20000000 and entropy>=7.2:result['packer_indicators'].append('high_entropy_executable:'+name)
            result['recommended_stage']='quick_then_selected_function'
            if result['packer_indicators']:
                result['limitations'].append('Kod paketlenmiş/korumalı olabilir. Çözülen kod yalnız yükleyici olabilir; asıl programın çözüldüğü iddia edilmemeli.')
        self.unchanged();return result

    def command(self, args, timeout=45, env=None, operation=None, capture_stderr=False):
        self.check()
        with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
            command=[sys.executable,'-I','-B',str(Path(__file__).with_name('rea_native_guard.py')),
                     str(memory_policy()['native_memory_bytes']),str(math.ceil(timeout)+3),*map(str,args)]
            p = subprocess.Popen(command, stdout=out, stderr=err, start_new_session=True, env=env)
            started=time.monotonic();activity=None;sizes=(0,0);operation=operation or Path(args[0]).name
            self.pulse(operation,started,timeout,force=True)
            try:
                while p.poll() is None:
                    self.check()
                    current=(os.fstat(out.fileno()).st_size,os.fstat(err.fileno()).st_size)
                    if current!=sizes:activity=time.monotonic();sizes=current
                    self.pulse(operation,started,timeout,activity)
                    if time.monotonic()-started>timeout:
                        raise NativeTimeout(operation or Path(args[0]).name,timeout,time.monotonic()-started)
                    if os.fstat(out.fileno()).st_size>MAX_RESULT or os.fstat(err.fileno()).st_size>1024**2:raise ValueError('Motor çıktı sınırı aşıldı.')
                    time.sleep(.03)
                self.unchanged();out.seek(0);err.seek(0)
                text=out.read(MAX_RESULT+1);error=err.read(1024**2+1)
                if len(text)>MAX_RESULT or len(error)>1024**2:raise ValueError('Motor çıktı sınırı aşıldı.')
                if p.returncode:
                    detail=error.decode(errors='replace')
                    if len(detail)>1600:detail=detail[:1000]+'\n…\n'+detail[-500:]
                    raise ValueError(Path(args[0]).name+f': çıkış kodu {p.returncode}; '+
                        detail+(' (Kaynak sınırı veya dış sonlandırma olabilir.)' if p.returncode<0 else ''))
                decoded=text.decode(errors='replace')
                self.pulse(operation,started,timeout,activity,status='completed',force=True)
                return (decoded,error.decode(errors='replace')) if capture_stderr else decoded
            finally:
                try:os.killpg(p.pid, signal.SIGKILL)
                except ProcessLookupError:pass
                p.wait()

    def executable(self, name):
        p=shutil.which(name)
        if not p:raise ValueError(name+' bulunamadı; Analiz araçlarının durumu ekranını kontrol edin.')
        return p

    def strings(self, max_rows=10000, max_text_bytes=2*1024**2):
        """Bounded fragments with real file offsets; a quota preserves partial evidence."""
        patterns=[(re.compile(rb'[\x20-\x7e\x80-\xff]{4,512}'),'8-bit / UTF-8','utf-8'),
                  (re.compile(rb'(?:[\x20-\x7e]\x00){4,512}'),'UTF-16LE (ASCII aralığı)','utf-16-le'),
                  (re.compile(rb'(?:\x00[\x20-\x7e]){4,512}'),'UTF-16BE (ASCII aralığı)','utf-16-be')]
        rows=[];seen=set();carry=b'';read=0;text_bytes=0;limited=False;started=time.monotonic()
        with open(self.path,'rb') as stream:
            while True:
                self.unchanged();chunk=stream.read(65536);eof=not chunk
                block=carry+chunk;start=read-len(carry);read+=len(chunk)
                self.pulse('String taraması',started,activity=time.monotonic(),bytes_read=read,total_bytes=self.before[2])
                ready=len(block) if eof else max(0,len(block)-1024)
                candidates=[]
                for pattern,label,encoding in patterns:
                    for match in pattern.finditer(block):
                        if match.start()>=ready:continue
                        offset=start+match.start();key=(offset,label)
                        if key not in seen:candidates.append((offset,label,match.group().decode(encoding,errors='replace')))
                for offset,label,text in sorted(candidates):
                    self.check();size=len(text.encode('utf-8'))
                    if len(rows)>=max_rows or text_bytes+size>max_text_bytes:
                        limited=True;break
                    seen.add((offset,label));rows.append({'offset':offset,'encoding':label,'text':text});text_bytes+=size
                if limited or eof:break
                # All deferred starts are in this suffix; already emitted starts
                # are deduplicated when their bytes cross the next chunk boundary.
                carry=block[-2048:]
        self.unchanged()
        self.pulse('String taraması',started,activity=time.monotonic(),status='partial' if limited else 'completed',
                   force=True,bytes_read=read,total_bytes=self.before[2])
        return {'strings':rows,'partial':limited,'scanned_bytes':read,'file_bytes':self.before[2],
                'fragment_limit':512,'limitations':['En fazla 512 bayt/kod birimlik string parçaları; UTF-16 yalnız ASCII aralığı.',
                    'String adayları insan tarafından yazılmış metin olduğunu kanıtlamaz.']+
                    (['Çıktı kotasına ulaşıldı; dosyanın kalanında başka stringler olabilir.'] if limited else [])}

    def quick_functions(self):
        rabin=self.executable('rabin2')
        symbols=json.loads(self.command([rabin,'-sj',self.path]))
        entries=json.loads(self.command([rabin,'-ej',self.path]))
        if isinstance(symbols,dict):symbols=symbols.get('symbols',[])
        if isinstance(entries,dict):entries=entries.get('entries',[])
        if not isinstance(symbols,list) or not isinstance(entries,list):raise ValueError('Rabin2 envanter biçimi geçersiz.')
        functions=[{'name':s.get('name'),'address':hex(s['vaddr'])} for s in symbols if isinstance(s,dict) and s.get('type')=='FUNC' and type(s.get('vaddr')) is int][:1000]
        for e in entries[:32]:
            if isinstance(e,dict) and type(e.get('vaddr')) is int:functions.insert(0,{'name':'entry0','address':hex(e['vaddr'])})
        return evidence('radare2/rabin2','quick_functions',functions,
                        ['Başlık girişleri ve semboller; tam fonksiyon envanteri değildir. Global aa/aaa analizi çalıştırılmadı.'])

    def address(self, procedure):
        if re.fullmatch(r'0x[0-9a-fA-F]{1,16}',procedure):return int(procedure,16)
        functions=self.quick_functions()['structuredContent']['observed_result']
        hits={f['address'] for f in functions if f['name']==procedure}
        if len(hits)!=1:raise ValueError('Alternatif motor için tekil sembol veya 0x adresi gerekli: '+procedure)
        return int(hits.pop(),16)

    def assembly(self, procedure, pseudo=False):
        address=self.address(procedure)
        query=f'af @ {hex(address)};'+(f'pdc @ {hex(address)}' if pseudo else f'pdj 256 @ {hex(address)}')
        text=self.command([self.executable('radare2'),'-N','-2','-q','-e','scr.color=0','-c',query,self.path],timeout=60,
                          operation='Radare2 / seçili '+('sözde kod' if pseudo else 'assembly'))
        if not text.strip():raise ValueError('Radare2 seçili adreste çıktı üretmedi.')
        if pseudo and not re.search(r'\)\s*\{',text):raise ValueError('Radare2 sözde kod gövdesi üretmedi.')
        return evidence('radare2', 'procedure_pseudo_code' if pseudo else 'procedure_assembly',text,
                        ['Yalnız seçili adres; sınırlı statik çıktı. Radare2 pdc yaklaşık sözde koddur, özgün kaynak kod değildir.' if pseudo else 'En fazla 256 komut; tam fonksiyon olmayabilir.'])

    def retdec(self, procedure):
        if not procedure:raise ValueError('RetDec için fonksiyon adı veya 0x adresi seçin.')
        if memory_policy()['available_bytes'] < 512*1024**2:
            raise ValueError('RetDec için kullanılabilir bellek 512 MiB altında; hızlı Radare2 incelemesini kullanın.')
        with tempfile.TemporaryDirectory(prefix='rehkc-retdec-') as temporary:
            output=Path(temporary)/'selected.c'
            # The guard already sets a hard address-space limit. RetDec's own
            # limiter tries to raise inherited limits and fails under a hard cap.
            args=[self.executable('retdec-decompiler'),'--timeout','180','--no-memory-limit',
                  '--cleanup','--backend-no-time-varying-info','--select-decode-only','-o',str(output)]
            limitations=['Seçici RetDec analizi; özgün kaynak kod değildir. Seçili aralık/fonksiyon dışındaki kod analiz edilmedi.']
            if re.fullmatch(r'0x[0-9a-fA-F]{1,16}',procedure):
                address=int(procedure,16)
                if address>2**64-4096:raise ValueError('Adres aralığı geçersiz.')
                end=address+4095
                for section in self.preflight()['sections']:
                    start=int(section['address'],16)
                    if start<=address<start+section['virtual_size']:end=min(end,start+section['virtual_size']-1)
                args+=['--select-ranges',f'{hex(address)}-{hex(end)}']
                limitations.append('Adres seçimi en fazla 4096 bayt; tüm fonksiyonun kurtarıldığı garanti edilmez.')
            elif re.fullmatch(r'[A-Za-z_?$@.][A-Za-z0-9_?$@.:]{0,255}',procedure):args+=['--select-functions',procedure]
            else:raise ValueError('Geçersiz fonksiyon adı/adresi.')
            self.command([*args,self.path],timeout=200,operation='RetDec / seçili fonksiyon')
            if not output.is_file() or output.stat().st_size>MAX_RESULT:raise ValueError('RetDec C çıktısı yok veya çok büyük.')
            code=output.read_text(errors='replace')
            if not re.search(r'\)\s*\{',code):raise ValueError('RetDec fonksiyon gövdesi üretmedi.')
            return evidence('retdec','procedure_pseudo_code',code,limitations)

    def fallback(self, name, arguments, reason):
        self.unchanged();failures=[{'engine':'ghidra','error':str(reason)[:1200]}]
        if hasattr(reason,'details'):failures[0]['timeout']=reason.details()
        if name=='list_procedures':result=self.quick_functions()
        elif name in ('list_strings','search_strings'):
            p=self.preflight();strings=p['strings']
            if name=='search_strings':strings=[s for s in strings if arguments['pattern'].lower() in s.lower()]
            result=evidence('bounded-static-scan',name,strings,p['limitations'])
        elif name=='procedure_assembly':result=self.assembly(arguments['procedure'])
        elif name=='procedure_pseudo_code':
            try:result=self.retdec(arguments['procedure'])
            except Exception as exc:
                self.check()
                failures.append({'engine':'retdec','error':str(exc)[:1200]})
                result=self.assembly(arguments['procedure'],pseudo=True)
        else:raise ValueError('Bu işlem için alternatif motor yok.')
        result['structuredContent']['fallback_from']=failures
        self.unchanged();return result

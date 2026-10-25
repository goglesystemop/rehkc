"""Static Radare2 and RetDec adapters for the Makulu desktop GUI."""
import os, re, json, stat, time, shutil, hashlib, tempfile, subprocess, signal
from pathlib import Path
from PyQt5.QtCore import QThread, pyqtSignal

class EngineCancelled(Exception): pass

class ExtraEngineWorker(QThread):
    completed=pyqtSignal(str,str)
    failed=pyqtSignal(str,str)
    log_line=pyqtSignal(str,str)

    def __init__(self,engine,target,procedure='',parent=None):
        super().__init__(parent);self.engine=engine;self.target=os.path.abspath(target);self.procedure=procedure.strip();self.stopped=False;self.process=None

    def cancel(self):
        self.stopped=True
        process=self.process
        if process:
            try:os.killpg(process.pid,signal.SIGTERM)
            except ProcessLookupError:pass

    def check(self):
        if self.stopped:raise EngineCancelled()

    def command(self,args,cwd,timeout=90):
        self.check()
        with tempfile.TemporaryFile() as output,tempfile.TemporaryFile() as error:
            process=subprocess.Popen(args,cwd=cwd,stdout=output,stderr=error,start_new_session=True,env=dict(os.environ,LC_ALL='C'))
            self.process=process;started=time.monotonic()
            try:
                while process.poll() is None:
                    self.check()
                    if time.monotonic()-started>timeout:raise ValueError('Analiz zaman sınırını aştı.')
                    if os.fstat(output.fileno()).st_size>32*1024*1024 or os.fstat(error.fileno()).st_size>4*1024*1024:raise ValueError('Araç çıktısı sınırı aşıldı.')
                    time.sleep(.02)
                self.check();output.seek(0);error.seek(0)
                stdout=output.read(32*1024*1024+1);stderr=error.read(4*1024*1024+1)
                if len(stdout)>32*1024*1024 or len(stderr)>4*1024*1024:raise ValueError('Araç çıktısı sınırı aşıldı.')
                if process.returncode:raise ValueError(f"{Path(args[0]).name} çıkış kodu {process.returncode}: "+stderr.decode('utf-8','replace')[-5000:]+stdout.decode('utf-8','replace')[-2000:])
                return stdout.decode('utf-8','replace'),stderr.decode('utf-8','replace')
            finally:
                try:os.killpg(process.pid,signal.SIGKILL)
                except ProcessLookupError:pass
                if process.poll() is None:process.wait()
                self.process=None

    def executable(self,name):
        path=shutil.which(name)
        if name=='radare2' and not path:path=shutil.which('r2')
        if name=='retdec-decompiler' and not path:
            root=os.environ.get('RETDEC_INSTALL_DIR') or str(Path.home()/'.local/opt/retdec-5.0')
            candidate=Path(root)/'bin/retdec-decompiler'
            if candidate.is_file() and os.access(candidate,os.X_OK):path=str(candidate)
        if not path:raise ValueError(name+' bulunamadı. Analiz araçlarının durumu ekranını kontrol edin.')
        return path

    def json_command(self,args,cwd):
        text,_=self.command(args,cwd)
        try:return json.loads(text)
        except ValueError:raise ValueError('Araç geçerli JSON analiz çıktısı vermedi: '+text[:500])

    def radare(self,cwd):
        r2=self.executable('radare2');rabin=self.executable('rabin2')
        version=self.command([r2,'-v'],cwd)[0].splitlines()[0]
        meta=self.json_command([rabin,'-Ij',self.target],cwd)
        strings=self.json_command([rabin,'-zj',self.target],cwd)
        common=[r2,'-N','-2','-q','-A','-e','scr.color=0','-e','bin.relocs.apply=true']
        functions=self.json_command([*common,'-c','aflj',self.target],cwd)
        if not isinstance(functions,list) or not functions:raise ValueError('Radare2 ayrılabilir fonksiyon bulamadı.')
        selected=None;details=None;blocks=[];refs=[]
        if self.procedure:
            numeric=int(self.procedure,16) if re.fullmatch(r'0x[0-9a-fA-F]+',self.procedure) else None
            candidates=[]
            for item in functions:
                addr=item.get('addr',item.get('offset'));name=item.get('name','')
                if (numeric is not None and addr==numeric) or name==self.procedure or re.sub(r'^(?:dbg|sym|fcn)\.', '',name)==self.procedure:candidates.append(item)
            if len(candidates)!=1:raise ValueError('Fonksiyon/adres tek bir sonuçla eşleşmedi: '+self.procedure)
            selected=candidates[0];addr=selected.get('addr',selected.get('offset'))
            if type(addr) is not int or not 0<=addr<2**64:raise ValueError('Geçersiz fonksiyon adresi.')
            query=f'pdfj @ {hex(addr)};afbj @ {hex(addr)};axtj @ {hex(addr)}'
            text,_=self.command([*common,'-c',query,self.target],cwd)
            decoder=json.JSONDecoder();values=[]
            try:
                while text.strip():value,end=decoder.raw_decode(text.lstrip());values.append(value);text=text.lstrip()[end:]
            except ValueError:raise ValueError('Radare2 fonksiyon ayrıntıları okunamadı.')
            if len(values)!=3 or not isinstance(values[0],dict):raise ValueError('Radare2 fonksiyon ayrıntıları eksik.')
            details,blocks,refs=values
        lines=[version,'Hedef: '+self.target,f'Fonksiyon sayısı: {len(functions)}','', 'FONKSİYON ENVANTERİ']
        for item in functions:
            addr=item.get('addr',item.get('offset',0));lines.append(f"{hex(addr) if type(addr) is int else addr}  {item.get('name','?')}  boyut={item.get('size','?')}  blok={item.get('nbbs','?')}")
        if details:
            lines += ['', 'SEÇİLİ FONKSİYON: '+details.get('name',self.procedure),f'Temel blok: {len(blocks) if isinstance(blocks,list) else 0}; gelen referans: {len(refs) if isinstance(refs,list) else 0}','']
            for item in details.get('ops',[]):
                addr=item.get('addr',item.get('offset',0));lines.append(f"{hex(addr) if type(addr) is int else addr}  {item.get('opcode',item.get('disasm',''))}")
        raw_strings=strings.get('strings',[]) if isinstance(strings,dict) else strings if isinstance(strings,list) else []
        string_text='\n'.join(f"{hex(s.get('vaddr',0))}  {s.get('string','')}" for s in raw_strings if isinstance(s,dict) and type(s.get('vaddr',0)) is int)
        return dict(engine='radare2',version=version,target=self.target,metadata=meta,functions=functions,strings=strings,selected_function=details,basic_blocks=blocks,incoming_references=refs,report='\n'.join(lines),strings_report=string_text)

    def retdec(self,cwd):
        binary=self.executable('retdec-decompiler');version=self.command([binary,'--version'],cwd)[0].splitlines()[0]
        output=Path(cwd)/'decompiled.c'
        args=[binary,'--timeout','120','--max-memory','4294967296','--cleanup','--backend-no-time-varying-info','-o',str(output)]
        if self.procedure:
            names=[name.strip() for name in self.procedure.split(',')]
            if any(not re.fullmatch(r'[A-Za-z_?$@.][A-Za-z0-9_?$@.:]*',name) for name in names):raise ValueError('Fonksiyon adı/adları geçersiz. İsimleri virgülle ayırın veya alanı boş bırakın.')
            args+=['--select-functions',','.join(names)]
        args.append(self.target)
        stdout,stderr=self.command(args,cwd,timeout=180)
        if not output.is_file() or output.stat().st_size>16*1024*1024:raise ValueError('RetDec geçerli boyutta bir C dosyası üretmedi.')
        code=output.read_text(errors='replace')
        if not re.search(r'\)\s*\{',code):raise ValueError('RetDec seçilen fonksiyon için bir gövde üretmedi; adı veya dosya biçimini kontrol edin.')
        return dict(engine='retdec',version=version,target=self.target,procedure=self.procedure,code=code,diagnostics=(stdout+'\n'+stderr)[-12000:])

    def analyze(self):
        self.check();before=os.stat(self.target)
        if not stat.S_ISREG(before.st_mode) or before.st_size>128*1024*1024:raise ValueError('En fazla 128 MB boyutunda normal bir dosya seçin.')
        with open(self.target,'rb') as source:digest=hashlib.file_digest(source,'sha256').hexdigest()
        self.log_line.emit(('Radare2 analizi' if self.engine=='radare2' else 'RetDec decompile')+' başlatılıyor…','run')
        with tempfile.TemporaryDirectory(prefix='rea-static-engine-') as cwd:
            if self.engine=='radare2':result=self.radare(cwd)
            elif self.engine=='retdec':result=self.retdec(cwd)
            else:raise ValueError('Bilinmeyen analiz aracı.')
        self.check();after=os.stat(self.target)
        if (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns):raise ValueError('Hedef dosya analiz sırasında değişti; sonuç kullanılmadı.')
        result['target_sha256']=digest
        return result

    def run(self):
        try:self.completed.emit(self.engine,json.dumps(self.analyze(),ensure_ascii=False))
        except EngineCancelled:self.failed.emit(self.engine,'İşlem durduruldu.')
        except Exception as exc:self.failed.emit(self.engine,str(exc))

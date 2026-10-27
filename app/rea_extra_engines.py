"""GUI adapters share the staged, cached static analysis path with MCP."""
import json
import os
from pathlib import Path
import threading
import time
from PyQt5.QtCore import QThread, pyqtSignal
from rea_analysis import StaticAnalysis, ResultCache, digest_file, engine_identity
from rea_mcp import McpCancelled, McpClient, SelectedTargetTools

class ExtraEngineWorker(QThread):
    completed=pyqtSignal(str,str)
    failed=pyqtSignal(str,str)
    log_line=pyqtSignal(str,str)
    preflight_ready=pyqtSignal(dict)

    def __init__(self,engine,target,procedure='',parent=None,rea_bin=None):
        super().__init__(parent)
        self.engine,self.target,self.procedure=engine,os.path.abspath(target),procedure.strip()
        self.rea_bin=rea_bin or os.environ.get('REA_BIN_PATH') or str(Path(__file__).with_name('rea-engine'))
        self.stopped=threading.Event();self.client=None;self.started=None

    def cancel(self):self.stopped.set()

    def check(self):
        if self.stopped.is_set():raise McpCancelled('Analiz durduruldu.')
        if self.started is not None and time.monotonic()-self.started>1800:raise TimeoutError('Seçili fonksiyon analizi: toplam 1800 sn sınırı doldu.')

    def analyze(self):
        self.started=time.monotonic();service=StaticAnalysis(self.target,self.check)
        preflight=service.preflight()
        self.preflight_ready.emit(dict(target=self.target,preflight=preflight))
        self.log_line.emit('Hızlı ön inceleme: '+str(preflight['bytes'])+' bayt, '+preflight['format']+'; derin analiz seçili fonksiyonla sınırlandırılıyor.','info')
        if preflight['packer_indicators']:self.log_line.emit('Paketleyici/koruma işaretleri: '+', '.join(preflight['packer_indicators'])+'. Sonuç yalnız yükleyici kodu olabilir.','warn')
        digest=digest_file(self.target,self.check)
        cache=ResultCache(digest,engine_identity(self.rea_bin,self.check),target=self.target)
        args={'procedure':self.procedure};operation='manual/'+self.engine
        result=cache.get(operation,args)
        if result is not None:
            service.unchanged();result['cache_hit']=True
            self.log_line.emit('Önbellek: aynı dosya ve motor ayarları için tamamlanan sonuç kullanıldı.','info')
            return result
        if self.engine=='adaptive':
            self.log_line.emit('Ghidra seçili fonksiyonu çözüyor; gerekirse RetDec/Radare2 denenecek. Durdur kullanılabilir.','run')
            self.client=McpClient(self.rea_bin,self.stopped,self.started+1800,started=self.started)
            try:
                _,inventory=self.client.start()
                router=SelectedTargetTools(self.client,self.target,inventory,lambda e:self.log_line.emit(
                    e['tool']+': '+e['status']+(' (önbellek)' if e.get('cache_hit') else ''),'info'),
                    digest=digest,expected_signature=service.before)
                result=router.execute('procedure_pseudo_code',{'procedure':self.procedure})
            finally:self.client.close();self.client=None
        elif self.engine=='retdec':result=service.retdec(self.procedure or preflight.get('entry',''))
        elif self.engine=='radare2':result=service.assembly(self.procedure) if self.procedure else service.quick_functions()
        else:raise ValueError('Bilinmeyen motor.')
        service.unchanged()
        if result.get('isError') or result.get('structuredContent',{}).get('ok') is False:raise ValueError('Motor analiz hatası: '+json.dumps(result,ensure_ascii=False)[:1600])
        result.update(target=self.target,target_sha256=digest,preflight=preflight)
        # Partial observations retain their limitations; failed results never enter cache.
        cache.put(operation,args,result)
        return result

    def run(self):
        try:self.completed.emit(self.engine,json.dumps(self.analyze(),ensure_ascii=False))
        except Exception as exc:self.failed.emit(self.engine,str(exc))

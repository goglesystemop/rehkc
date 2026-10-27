"""GUI adapters share the staged, cached static analysis path with MCP."""
import json
import os
from pathlib import Path
import threading
import time
from datetime import datetime, timezone
from PyQt5.QtCore import QThread, pyqtSignal
from rea_analysis import StaticAnalysis, ResultCache, digest_file, engine_identity
from rea_mcp import McpCancelled, McpClient, SelectedTargetTools

class ExtraEngineWorker(QThread):
    completed=pyqtSignal(str,str)
    failed=pyqtSignal(str,str)
    log_line=pyqtSignal(str,str)
    preflight_ready=pyqtSignal(dict)
    analysis_progress=pyqtSignal(dict)

    def __init__(self,engine,target,procedure='',parent=None,rea_bin=None,refresh=False,session_pool=None):
        super().__init__(parent)
        self.engine,self.target,self.procedure=engine,os.path.abspath(target),procedure.strip()
        self.refresh=refresh
        self.session_pool,self.analysis_lease=session_pool,None
        self.rea_bin=rea_bin or os.environ.get('REA_BIN_PATH') or str(Path(__file__).with_name('rea-engine'))
        self.stopped=threading.Event();self.client=None;self.started=None

    def cancel(self):self.stopped.set()

    def check(self):
        if self.stopped.is_set():raise McpCancelled('Analiz durduruldu.')
        if self.started is not None and time.monotonic()-self.started>1800:raise TimeoutError('Seçili fonksiyon analizi: toplam 1800 sn sınırı doldu.')

    def analyze(self):
        self.started=time.monotonic();service=StaticAnalysis(self.target,self.check,progress=self.analysis_progress.emit)
        preflight=service.preflight()
        self.preflight_ready.emit(dict(target=self.target,preflight=preflight))
        self.log_line.emit('Hızlı ön inceleme: '+str(preflight['bytes'])+' bayt, '+preflight['format']+'; derin analiz seçili fonksiyonla sınırlandırılıyor.','info')
        if preflight['packer_indicators']:self.log_line.emit('Paketleyici/koruma işaretleri: '+', '.join(preflight['packer_indicators'])+'. Sonuç yalnız yükleyici kodu olabilir.','warn')
        digest=digest_file(self.target,self.check,progress=self.analysis_progress.emit)
        cache=ResultCache(digest,engine_identity(self.rea_bin,self.check),target=self.target,read_enabled=not self.refresh)
        if self.refresh:self.log_line.emit('Önbellek atlanarak seçili fonksiyon yeniden analiz ediliyor.','info')
        args={'procedure':self.procedure};operation='manual/'+self.engine
        result=cache.get(operation,args)
        if result is not None:
            result.pop('refresh_requested',None)
            result['analysis_session_reused']=False
            service.unchanged();result['cache_hit']=True
            self.log_line.emit('Önbellek: aynı dosya ve motor ayarları için tamamlanan sonuç kullanıldı.','info')
            return result
        if self.engine=='adaptive':
            self.log_line.emit('Ghidra seçili fonksiyonu çözüyor; gerekirse RetDec/Radare2 denenecek. Durdur kullanılabilir.','run')
            router=None;reused=False
            if self.session_pool is not None:
                self.analysis_lease=self.session_pool.acquire(self.rea_bin,self.target,digest,self.stopped,
                    self.started+1800,self.started,self.check,expected_signature=service.before,
                    force_fresh=self.refresh,progress=self.analysis_progress.emit)
                self.client=self.analysis_lease.client
                inventory=self.analysis_lease.inventory;reused=self.analysis_lease.reused
                if reused:self.log_line.emit('Aynı dosyanın açık Ghidra analiz oturumu yeniden kullanılıyor.','info')
            else:
                self.client=McpClient(self.rea_bin,self.stopped,self.started+1800,started=self.started)
                self.client.progress=self.analysis_progress.emit
                inventory=None
            try:
                if inventory is None:_,inventory=self.client.start()
                router=SelectedTargetTools(self.client,self.target,inventory,lambda e:self.log_line.emit(
                    e['tool']+': '+e['status']+(' (önbellek)' if e.get('cache_hit') else ''),'info'),
                    digest=digest,expected_signature=service.before,read_cache=not self.refresh)
                result=router.execute('procedure_pseudo_code',{'procedure':self.procedure})
                result['analysis_session_reused']=reused
            finally:
                if self.analysis_lease:self.analysis_lease.release(healthy=router is not None and router.primary_failed is None)
                else:self.client.close()
                self.client=None;self.analysis_lease=None
        elif self.engine=='retdec':result=service.retdec(self.procedure or preflight.get('entry',''))
        elif self.engine=='radare2':result=service.assembly(self.procedure) if self.procedure else service.quick_functions()
        else:raise ValueError('Bilinmeyen motor.')
        service.unchanged()
        if result.get('isError') or result.get('structuredContent',{}).get('ok') is False:raise ValueError('Motor analiz hatası: '+json.dumps(result,ensure_ascii=False)[:1600])
        result.update(target=self.target,target_sha256=digest,preflight=preflight,
                      procedure=self.procedure,engine_identity=cache.identity.split('|',1)[0],
                      analysis_completed_at=datetime.now(timezone.utc).isoformat())
        if self.refresh:result['refresh_requested']=True
        # Partial observations retain their limitations; failed results never enter cache.
        cache.put(operation,args,result)
        return result

    def run(self):
        try:self.completed.emit(self.engine,json.dumps(self.analyze(),ensure_ascii=False))
        except Exception as exc:self.failed.emit(self.engine,str(exc))

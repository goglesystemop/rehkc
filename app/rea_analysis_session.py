"""One reusable, read-only MCP analysis per desktop window; exclusive leases."""
import atexit
from pathlib import Path
import threading
import time

from rea_analysis import engine_identity, signature
from rea_mcp import McpClient


class AnalysisLease:
    def __init__(self,pool,entry,reused):
        self.pool,self.entry,self.reused=pool,entry,reused
        self.client,self.info,self.inventory=entry['client'],entry['info'],entry['inventory']
        self.released=False

    def release(self,healthy=True):
        if not self.released:
            self.released=True
            self.pool.release(self,healthy)


class AnalysisSessionPool:
    def __init__(self,idle_seconds=300,client_factory=McpClient):
        self.idle_seconds,self.factory=idle_seconds,client_factory
        self.lock=threading.Lock();self.entry=None;self.active=False
        self.active_stop=None
        self.epoch=0;self.timer=None;self.closed=False;self.cleanup_threads=[]
        atexit.register(self.close)

    def _detach(self):
        self.epoch+=1
        if self.timer:self.timer.cancel();self.timer=None
        old=self.entry;self.entry=None
        return old

    def _dispose(self,entry,background=False):
        if entry is None:return
        def close():
            try:
                entry['client'].progress=None
                entry['client'].close()
            except Exception:pass
        if background:
            thread=threading.Thread(target=close,name='rehkc-analysis-cleanup',daemon=True)
            with self.lock:
                self.cleanup_threads=[t for t in self.cleanup_threads if t.is_alive()]
                self.cleanup_threads.append(thread);thread.start()
        else:close()

    def acquire(self,binary,path,digest,stopped,deadline,started,check=lambda:None,
                expected_signature=None,force_fresh=False,progress=None):
        check();path=str(Path(path).absolute());stamp=signature(path)
        if expected_signature is not None and stamp!=expected_signature:
            raise ValueError('Hedef değişti; sıcak analiz oturumu kullanılmadı.')
        key=(path,stamp,digest,engine_identity(binary,check))
        with self.lock:
            if self.closed:raise ValueError('Analiz oturumu havuzu kapalı.')
            if self.active:raise ValueError('Bu pencerede başka bir analiz çalışıyor; bitmesini bekleyin.')
            self.active=True
            self.active_stop=stopped
            old=None;entry=self.entry
            if entry and (force_fresh or entry['key']!=key or entry['expires']<=time.monotonic()
                          or getattr(entry['client'],'_closed',False) or entry['client'].process.poll() is not None):
                old=self._detach();entry=None
            else:
                self.epoch+=1
                if self.timer:self.timer.cancel();self.timer=None
            generation=self.epoch
        self._dispose(old)
        reused=entry is not None
        try:
            if entry is None:
                client=self.factory(binary,stopped,deadline,started=started)
                try:
                    client.progress=progress
                    info,inventory=client.start()
                    entry={'client':client,'info':info,'inventory':inventory,'key':key,'expires':0,'generation':generation}
                except BaseException:
                    client.close();raise
            else:
                client=entry['client'];client.stopped=stopped;client.deadline=deadline;client.started=started
                client.progress=progress;client.request_context=None
            check()
            if signature(path)!=stamp:raise ValueError('Hedef analiz bağlantısı sırasında değişti.')
            with self.lock:
                if self.closed or generation!=self.epoch:raise ValueError('Analiz oturumu hedef değişimi nedeniyle bırakıldı.')
                self.entry=entry;entry['generation']=generation
            return AnalysisLease(self,entry,reused)
        except BaseException:
            with self.lock:
                self.active=False
                self.active_stop=None
                if self.entry is entry:self.entry=None
            self._dispose(entry)
            raise

    def release(self,lease,healthy):
        entry=lease.entry;client=entry['client']
        try:unchanged=signature(entry['key'][0])==entry['key'][1]
        except (OSError,ValueError):unchanged=False
        keep=healthy and unchanged and not client.stopped.is_set() and client.pending is None and not getattr(client,'_closed',False) and client.process.poll() is None
        with self.lock:
            self.active=False
            self.active_stop=None
            if self.entry is not entry or entry['generation']!=self.epoch or self.closed:keep=False
            if not keep:
                if self.entry is entry:self._detach()
            else:
                # Never retain a GUI worker's bound signal/cancellation context while idle.
                client.progress=None
                entry['expires']=time.monotonic()+self.idle_seconds;self.epoch+=1
                token=self.epoch;entry['generation']=token
                self.timer=threading.Timer(self.idle_seconds,self._expire,args=(entry,token))
                self.timer.daemon=True;self.timer.start()
        if not keep:self._dispose(entry)

    def _expire(self,entry,token):
        with self.lock:
            if self.active or self.entry is not entry or token!=self.epoch:return
            # Window close must also wait for a timer that has detached a
            # client and is still closing its JVM outside the pool lock.
            self.cleanup_threads=[t for t in self.cleanup_threads if t.is_alive()]
            self.cleanup_threads.append(threading.current_thread())
            old=self._detach()
        self._dispose(old)

    def clear(self):
        with self.lock:
            if self.active:
                self.epoch+=1
                if self.active_stop:self.active_stop.set()
                return
            old=self._detach()
        self._dispose(old,background=True)

    def close(self):
        with self.lock:
            if self.closed:return
            self.closed=True
            if self.active:
                self.epoch+=1
                if self.active_stop:self.active_stop.set()
                old=None
            else:old=self._detach()
        self._dispose(old)
        for thread in self.cleanup_threads:
            if thread is not threading.current_thread():thread.join(timeout=4)

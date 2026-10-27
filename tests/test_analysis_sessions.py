"""Exclusive session leases, target identity, idle cleanup and cancellation."""
from pathlib import Path
import os
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'app'))
from rea_analysis import digest_file
from rea_mcp import McpCancelled,SelectedTargetTools,SCHEMAS
import rea_analysis_session as sessions

class Client:
    made=[]
    def __init__(self,binary,stopped,deadline,started=None):
        self.binary=binary;self.stopped=stopped;self.deadline=deadline;self.started=started
        self.pending=None;self._closed=False;self.request_context=None;self.opened=False
        self.process=SimpleNamespace(poll=lambda:0 if self._closed else None)
        self.ghidra_initial_timeout=930;self.calls=[];self.progress=None;Client.made.append(self)
    def start(self):
        inventory={n:{} for n in SCHEMAS};inventory['open_binary']={'inputSchema':{'properties':{'provider_id':{}}}}
        return {'name':'test'},inventory
    def check(self,deadline):
        if self.stopped.is_set():raise McpCancelled('stopped')
    def call(self,method,params,**kwargs):
        self.calls.append(params['name']);return {'structuredContent':{'normalized_result':'int f() {return 1;}'}}
    def close(self):self._closed=True

class AnalysisSessions(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name);self.path=self.root/'target';self.path.write_bytes(b'fixture')
        self.env=patch.dict(os.environ,{'REHKC_DATA_DIR':str(self.root/'state')});self.env.start()
        self.ident=patch.object(sessions,'engine_identity',side_effect=lambda binary,check:'identity:'+str(binary));self.ident.start()
        self.pools=[];Client.made=[]
    def tearDown(self):
        for p in self.pools:p.close()
        self.ident.stop();self.env.stop();self.tmp.cleanup()
    def pool(self,timeout=300):
        p=sessions.AnalysisSessionPool(timeout,client_factory=Client);self.pools.append(p);return p
    def acquire(self,p,**kwargs):
        now=time.monotonic();return p.acquire(str(self.path),self.path,digest_file(self.path),threading.Event(),now+3600,now,**kwargs)
    def test_same_file_and_engine_reuse_an_exclusive_connection(self):
        p=self.pool();a=self.acquire(p);client=a.client;a.release();b=self.acquire(p)
        self.assertTrue(b.reused);self.assertIs(b.client,client);self.assertEqual(len(Client.made),1);b.release()
    def test_different_queries_reuse_open_ghidra_state_without_reopening(self):
        p=self.pool();a=self.acquire(p);r=SelectedTargetTools(a.client,self.path,a.inventory,lambda e:None)
        r.execute('list_procedures',{});a.release();b=self.acquire(p)
        r=SelectedTargetTools(b.client,self.path,b.inventory,lambda e:None)
        self.assertTrue(r.ready and r.ghidra_initialized)
        r.execute('procedure_assembly',{'procedure':'entry'})
        self.assertEqual(b.client.calls,['open_binary','list_procedures','procedure_assembly']);b.release()
    def test_concurrent_acquire_is_rejected(self):
        p=self.pool();a=self.acquire(p)
        with self.assertRaisesRegex(ValueError,'başka bir analiz'):self.acquire(p)
        a.release()
    def test_changed_file_invalidates_the_old_session(self):
        p=self.pool();a=self.acquire(p);old=a.client;a.release();self.path.write_bytes(b'changed')
        b=self.acquire(p);self.assertFalse(b.reused);self.assertTrue(old._closed);b.release()
    def test_engine_identity_change_discards_the_idle_program(self):
        p=self.pool();a=self.acquire(p);a.release();now=time.monotonic()
        b=p.acquire('other-engine',self.path,digest_file(self.path),threading.Event(),now+100,now)
        self.assertFalse(b.reused);self.assertTrue(a.client._closed);b.release()
    def test_force_fresh_discards_both_connection_and_warm_program(self):
        p=self.pool();a=self.acquire(p);old=a.client;a.release();b=self.acquire(p,force_fresh=True)
        self.assertFalse(b.reused);self.assertTrue(old._closed);b.release()
    def test_cancelled_and_pending_clients_are_never_retained(self):
        for mode in ('cancel','pending','unhealthy'):
            p=self.pool();a=self.acquire(p)
            if mode=='cancel':a.client.stopped.set()
            if mode=='pending':a.client.pending=1
            a.release(healthy=mode!='unhealthy');self.assertTrue(a.client._closed)
    def test_idle_timeout_reaps_process_without_a_gui_timer(self):
        p=self.pool(.05);a=self.acquire(p);a.release();end=time.monotonic()+1
        while not a.client._closed and time.monotonic()<end:time.sleep(.01)
        self.assertTrue(a.client._closed)
    def test_idle_client_does_not_hold_worker_progress_callback(self):
        p=self.pool();a=self.acquire(p,progress=lambda e:None);a.release();self.assertIsNone(a.client.progress)
    def test_close_waits_for_an_expiring_jvm_cleanup(self):
        p=self.pool(.01);started=threading.Event();finish=threading.Event()
        def slow_close(client):
            started.set();finish.wait(1);client._closed=True
        with patch.object(Client,'close',new=slow_close):
            a=self.acquire(p);a.release();self.assertTrue(started.wait(1))
            timer=threading.Timer(.05,finish.set);timer.start()
            try:p.close()
            finally:timer.cancel();finish.set()
        self.assertTrue(a.client._closed)
    def test_new_worker_receives_new_deadline_and_cancel_event(self):
        p=self.pool();a=self.acquire(p);old_event=a.client.stopped;a.release();b=self.acquire(p)
        self.assertIsNot(b.client.stopped,old_event);old_event.set();self.assertFalse(b.client.stopped.is_set());b.release()
    def test_clear_active_lease_cancels_and_prevents_reuse(self):
        p=self.pool();a=self.acquire(p);p.clear();self.assertTrue(a.client.stopped.is_set());a.release();self.assertTrue(a.client._closed)
    def test_close_cleans_idle_and_refuses_new_leases(self):
        p=self.pool();a=self.acquire(p);a.release();p.close();self.assertTrue(a.client._closed)
        with self.assertRaisesRegex(ValueError,'kapalı'):self.acquire(p)
    def test_file_deleted_before_release_is_safely_discarded(self):
        p=self.pool();a=self.acquire(p);self.path.unlink();a.release();self.assertTrue(a.client._closed)
    def test_failed_start_does_not_leave_pool_busy(self):
        p=self.pool()
        with patch.object(Client,'start',side_effect=RuntimeError('broken')):
            with self.assertRaises(RuntimeError):self.acquire(p)
        self.assertTrue(Client.made[-1]._closed);a=self.acquire(p);a.release()
    def test_model_network_failure_can_preserve_healthy_analysis_for_next_worker(self):
        from rea_copilot import McpCopilotWorker
        p=self.pool();records=[]
        def worker():
            w=McpCopilotWorker('http://127.0.0.1:1234','','fixture',[{'role':'user','content':'analyze'}],self.path,str(self.path),session_pool=p)
            w.run_recorded.connect(records.append)
            return w
        def call(name,args):return {'id':'call-1','type':'function','function':{'name':name,'arguments':__import__('json').dumps(args)}}
        first=worker()
        with patch.object(first,'model_round',side_effect=[('',[call('list_procedures',{})]),OSError('temporary model connection failure')]):first.run()
        self.assertEqual(records[-1]['status'],'Hata');self.assertFalse(Client.made[0]._closed)
        second=worker()
        with patch.object(second,'model_round',side_effect=[('',[call('procedure_pseudo_code',{'procedure':'entry'})]),('Observed code',[])]):second.run()
        self.assertEqual(records[-1]['status'],'Tamamlandı');self.assertTrue(records[-1]['analysis_session_reused'])
        self.assertEqual(Client.made[0].calls,['open_binary','list_procedures','procedure_pseudo_code'])
    def test_clear_during_initialization_cancels_unpublished_client(self):
        p=self.pool();errors=[];ready=threading.Event()
        def slow_start(client):
            ready.set()
            if not client.stopped.wait(1):raise RuntimeError('cancel was not delivered')
            raise McpCancelled('initialization cancelled')
        def acquire():
            try:self.acquire(p)
            except Exception as exc:errors.append(exc)
        with patch.object(Client,'start',new=slow_start):
            thread=threading.Thread(target=acquire);thread.start();self.assertTrue(ready.wait(1))
            p.clear();thread.join(2)
        self.assertFalse(thread.is_alive());self.assertIsInstance(errors[0],McpCancelled)
        self.assertTrue(Client.made[-1]._closed);self.assertFalse(p.active)

if __name__=='__main__':unittest.main(verbosity=2)

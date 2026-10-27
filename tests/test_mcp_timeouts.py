"""Cold Ghidra budgets, precise timeout diagnostics and responsive cancellation."""
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'app'))
import rea_mcp as mcp
from rea_copilot import McpCopilotWorker
from rea_chatgpt import CloudCopilotWorker

SERVER='''#!/usr/bin/env python3
import json,os,sys,time
for raw in sys.stdin:
 r=json.loads(raw)
 if 'id' not in r:continue
 if r['method']=='echo_env':
  result={'startup_ms':os.environ.get('REA_GHIDRA_STARTUP_TIMEOUT_MS')}
 else:
  for i in range(1000):
   sys.stderr.write('working\\n');sys.stderr.flush();time.sleep(.02)
  result={}
 print(json.dumps({'jsonrpc':'2.0','id':r['id'],'result':result}),flush=True)
'''

class VirtualClient(mcp.McpClient):
    def __init__(self,clock,costs=None,results=None,total=3600):
        self.clock=clock;self.costs=costs or {};self.results=results or {}
        self.started=clock.value;self.deadline=self.started+total
        self.stopped=threading.Event();self.request_context=None;self.last_operation=None
        self.next_id=0;self.pending=None;self.buffer=bytearray();self.opened=False
        self.ghidra_initial_timeout=930;self.observed=[]
    def write(self,value,deadline,ignore_cancel=False):
        name=value['params'].get('name',value['method'])
        self.observed.append((name,self.request_context['limit']))
        self.clock.value+=self.costs.get(name,0)
        result=self.results.get(name,{'structuredContent':{'ok':True,'normalized_result':'observed'}})
        self.buffer.extend(json.dumps({'id':value['id'],'result':result}).encode()+b'\n')


class McpTimeouts(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.target=self.root/'target.elf';self.target.write_bytes(b'fixture, never executed')
        self.server=self.root/'mcp-server';self.server.write_text(SERVER);self.server.chmod(0o755)
    def tearDown(self):self.temp.cleanup()
    def router(self,client):
        inventory={name:{} for name in mcp.SCHEMAS}
        inventory['open_binary']={'inputSchema':{'properties':{'provider_id':{}}}}
        return mcp.SelectedTargetTools(client,self.target,inventory,lambda e:None)
    def worker(self):
        return McpCopilotWorker('http://localhost:1234','','test',[{'role':'user','content':'analyze'}],self.target,str(self.server))

    def test_cold_analysis_can_exceed_old_90_seconds(self):
        clock=SimpleNamespace(value=10.)
        with patch.object(mcp,'time',SimpleNamespace(monotonic=lambda:clock.value)):
            client=VirtualClient(clock,{'list_procedures':120,'procedure_pseudo_code':10})
            router=self.router(client)
            router.execute('list_procedures',{})
            router.execute('procedure_pseudo_code',{'procedure':'entry'})
        self.assertEqual(client.observed,[('open_binary',930),('list_procedures',930),('procedure_pseudo_code',300)])
        self.assertEqual(router.events[1]['phase'],'Ghidra ilk analiz')
        self.assertTrue(router.ghidra_initialized)

    def test_the_same_delay_would_fail_old_tool_budget(self):
        clock=SimpleNamespace(value=10.)
        with patch.object(mcp,'time',SimpleNamespace(monotonic=lambda:clock.value)):
            client=VirtualClient(clock,{'list_procedures':120})
            with self.assertRaises(mcp.McpTimeout) as raised:
                client.call('tools/call',{'name':'list_procedures'},timeout=90)
        self.assertEqual(raised.exception.limit,90)
        self.assertIn('list_procedures',str(raised.exception))

    def test_ghidra_timeout_is_named_and_retained_in_event(self):
        clock=SimpleNamespace(value=10.)
        with patch.object(mcp,'time',SimpleNamespace(monotonic=lambda:clock.value)):
            router=self.router(VirtualClient(clock,{'list_procedures':931}))
            with self.assertRaises(mcp.McpTimeout) as raised:router.execute('list_procedures',{})
        error=raised.exception
        self.assertIn('Ghidra ilk analiz / list_procedures',str(error))
        self.assertEqual(error.scope,'araç çağrısı');self.assertEqual(error.limit,930)
        self.assertEqual(router.events[-1]['timeout']['operation'],error.operation)
        self.assertEqual(router.events[-1]['error'],str(error))

    def test_global_limit_is_distinct_from_tool_limit(self):
        clock=SimpleNamespace(value=10.)
        with patch.object(mcp,'time',SimpleNamespace(monotonic=lambda:clock.value)):
            router=self.router(VirtualClient(clock,{'list_procedures':200},total=100))
            with self.assertRaises(mcp.McpTimeout) as raised:router.execute('list_procedures',{})
        self.assertEqual(raised.exception.scope,'toplam analiz')
        self.assertEqual(raised.exception.limit,100)
        self.assertIn('list_procedures',str(raised.exception))

    def test_failed_first_result_keeps_long_initial_budget(self):
        clock=SimpleNamespace(value=10.)
        with patch.object(mcp,'time',SimpleNamespace(monotonic=lambda:clock.value)):
            client=VirtualClient(clock,results={'list_procedures':{'isError':True}})
            router=self.router(client);router.execute('list_procedures',{})
            self.assertFalse(router.ghidra_initialized)
            client.results.clear();router.execute('list_procedures',{})
        self.assertEqual(client.observed[-1],('list_procedures',930))

    def test_default_and_overridden_backend_startup_are_aligned(self):
        for raw,seconds in [(None,930),('1200000',1230)]:
            with self.subTest(raw=raw),patch.dict(os.environ,{},clear=False):
                os.environ.pop('REA_GHIDRA_STARTUP_TIMEOUT_MS',None)
                if raw is not None:os.environ['REA_GHIDRA_STARTUP_TIMEOUT_MS']=raw
                client=mcp.McpClient(str(self.server),threading.Event(),time.monotonic()+3600)
                try:
                    self.assertEqual(client.ghidra_initial_timeout,seconds)
                    echo=client.call('echo_env',{},timeout=2)
                    self.assertEqual(echo['startup_ms'],raw or '900000')
                finally:client.close()

    def test_invalid_backend_override_does_not_launch_a_process(self):
        for raw in ['0','-1','abc','2147483648']:
            with self.subTest(raw=raw),patch.dict(os.environ,{'REA_GHIDRA_STARTUP_TIMEOUT_MS':raw}),patch.object(mcp.subprocess,'Popen') as popen:
                with self.assertRaises(ValueError):mcp.McpClient(str(self.server),threading.Event(),time.monotonic()+3600)
                popen.assert_not_called()

    def test_real_read_timeout_does_not_reset_on_stderr_activity(self):
        client=mcp.McpClient(str(self.server),threading.Event(),time.monotonic()+3600)
        try:
            with self.assertRaises(mcp.McpTimeout) as raised:
                client.call('tools/call',{'name':'list_procedures'},timeout=.12)
            self.assertIn('list_procedures',str(raised.exception))
            self.assertEqual(raised.exception.scope,'araç çağrısı')
            self.assertLess(raised.exception.elapsed,1)
        finally:client.close()
        self.assertIsNotNone(client.process.poll())

    def test_cancel_still_interrupts_long_wait_quickly(self):
        stopped=threading.Event();client=mcp.McpClient(str(self.server),stopped,time.monotonic()+3600)
        timer=threading.Timer(.12,stopped.set);timer.start();started=time.monotonic()
        try:
            with self.assertRaises(mcp.McpCancelled):client.call('tools/call',{'name':'list_procedures'},timeout=930)
            self.assertLess(time.monotonic()-started,1)
        finally:timer.cancel();client.close()
        self.assertIsNotNone(client.process.poll())

    def test_cancel_interrupts_backpressure_on_request_write(self):
        server=self.root/'no-reader';server.write_text('#!/usr/bin/env python3\nimport time\ntime.sleep(30)\n');server.chmod(0o755)
        stopped=threading.Event();client=mcp.McpClient(str(server),stopped,time.monotonic()+3600)
        try:
            while True:
                try:os.write(client.process.stdin.fileno(),b'x'*4096)
                except BlockingIOError:break
            timer=threading.Timer(.12,stopped.set);timer.start();started=time.monotonic()
            try:
                with self.assertRaises(mcp.McpCancelled):client.call('tools/call',{'name':'list_procedures'},timeout=930)
                self.assertLess(time.monotonic()-started,1)
            finally:timer.cancel()
        finally:client.close()
        self.assertIsNotNone(client.process.poll())

    def test_cloud_and_local_workers_get_long_total_budget(self):
        local=self.worker()
        store=SimpleNamespace(summary=lambda:{'active':'fixture'})
        cloud=CloudCopilotWorker(store,'test',[{'role':'user','content':'analyze'}],self.target,str(self.server))
        self.assertEqual(local.timeout,3600);self.assertEqual(cloud.timeout,3600)

    def test_auth_network_timeout_names_the_auth_step(self):
        store=SimpleNamespace(summary=lambda:{'active':'fixture'},token=lambda account:(_ for _ in ()).throw(TimeoutError('timed out')))
        worker=CloudCopilotWorker(store,'test',[{'role':'user','content':'analyze'}],self.target,str(self.server))
        worker.started=time.monotonic()
        with self.assertRaises(TimeoutError) as caught:worker.model_round([],[])
        error=worker.timeout_error(caught.exception)
        self.assertEqual(error.scope,'ağ bekleme');self.assertEqual(error.limit,15)
        self.assertIn('oturum doğrulaması',str(error))

    def test_global_budget_wins_when_socket_wait_is_clipped_by_total(self):
        worker=self.worker();worker.started=time.monotonic()-3601
        worker.note_wait('ChatGPT akışı / test',1)
        error=worker.timeout_error(TimeoutError('timed out'))
        self.assertEqual(error.scope,'toplam analiz');self.assertEqual(error.limit,3600)

    def test_worker_reports_phase_and_distinguishes_network_wait(self):
        worker=self.worker();worker.started=time.monotonic()-3601;worker.phase='Ghidra / list_procedures'
        with self.assertRaises(mcp.McpTimeout) as raised:worker.check()
        self.assertEqual(raised.exception.scope,'toplam analiz')
        self.assertIn('list_procedures',str(raised.exception))
        worker.started=time.monotonic()
        worker.note_wait('ChatGPT akışı / test',90)
        error=worker.timeout_error(TimeoutError('timed out'))
        self.assertEqual(error.scope,'ağ bekleme');self.assertEqual(error.limit,90)
        self.assertIn('ChatGPT akışı',str(error))
        self.assertIs(worker.timeout_error(raised.exception),raised.exception)


if __name__=='__main__':unittest.main(verbosity=2)

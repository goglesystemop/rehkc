"""Behaviour checks for staged discovery, cache validity and engine fallback."""
import hashlib
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'app'))
import rea_analysis as analysis
import rea_mcp as mcp


def pe_fixture(path, section=b'.text', data=None):
    payload=data if data is not None else (b'hello static fixture\0'+b'\x90'*512)[:512]
    raw=bytearray(512+len(payload));raw[:2]=b'MZ';struct.pack_into('<I',raw,0x3c,0x80)
    raw[0x80:0x84]=b'PE\0\0';struct.pack_into('<HH',raw,0x84,0x14c,1)
    struct.pack_into('<H',raw,0x94,224);struct.pack_into('<H',raw,0x98,0x10b)
    struct.pack_into('<I',raw,0xa8,0x1000);struct.pack_into('<I',raw,0xb4,0x400000)
    start=0x98+224;raw[start:start+8]=section.ljust(8,b'\0')[:8]
    struct.pack_into('<IIII',raw,start+8,len(payload),0x1000,len(payload),512)
    struct.pack_into('<I',raw,start+36,0x60000020);raw[512:]=payload;path.write_bytes(raw)


class StagedAnalysis(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.env=patch.dict(os.environ,{'REHKC_DATA_DIR':str(self.root/'state')});self.env.start()
        self.target=self.root/'target.exe';pe_fixture(self.target)
        self.calls=[]
    def tearDown(self):self.env.stop();self.temp.cleanup()
    def client(self, result=None):
        c=SimpleNamespace(binary=str(self.target),deadline=time.monotonic()+3600,
            ghidra_initial_timeout=930,stopped=threading.Event(),check=lambda deadline:None,opened=False,close=Mock())
        def call(method,params,**kwargs):
            self.calls.append(params['name'])
            if params['name']=='open_binary':return {'structuredContent':{'ok':True}}
            if isinstance(result,Exception):raise result
            return result or {'structuredContent':{'normalized_result':'int entry(void) { return 3; }','engine':'ghidra'}}
        c.call=call;return c
    def router(self,client=None):
        inventory={name:{} for name in mcp.SCHEMAS}
        inventory['open_binary']={'inputSchema':{'properties':{'provider_id':{}}}}
        with patch.object(mcp,'engine_identity',return_value='fixture-engine-v1'):
            return mcp.SelectedTargetTools(client or self.client(),self.target,inventory,lambda event:None)

    def test_preflight_detects_pe_and_packer_without_engine(self):
        pe_fixture(self.target,b'UPX1',bytes(range(256))*2)
        info=analysis.StaticAnalysis(self.target).preflight()
        self.assertEqual(info['architecture'],'x86');self.assertEqual(info['entry'],'0x401000')
        self.assertIn('section:UPX1',info['packer_indicators'])
        self.assertIn('high_entropy_executable:UPX1',info['packer_indicators'])
        self.assertEqual(info['sections'][0]['entropy_sample'],8)
    def test_rabin_json_envelopes_and_legacy_arrays(self):
        s=analysis.StaticAnalysis(self.target)
        for wrapped in (False,True):
            symbols=[{'name':'f','type':'FUNC','vaddr':0x401020}];entries=[{'vaddr':0x401000}]
            values=[{'symbols':symbols},{'entries':entries}] if wrapped else [symbols,entries]
            with patch.object(s,'executable',return_value='/rabin2'),patch.object(s,'command',side_effect=[json.dumps(v) for v in values]):
                functions=s.quick_functions()['structuredContent']['observed_result']
            self.assertEqual(functions,[{'name':'entry0','address':'0x401000'},{'name':'f','address':'0x401020'}])
    def test_truncated_or_out_of_bounds_pe_is_explicit(self):
        raw=bytearray(self.target.read_bytes());struct.pack_into('<I',raw,0x98+224+20,999999);self.target.write_bytes(raw)
        with self.assertRaisesRegex(ValueError,'sınır'):analysis.StaticAnalysis(self.target).preflight()
    def test_large_file_preflight_is_bounded(self):
        with self.target.open('ab') as f:f.truncate(160*1024**2)
        start=time.monotonic();info=analysis.StaticAnalysis(self.target).preflight()
        self.assertEqual(info['bytes'],160*1024**2);self.assertLess(time.monotonic()-start,2)
    def test_file_change_rejects_even_cached_result(self):
        r=self.router();r.execute('procedure_pseudo_code',{'procedure':'entry'});self.target.write_bytes(self.target.read_bytes()+b'change')
        with self.assertRaisesRegex(ValueError,'değişti'):r.execute('procedure_pseudo_code',{'procedure':'entry'})
    def test_expected_signature_prevents_old_digest_new_target_race(self):
        old=analysis.signature(self.target);self.target.write_bytes(self.target.read_bytes()+b'change')
        with self.assertRaises(ValueError):mcp.SelectedTargetTools(self.client(),self.target,{},lambda e:None,digest='old',expected_signature=old)
    def test_success_reused_across_sessions_without_ghidra_open(self):
        self.router().execute('procedure_pseudo_code',{'procedure':'0x401000'})
        r=self.router();result=r.execute('procedure_pseudo_code',{'procedure':'0x401000'})
        self.assertTrue(result['cache_hit']);self.assertTrue(r.events[-1]['cache_hit'])
        self.assertEqual(self.calls,['open_binary','procedure_pseudo_code'])
    def test_hash_and_engine_configuration_invalidate_cache(self):
        a=analysis.ResultCache('file1','engine1');a.put('code',{}, {'value':'one'})
        self.assertIsNone(analysis.ResultCache('file2','engine1').get('code',{}))
        self.assertIsNone(analysis.ResultCache('file1','engine2').get('code',{}))
        self.assertIsNone(a.get('code',{'procedure':'different'}))
    def test_cache_is_private_corruption_is_a_miss_and_disable_works(self):
        c=analysis.ResultCache('file','engine');c.put('code',{}, {'value':'ok'})
        p=c.path('code',{});self.assertEqual(p.stat().st_mode&0o777,0o600)
        self.assertEqual(c.get('code',{}),{'value':'ok'})
        with patch.dict(os.environ,{'REHKC_DISABLE_ANALYSIS_CACHE':'1'}):self.assertIsNone(c.get('code',{}))
        p.write_text('{broken');self.assertIsNone(c.get('code',{}))
    def test_expired_cache_is_a_miss(self):
        c=analysis.ResultCache('file','engine');c.put('x',{}, {'value':'ok'})
        os.utime(c.path('x',{}),(0,0));self.assertIsNone(c.get('x',{}))
    def test_invalid_model_arguments_never_reach_cache_or_process(self):
        r=self.router()
        for name,args in [('procedure_pseudo_code',{'procedure':'main','path':'/etc/passwd'}),('quick_functions',{'command':'pdc'}),('inspect_with_objdump',{'operation':'symbols','symbol':'main'})]:
            with self.assertRaises(ValueError):r.execute(name,args)
        self.assertEqual(self.calls,[])
    def test_failure_switches_engine_and_preserves_primary_reason(self):
        r=self.router(self.client(RuntimeError('provider unavailable')))
        with patch.object(r.analysis,'retdec',return_value=analysis.evidence('retdec','procedure_pseudo_code','int f() {return 1;}', ['selected range'])):
            result=r.execute('procedure_pseudo_code',{'procedure':'0x401000'})
        v=result['structuredContent'];self.assertEqual(v['engine'],'retdec');self.assertTrue(v['partial'])
        self.assertIn('provider unavailable',v['fallback_from'][0]['error'])
        self.assertIsNone(r.cache.get('procedure_pseudo_code',{'procedure':'0x401000'}))
        self.assertEqual(r.events[-1]['engine'],'retdec')
    def test_failed_retdec_uses_radare_with_both_errors_visible(self):
        s=analysis.StaticAnalysis(self.target)
        with patch.object(s,'retdec',side_effect=ValueError('no code')),patch.object(s,'assembly',return_value=analysis.evidence('radare2','procedure_pseudo_code','void f() {}',['approximate'])):
            v=s.fallback('procedure_pseudo_code',{'procedure':'0x401000'},'Ghidra error')['structuredContent']
        self.assertEqual([e['engine'] for e in v['fallback_from']],['ghidra','retdec']);self.assertEqual(v['engine'],'radare2')
    def test_alternative_failure_is_not_retried_recursively(self):
        r=self.router(self.client(TimeoutError('Ghidra tool timeout')))
        with patch.object(r.analysis,'fallback',side_effect=TimeoutError('r2 timeout')) as fallback:
            with self.assertRaisesRegex(TimeoutError,'r2 timeout'):r.execute('procedure_pseudo_code',{'procedure':'main'})
        self.assertEqual(fallback.call_count,1)
    def test_open_timeout_can_fallback(self):
        c=self.client();c.call=Mock(side_effect=TimeoutError('open timeout'));r=self.router(c)
        with patch.object(r.analysis,'fallback',return_value=analysis.evidence('radare2','list_procedures',[],['partial'])) as fallback:
            r.execute('list_procedures',{})
        self.assertEqual(fallback.call_count,1)
    def test_overall_timeout_and_cancel_never_fallback(self):
        for failure in [mcp.McpCancelled('stop'),mcp.McpTimeout('global','toplam analiz',1,2)]:
            c=self.client();r=self.router(c);c.check=Mock(side_effect=failure)
            with patch.object(r.analysis,'fallback') as fallback:
                with self.assertRaises(type(failure)):r.execute('procedure_pseudo_code',{'procedure':'main'})
                fallback.assert_not_called()
    def test_native_timeout_and_cancel_are_responsive(self):
        s=analysis.StaticAnalysis(self.target)
        with self.assertRaises(TimeoutError):s.command([sys.executable,'-c','import time;time.sleep(20)'],timeout=.1)
        stopped=threading.Event()
        def check():
            if stopped.is_set():raise mcp.McpCancelled('stop')
        s.check=check;timer=threading.Timer(.1,stopped.set);timer.start();start=time.monotonic()
        try:
            with self.assertRaises(mcp.McpCancelled):s.command([sys.executable,'-c','import time;time.sleep(20)'])
        finally:timer.cancel()
        self.assertLess(time.monotonic()-start,1)
    def test_native_child_has_real_memory_cpu_and_core_limits(self):
        s=analysis.StaticAnalysis(self.target)
        raw=s.command([sys.executable,'-c','import resource,json; print(json.dumps([resource.getrlimit(resource.RLIMIT_AS),resource.getrlimit(resource.RLIMIT_CPU),resource.getrlimit(resource.RLIMIT_CORE)]))'],timeout=5)
        memory,cpu,core=json.loads(raw)
        self.assertLessEqual(memory[1],4*1024**3);self.assertGreaterEqual(memory[1],256*1024**2)
        self.assertEqual(cpu,[8,8]);self.assertEqual(core,[0,0])
    def test_low_memory_skips_ghidra_before_open(self):
        r=self.router()
        with patch.object(mcp,'memory_policy',return_value={'available_bytes':128*1024**2}),patch.object(r.analysis,'fallback',return_value=analysis.evidence('radare2','list_procedures',[],['partial'])) as fallback:
            r.execute('list_procedures',{})
        self.assertEqual(self.calls,[]);fallback.assert_called_once()
    def test_retdec_selects_a_bounded_range_without_shell(self):
        s=analysis.StaticAnalysis(self.target);observed=[]
        def command(args,**kwargs):
            observed.extend(args);Path(args[args.index('-o')+1]).write_text('int f(void) { return 3; }');return ''
        with patch.object(s,'executable',return_value='/retdec'),patch.object(s,'command',side_effect=command):
            result=s.retdec('0x401000')
        self.assertIn('--select-decode-only',observed);self.assertIn('0x401000-0x4011ff',observed)
        self.assertTrue(result['structuredContent']['partial'])
        with self.assertRaises(ValueError):s.retdec('main;!touch bad')
    def test_empty_ghidra_code_tries_another_engine(self):
        r=self.router(self.client({'structuredContent':{'normalized_result':None}}))
        with patch.object(r.analysis,'fallback',return_value=analysis.evidence('retdec','procedure_pseudo_code','int f() {}')) as fallback:r.execute('procedure_pseudo_code',{'procedure':'entry'})
        fallback.assert_called_once()

if __name__=='__main__':unittest.main(verbosity=2)

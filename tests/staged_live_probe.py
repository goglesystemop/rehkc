"""Real engines, fresh MCP sessions and persistent results on a never-executed target."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import threading
import time

p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--package',required=True,type=Path)
p.add_argument('--engine',required=True)
p.add_argument('--target',required=True,type=Path)
p.add_argument('--procedure',required=True)
p.add_argument('--report',required=True,type=Path)
p.add_argument('--retdec-target',type=Path)
a=p.parse_args()
sys.path.insert(0,str(a.package.resolve()/'app'))
import rehkc_boot
rehkc_boot.tool_environment()
from rea_analysis import StaticAnalysis,observation
from rea_mcp import McpClient,SelectedTargetTools
report={'runs':[],'target_executed':False}
before=hashlib.sha256(a.target.read_bytes()).hexdigest()
service=StaticAnalysis(a.target)
start=time.monotonic();report['preflight']=service.preflight();report['preflight_seconds']=time.monotonic()-start
for repeat in range(2):
    client=McpClient(a.engine,threading.Event(),time.monotonic()+1800)
    try:
        _,inventory=client.start();router=SelectedTargetTools(client,a.target,inventory,lambda event:None)
        quick=router.execute('quick_functions',{})
        assert observation(quick)['engine']=='radare2/rabin2'
        start=time.monotonic();result=router.execute('procedure_pseudo_code',{'procedure':a.procedure})
        seconds=time.monotonic()-start
        value=observation(result)
        assert isinstance(value.get('normalized_result',value.get('observed_result')),str)
        if repeat:assert result.get('cache_hit'),result
        report['runs'].append({'repeat':repeat,'seconds':seconds,'cache_hit':bool(result.get('cache_hit')),
                               'engine':value.get('engine',value.get('provider'))})
    finally:client.close()
# Force a provider error, not a long artificial wait; fallback motors remain real.
os.environ['REHKC_DATA_DIR']=os.environ['REHKC_DATA_DIR']+'-fallback'
client=McpClient(a.engine,threading.Event(),time.monotonic()+600)
try:
    _,inventory=client.start();original=client.call
    def unavailable(method,params,**kwargs):
        if params.get('name')=='open_binary':
            return {'isError':True,'structuredContent':{'ok':False,'error':{'code':'provider_unavailable','message':'Controlled primary failure'}}}
        return original(method,params,**kwargs)
    client.call=unavailable;router=SelectedTargetTools(client,a.target,inventory,lambda event:None)
    start=time.monotonic();value=observation(router.execute('procedure_pseudo_code',{'procedure':a.procedure}))
    assert value['engine'] in ('retdec','radare2'),value
    report['fallback']={'engine':value['engine'],'seconds':time.monotonic()-start,
                        'limitations':value['limitations'],'failures':value['fallback_from']}
finally:client.close()
report['radare_assembly_engine']=observation(service.assembly(a.procedure))['engine']
if a.retdec_target:
    # A well-formed generated ELF gives RetDec an independent positive test.
    # Merely accepting Radare2 fallback would hide a broken RetDec adapter.
    retdec=StaticAnalysis(a.retdec_target).retdec('0x401000')
    value=observation(retdec)
    assert value['engine']=='retdec' and value['observed_result'].strip()
    report['retdec_positive_test']=True
# Different operations must reuse the same imported Program, with result-cache
# reads disabled so a cached response cannot conceal a broken session lease.
from rea_analysis_session import AnalysisSessionPool
from rea_analysis import digest_file
pool=AnalysisSessionPool();warm=[];client=None
try:
    for name,args in [('procedure_pseudo_code',{'procedure':a.procedure}),('procedure_assembly',{'procedure':a.procedure})]:
        now=time.monotonic();lease=pool.acquire(a.engine,a.target,digest_file(a.target),threading.Event(),now+600,now)
        client=lease.client;router=None
        try:
            router=SelectedTargetTools(client,a.target,lease.inventory,lambda event:None,read_cache=False)
            result=router.execute(name,args)
            assert observation(result).get('normalized_result') is not None
            warm.append({'operation':name,'session_reused':lease.reused,'pid':client.process.pid,
                         'open_binary_called':any(e['tool']=='open_binary' for e in router.events)})
        finally:lease.release(healthy=router is not None and router.primary_failed is None)
    assert warm[1]['session_reused'] and not warm[1]['open_binary_called']
    assert warm[0]['pid']==warm[1]['pid']
finally:pool.close()
assert client.process.poll() is not None
report['warm_session']={'runs':warm,'closed_after_test':True}
report['target_unchanged']=hashlib.sha256(a.target.read_bytes()).hexdigest()==before
assert report['target_unchanged']
report['ok']=True
a.report.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
print(json.dumps(report,ensure_ascii=False,indent=2))

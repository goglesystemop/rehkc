"""Repeated model requests preserve real evidence without spending another tool call."""
import json,sys,tempfile,threading,time,unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'app'))
import rea_copilot as copilot
import rea_mcp as mcp

class Client:
    instances=[]
    def __init__(self,binary,stopped,deadline,started=None):
        self.stopped=stopped;self.deadline=deadline;self.ghidra_initial_timeout=930;self.calls=[];self.opened=False
        self.__class__.instances.append(self)
    def check(self,deadline):
        if self.stopped.is_set():raise mcp.McpCancelled('cancelled')
    def start(self):
        inventory={name:{} for name in mcp.SCHEMAS}
        inventory['open_binary']={'inputSchema':{'properties':{'provider_id':{}}}}
        return {},inventory
    def call(self,method,params,**kwargs):
        self.calls.append((params['name'],params['arguments']))
        if params['name']=='open_binary':return {'structuredContent':{'ok':True}}
        if params['arguments'].get('procedure')=='bad':raise RuntimeError('real fixture failure')
        return {'structuredContent':{'ok':True,'provider':{'name':'fixture'},'normalized_result':'real fixture observation'}}
    def close(self):pass

def call(name,arguments,identifier):
    return {'id':identifier,'type':'function','function':{'name':name,'arguments':json.dumps(arguments) if not isinstance(arguments,str) else arguments}}

class RepeatedRequests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.path=Path(self.tmp.name)/'target';self.path.write_bytes(b'fixture, never executed');Client.instances=[]
    def tearDown(self):self.tmp.cleanup()
    def run_worker(self,rounds,callback=None):
        w=copilot.McpCopilotWorker('http://localhost:1234','','fixture',[{'role':'user','content':'analyze'}],self.path,'unused',context_limit=20000)
        record=[];failures=[];requests=[];w.run_recorded.connect(record.append);w.failed.connect(failures.append)
        answers=iter(rounds)
        def model(messages,tools,require_tools=False):
            requests.append({'tools':tools,'messages':messages,'required':require_tools})
            if callback:callback(w,len(requests))
            answer,calls=next(answers)
            if not calls:w.pieces.append(answer)
            return answer,calls
        with patch.object(copilot,'McpClient',Client),patch.object(w,'model_round',side_effect=model):w.run()
        self.assertTrue(record)
        return record[0],failures,requests,Client.instances[-1]
    def test_duplicate_only_round_forces_final_without_reopening_engine(self):
        c=lambda n:call('procedure_pseudo_code',{'procedure':'entry'},n)
        r,errors,requests,client=self.run_worker([('',[c('a')]),('',[c('b')]),('observed',[])])
        self.assertFalse(errors);self.assertEqual(r['status'],'Tamamlandı')
        self.assertEqual([name for name,args in client.calls],['open_binary','procedure_pseudo_code'])
        self.assertTrue(requests[1]['tools']);self.assertFalse(requests[2]['tools']);self.assertFalse(requests[2]['required'])
        self.assertEqual(len(r['reused_tool_requests']),1)
        original=requests[1]['messages'][-1]['content'];reused=requests[2]['messages'][-1]['content'];self.assertEqual(original,reused)
    def test_failures_are_reused_without_claiming_success(self):
        c=lambda n:call('procedure_pseudo_code',{'procedure':'bad'},n)
        r,errors,requests,client=self.run_worker([('',[c('a')]),('',[c('b')]),('limited',[])])
        self.assertFalse(errors);self.assertEqual(r['status'],'Araç kanıtı yok')
        self.assertEqual(sum(name=='procedure_pseudo_code' for name,args in client.calls),1)
        raw=json.loads(requests[-1]['messages'][-1]['content']);self.assertFalse(raw['success']);self.assertIn('real fixture failure',raw['error'])
    def test_same_batch_deduplicates_but_different_arguments_execute(self):
        r,errors,requests,client=self.run_worker([('',[call('procedure_pseudo_code',{'procedure':'one'},'a'),call('procedure_pseudo_code',{'procedure':'one'},'b'),call('procedure_pseudo_code',{'procedure':'two'},'c')]),('done',[])])
        self.assertFalse(errors);self.assertEqual([args['procedure'] for name,args in client.calls if name=='procedure_pseudo_code'],['one','two'])
        self.assertEqual(len(r['reused_tool_requests']),1)
    def test_invalid_json_is_replayed_as_error_not_retried(self):
        c=lambda n:call('procedure_pseudo_code','{invalid',n)
        r,errors,requests,client=self.run_worker([('',[c('a')]),('',[c('b')]),('limited',[])])
        self.assertFalse(errors);self.assertFalse(client.calls);self.assertEqual(r['status'],'Araç kanıtı yok')
        self.assertIn('JSON',requests[-1]['messages'][-1]['content'])
    def test_target_change_before_reuse_aborts(self):
        def mutate(w,index):
            if index==2:self.path.write_bytes(b'changed')
        c=lambda n:call('procedure_pseudo_code',{'procedure':'entry'},n)
        r,errors,requests,client=self.run_worker([('',[c('a')]),('',[c('b')])],mutate)
        self.assertTrue(errors);self.assertIn('değişti',errors[0]);self.assertFalse(r['reused_tool_requests'])
    def test_cancel_before_reuse_aborts(self):
        def cancel(w,index):
            if index==2:w.cancel()
        c=lambda n:call('procedure_pseudo_code',{'procedure':'entry'},n)
        r,errors,requests,client=self.run_worker([('',[c('a')]),('',[c('b')])],cancel)
        self.assertEqual(r['status'],'Durduruldu');self.assertFalse(r['reused_tool_requests'])
    def test_new_question_can_retry_the_same_request(self):
        for _ in range(2):
            r,errors,requests,client=self.run_worker([('',[call('procedure_pseudo_code',{'procedure':'entry'},'a')]),('done',[])])
            self.assertFalse(errors);self.assertEqual(sum(n=='procedure_pseudo_code' for n,a in client.calls),1)
    def test_parameter_order_does_not_reexecute_identical_request(self):
        a=call('inspect_with_objdump',{'operation':'disassemble','symbol':'entry'},'a')
        b=call('inspect_with_objdump',{'symbol':'entry','operation':'disassemble'},'b')
        r,errors,requests,client=self.run_worker([('',[a,b]),('done',[])])
        self.assertFalse(errors);self.assertEqual(len(client.calls),1);self.assertEqual(len(r['reused_tool_requests']),1)
    def test_new_evidence_in_a_mixed_round_does_not_force_early_final(self):
        c=lambda name,n:call('procedure_pseudo_code',{'procedure':name},n)
        r,errors,requests,client=self.run_worker([('',[c('one','a')]),('',[c('one','b'),c('two','c')]),('done',[])])
        self.assertFalse(errors);self.assertTrue(requests[-1]['tools']);self.assertEqual(len(r['reused_tool_requests']),1)

if __name__=='__main__':unittest.main(verbosity=2)

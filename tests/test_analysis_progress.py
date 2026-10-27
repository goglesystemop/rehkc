"""Progress is elapsed time and observed transport activity, never invented percent."""
import json
from pathlib import Path
import sys
import tempfile
import threading
import time
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'app'))
from rea_analysis import StaticAnalysis
from rea_mcp import McpClient

class AnalysisProgress(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.target=self.root/'data';self.target.write_bytes(b'not executed')
    def tearDown(self):self.tmp.cleanup()
    def test_native_wait_reports_elapsed_and_actual_output_activity(self):
        events=[];service=StaticAnalysis(self.target,progress=events.append)
        text=service.command([sys.executable,'-c','import time;print("start",flush=True);time.sleep(1.2);print("done")'],timeout=5)
        self.assertIn('done',text);self.assertEqual(events[0]['status'],'running')
        self.assertTrue(any(e['elapsed']>=1 and e['last_activity_seconds'] is not None for e in events))
        self.assertEqual(events[-1]['status'],'completed');self.assertNotIn('percent',events[-1])
    def test_mcp_wait_reports_activity_without_resetting_the_budget(self):
        server=self.root/'server'
        server.write_text('#!/usr/bin/env python3\nimport json,sys,time\nfor line in sys.stdin:\n r=json.loads(line)\n if "id" not in r:continue\n print("working",file=sys.stderr,flush=True);time.sleep(1.2)\n print(json.dumps({"id":r["id"],"result":{"ok":True}}),flush=True)\n')
        server.chmod(0o755);events=[]
        client=McpClient(str(server),threading.Event(),time.monotonic()+10);client.progress=events.append
        try:result=client.call('fixture',{},timeout=3)
        finally:client.close()
        self.assertTrue(result['ok']);self.assertTrue(any(e['elapsed']>=1 and e['last_activity_seconds'] is not None for e in events))
        self.assertTrue(all(e['limit_seconds']==3 for e in events));self.assertEqual(events[-1]['status'],'completed')
    def test_progress_callback_failure_cannot_abort_native_analysis(self):
        def failed(event):raise RuntimeError('view gone')
        text=StaticAnalysis(self.target,progress=failed).command([sys.executable,'-c','print("evidence")'])
        self.assertEqual(text.strip(),'evidence')
    def test_malformed_result_remains_pending_for_session_discard(self):
        server=self.root/'malformed'
        server.write_text('#!/usr/bin/env python3\nimport json,sys\nfor line in sys.stdin:\n r=json.loads(line)\n if "id" in r:print(json.dumps({"id":r["id"],"result":None}),flush=True)\n')
        server.chmod(0o755);client=McpClient(str(server),threading.Event(),time.monotonic()+5)
        try:
            with self.assertRaisesRegex(ValueError,'sonuç nesnesi'):client.call('fixture',{},timeout=1)
            self.assertIsNotNone(client.pending)
        finally:client.close()

if __name__=='__main__':unittest.main(verbosity=2)

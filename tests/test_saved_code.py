"""Restored code must retain provenance and pass an asynchronous target digest check."""
import copy,hashlib,json,os,sys,threading,time,unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'app'))
os.environ['QT_QPA_PLATFORM']='offscreen'
import test_code_export as support
from rea_code_export import code_record
from rea_saved_code import SavedCodeVerifier,text_digest,validate_saved_code

class SavedValidation(unittest.TestCase):
    def sample(self):
        r=support.result();record=code_record(r);panes={'decomp':'visible code','disasm':''}
        return {'decomp':{'view_sha256':text_digest(panes['decomp']),'record':record}},r['target'],panes
    def test_legacy_session_needs_no_code_metadata(self):
        self.assertEqual(validate_saved_code({},'',{}),{})
    def test_valid_record_preserves_engine_errors_and_old_analysis_timestamp(self):
        saved,target,panes=self.sample();saved['decomp']['record']['fallback_from']=[{'engine':'failed-engine','error':'original failure'}]
        validated=validate_saved_code(saved,target,panes)
        self.assertEqual(validated,saved);self.assertIsNot(validated,saved)
    def test_changed_view_hash_or_target_is_rejected(self):
        for case in ('view','target','digest','field','kind','bool'):
            saved,target,panes=self.sample();record=saved['decomp']['record']
            if case=='view':panes['decomp']='different'
            elif case=='target':target='/different'
            elif case=='digest':record['target_sha256']='not a digest'
            elif case=='field':record['api_key']='should not export'
            elif case=='kind':record['kind']='assembly'
            else:record['cache_hit']='false'
            with self.assertRaises(ValueError,msg=case):validate_saved_code(saved,target,panes)
    def test_huge_or_malformed_limitations_are_rejected(self):
        for value in ('not a list',['x'*8193],['x']*101):
            saved,target,panes=self.sample();saved['decomp']['record']['limitations']=value
            with self.assertRaises(ValueError):validate_saved_code(saved,target,panes)
    def test_verification_rejects_target_over_analysis_size_limit(self):
        import tempfile
        with tempfile.TemporaryDirectory() as folder:
            target=Path(folder)/'large'
            with target.open('wb') as stream:stream.truncate(512*1024*1024+1)
            worker=SavedCodeVerifier(str(target),{})
            with self.assertRaisesRegex(ValueError,'512 MiB'):worker.analyze()

class SavedCodeUi(unittest.TestCase):
    @classmethod
    def setUpClass(cls):support.ExportUi.setUpClass.__func__(cls)
    setUp=support.ExportUi.setUp
    tearDown=support.ExportUi.tearDown
    export=support.ExportUi.export
    def save(self):
        r=support.result();r['target']=str(self.target);r['target_sha256']=hashlib.sha256(self.target.read_bytes()).hexdigest()
        self.w._on_tool_completed('adaptive',json.dumps(r))
        self.path=self.root/'saved.rea.json';self.w._write_session(str(self.path));return json.loads(self.path.read_text())
    def wait(self):
        end=time.monotonic()+5
        while time.monotonic()<end:
            self.app.processEvents()
            if self.w.current_worker is None or not self.w.current_worker.isRunning():
                for _ in range(5):self.app.processEvents();time.sleep(.002)
                return
            time.sleep(.002)
        raise TimeoutError('test worker did not finish')
    def test_round_trip_verifies_and_exports_without_motor_reanalysis(self):
        original=self.save()['code_exports']['decomp']['record'];self.w.tab_decomp.clear()
        with patch('rea_saved_code.StaticAnalysis.command',side_effect=AssertionError('must not run a motor')):
            self.assertTrue(self.w._load_session(str(self.path),confirm=False));self.assertNotIn(self.w.tab_decomp,self.w._code_exports);self.wait()
        self.assertEqual(self.w._code_exports[self.w.tab_decomp][1],original)
        self.w.tabs.setCurrentWidget(self.w.tab_decomp);ok,_=self.export();self.assertTrue(ok)
        exported=json.loads((self.root/'code.json').read_text());self.assertEqual(exported['analysis_completed_at'],original['analysis_completed_at']);self.assertEqual(exported['engine_version'],'12.1.4')
    def test_same_size_and_mtime_with_changed_contents_cannot_restore_export(self):
        data=self.save();stat=self.target.stat();self.target.write_bytes(b'X'+self.target.read_bytes()[1:]);os.utime(self.target,ns=(stat.st_atime_ns,stat.st_mtime_ns))
        self.assertTrue(self.w._load_session(str(self.path),confirm=False));self.wait()
        self.assertNotIn(self.w.tab_decomp,self.w._code_exports)
        self.assertEqual(self.w.tab_decomp.toPlainText(),data['panes']['decomp'])
    def test_missing_target_keeps_view_without_enabling_export(self):
        data=self.save();self.target.unlink();self.assertTrue(self.w._load_session(str(self.path),confirm=False))
        self.assertEqual(self.w.tab_decomp.toPlainText(),data['panes']['decomp']);self.assertNotIn(self.w.tab_decomp,self.w._code_exports)
    def test_old_session_without_metadata_still_loads(self):
        data=self.save();data.pop('code_exports');self.path.write_text(json.dumps(data));self.assertTrue(self.w._load_session(str(self.path),confirm=False));self.assertNotIn(self.w.tab_decomp,self.w._code_exports)
    def test_corrupt_metadata_does_not_modify_open_session(self):
        data=self.save();data['code_exports']['decomp']['view_sha256']='bad';self.path.write_text(json.dumps(data));self.w.tab_decomp.setPlainText('keep this')
        with patch.object(self.gui.QMessageBox,'warning') as warning:self.assertFalse(self.w._load_session(str(self.path),confirm=False));self.assertTrue(warning.called)
        self.assertEqual(self.w.tab_decomp.toPlainText(),'keep this')
    def test_pending_verification_survives_save_and_changed_view_is_not_rebound(self):
        self.save();started=threading.Event();release=threading.Event()
        import rea_saved_code
        original=rea_saved_code.digest_file
        def delayed(*args,**kwargs):started.set();release.wait(3);return original(*args,**kwargs)
        with patch.object(rea_saved_code,'digest_file',side_effect=delayed):
            try:
                self.assertTrue(self.w._load_session(str(self.path),confirm=False));self.assertTrue(started.wait(1))
                self.assertIn('decomp',self.w._session_snapshot()['code_exports'])
                self.w.tab_decomp.setPlainText('new view');release.set();self.wait()
            finally:release.set();self.wait()
        self.assertNotIn(self.w.tab_decomp,self.w._code_exports)
    def test_cancelled_verification_cannot_enable_export(self):
        self.save();started=threading.Event();release=threading.Event()
        import rea_saved_code
        original=rea_saved_code.digest_file
        def delayed(*args,**kwargs):started.set();release.wait(3);return original(*args,**kwargs)
        with patch.object(rea_saved_code,'digest_file',side_effect=delayed):
            try:
                self.assertTrue(self.w._load_session(str(self.path),confirm=False));self.assertTrue(started.wait(1));self.w.current_worker.cancel();release.set();self.wait()
            finally:release.set();self.wait()
        self.assertNotIn(self.w.tab_decomp,self.w._code_exports)
    def test_target_change_discards_queued_verification(self):
        self.save();self.assertTrue(self.w._load_session(str(self.path),confirm=False));self.w.set_target_file('/usr/bin/true');self.wait()
        self.assertNotIn(self.w.tab_decomp,self.w._code_exports)

if __name__=='__main__':unittest.main(verbosity=2)

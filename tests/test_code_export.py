"""Code exports retain evidence, selection and stale-target protection."""
import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'app'))
os.environ['QT_QPA_PLATFORM'] = 'offscreen'
from rea_code_export import code_record, render_code


def result():
    return {'target': '/tmp/example.exe', 'target_sha256': 'a'*64, 'procedure': '0x401000',
            'analysis_completed_at': '2026-10-27T12:00:00+00:00',
            'structuredContent': {'provider': {'name': 'Ghidra', 'version': '12.1.4'},
                                  'normalized_result': 'int test() {\n  return 42;\n}', 'limitations': ['Types inferred.']}}


class CodeExport(unittest.TestCase):
    def test_full_json_retains_code_motor_hash_and_limitations(self):
        data = json.loads(render_code(code_record(result()), file_format='json'))
        self.assertEqual(data['engine_version'], '12.1.4')
        self.assertEqual(data['code'], result()['structuredContent']['normalized_result'])
        self.assertEqual(data['target_sha256'], 'a'*64)
        self.assertIn('Types inferred.', data['limitations'])
        self.assertEqual(data['scope'], 'complete_result')
        self.assertEqual(data['analysis_completed_at'], result()['analysis_completed_at'])
    def test_selection_does_not_mutate_record(self):
        record = code_record(result()); original = copy.deepcopy(record)
        data = json.loads(render_code(record, 'return 42;', 'json'))
        self.assertEqual(data['code'], 'return 42;'); self.assertEqual(data['scope'], 'selection')
        self.assertEqual(record, original); self.assertGreater(len(data['limitations']), len(record['limitations']))
    def test_alternative_engine_packers_and_cache_survive(self):
        r = result(); r['cache_hit'] = True; r['preflight'] = {'packer_indicators': ['UPX']}
        r['structuredContent'] = {'engine': 'radare2-pdc', 'observed_result': 'return x;',
            'limitations': ['Approximate.'], 'fallback_from': [{'engine': 'ghidra', 'error': 'timed out\nfull detail'}]}
        record = code_record(r)
        self.assertTrue(record['partial']); self.assertTrue(record['cache_hit'])
        self.assertEqual(record['fallback_from'][0]['error'], 'timed out\nfull detail')
        self.assertEqual(record['engine_version'], 'bilinmiyor')
        self.assertIn('UPX', render_code(record))
    def test_markdown_fence_cannot_be_closed_by_recovered_code(self):
        r = result(); r['structuredContent']['normalized_result'] = '```\n````\ncode'
        text = render_code(code_record(r)); self.assertIn('`````c\n```\n````\ncode\n`````', text)
    def test_only_allowlisted_metadata_is_exported(self):
        r = result(); r['api_key'] = 'SECRET'; r['chat_history'] = ['PRIVATE']
        text = render_code(code_record(r)); self.assertNotIn('SECRET', text); self.assertNotIn('PRIVATE', text)
    def test_missing_hash_engine_or_code_is_rejected(self):
        for change in ('hash', 'engine', 'code'):
            r = result()
            if change == 'hash': r['target_sha256'] = ''
            elif change == 'engine': r['structuredContent'].pop('provider')
            else: r['structuredContent']['normalized_result'] = {'not': 'code'}
            with self.assertRaises(ValueError): code_record(r)
    def test_plain_text_keeps_unicode(self):
        self.assertIn('Türkçe\nç', render_code(code_record(result()), 'Türkçe\nç', 'txt'))


class ExportUi(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from PyQt5.QtWidgets import QApplication
        cls.app = QApplication.instance() or QApplication([])
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.root = Path(self.tmp.name)
        self.env = patch.dict(os.environ, {'REHKC_CONFIG_DIR': str(self.root/'config'), 'REHKC_DATA_DIR': str(self.root/'data')})
        self.env.start()
        import rea_gui
        self.gui = rea_gui
        self.refresh = patch.object(rea_gui.ReaMainWindow, '_refresh_models'); self.refresh.start()
        self.catalog = patch.object(rea_gui.ReaMainWindow, '_refresh_command_catalog'); self.catalog.start()
        self.w = rea_gui.ReaMainWindow(); self.w.autosave_timer.stop(); self.w.memory_timer.stop()
        self.target = self.root/'sample.exe'; self.target.write_bytes(b'MZ-not-executed')
        self.w.set_target_file(str(self.target)); self.app.processEvents()
    def tearDown(self):
        self.w.close(); self.app.processEvents(); self.refresh.stop(); self.catalog.stop(); self.env.stop(); self.tmp.cleanup()
    def load(self):
        r = result(); r['target'] = str(self.target)
        self.w._on_tool_completed('adaptive', json.dumps(r)); return r
    def export(self, name='code.json', callback=None):
        def dialog(*args):
            if callback: callback()
            return str(self.root/name), 'JSON (*.json)'
        with patch.object(self.gui.QFileDialog, 'getSaveFileName', side_effect=dialog), patch.object(self.gui.QMessageBox, 'warning') as warning:
            return self.w._export_code_dialog(), warning
    def test_selection_and_json_extension_and_private_permissions(self):
        self.load(); editor = self.w.tab_decomp
        cursor = editor.document().find('return 42;'); editor.setTextCursor(cursor)
        ok, _ = self.export('selected')
        self.assertTrue(ok); path = self.root/'selected.json'; data = json.loads(path.read_text())
        self.assertEqual(data['code'], 'return 42;'); self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        menu = self.w._build_selection_menu(editor, 'decomp')
        self.assertTrue(next(a for a in menu.actions() if a.objectName() == 'export_code').isEnabled()); menu.deleteLater()
    def test_full_result_omits_display_wrapper_and_cancel_creates_nothing(self):
        self.load(); ok, _ = self.export(); self.assertTrue(ok)
        self.assertEqual(json.loads((self.root/'code.json').read_text())['code'], result()['structuredContent']['normalized_result'])
        with patch.object(self.gui.QFileDialog, 'getSaveFileName', return_value=('', '')):
            self.assertFalse(self.w._export_code_dialog())
    def test_file_changed_or_target_switched_cannot_export_old_result(self):
        self.load(); self.target.write_bytes(b'changed')
        self.assertFalse(self.w._export_code_dialog()); self.assertFalse((self.root/'code.json').exists())
        self.w.set_target_file('/usr/bin/true'); self.assertFalse(self.w._export_code_dialog())
    def test_new_editor_content_invalidates_provenance(self):
        self.load(); self.w.tab_decomp.setPlainText('analysis failed')
        self.assertFalse(self.w._export_code_dialog())
    def test_target_change_while_dialog_open_is_rejected(self):
        self.load(); ok, warning = self.export(callback=lambda: self.target.write_bytes(b'changed'))
        self.assertFalse(ok); self.assertTrue(warning.called); self.assertFalse((self.root/'code.json').exists())
    def test_target_hardlink_cannot_be_overwritten(self):
        os.link(self.target, self.root/'alias.json'); self.load(); original = self.target.read_bytes()
        ok, warning = self.export('alias.json'); self.assertFalse(ok); self.assertTrue(warning.called)
        self.assertEqual(self.target.read_bytes(), original)
    def test_write_failure_leaves_no_partial_export(self):
        self.load()
        with patch.object(self.gui, 'atomic_private_write', side_effect=OSError('disk full')):
            ok, warning = self.export()
        self.assertFalse(ok); self.assertTrue(warning.called); self.assertFalse((self.root/'code.json').exists())

if __name__ == '__main__': unittest.main(verbosity=2)

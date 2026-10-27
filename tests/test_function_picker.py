"""Filtering preserves exact observed addresses and does not invent functions."""
import os,sys,unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'app'))
os.environ['QT_QPA_PLATFORM']='offscreen'
from PyQt5.QtWidgets import QApplication,QDialog
from rea_function_picker import FunctionPickerDialog,function_rows
import test_code_export as support

class FunctionPicker(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.app=QApplication.instance() or QApplication([])
    def test_addresses_are_validated_sorted_and_aliases_retained(self):
        rows=function_rows([{'name':'two','address':'0x20'},{'name':'entry','address':'0x000A'},{'name':'alias','address':'0xa'},{'address':'shell; rm -f x'},{'address':5},None])
        self.assertEqual([r['address'] for r in rows],['0xa','0x20']);self.assertIn('alias',rows[0]['name'])
        with self.assertRaises(ValueError):function_rows('not inventory')
    def test_large_input_is_bounded(self):
        self.assertEqual(len(function_rows([{'address':hex(i)} for i in range(2000)])),1032)
    def test_filtering_by_name_and_address_selects_real_row(self):
        d=FunctionPickerDialog([{'name':'Helper','address':'0x20'},{'name':'other','address':'0x30'}])
        self.assertEqual(d.procedure(),'0x20');d.search.setText('HELP');self.assertEqual(d.procedure(),'0x20')
        d.search.setText('0x30');self.assertEqual(d.procedure(),'0x30')
        d.search.setText('no match');self.assertIsNone(d.procedure());self.assertFalse(d.decompile.isEnabled())
        d.accept();self.assertNotEqual(d.result(),QDialog.Accepted)
        d.search.clear();self.assertTrue(d.decompile.isEnabled());d.close()
    def test_empty_inventory_has_no_actionable_selection(self):
        d=FunctionPickerDialog([]);self.assertIsNone(d.procedure());self.assertFalse(d.decompile.isEnabled());d.close()

class PickerRouting(unittest.TestCase):
    @classmethod
    def setUpClass(cls):support.ExportUi.setUpClass.__func__(cls)
    setUp=support.ExportUi.setUp
    tearDown=support.ExportUi.tearDown
    def complete(self):
        import json
        r={'target':str(self.target),'structuredContent':{'observed_result':[{'address':'0x401000','name':'entry'}]}}
        self.w._on_tool_completed('functions',json.dumps(r));self.app.processEvents()
    def test_selection_starts_exact_address_without_manual_prompt(self):
        with patch.object(FunctionPickerDialog,'exec_',return_value=QDialog.Accepted),patch.object(FunctionPickerDialog,'procedure',return_value='0x401000'),patch.object(self.w,'action_decompile') as start:
            self.complete();start.assert_called_once_with(procedure='0x401000')
    def test_target_change_during_picker_discards_selection(self):
        def changed(*args):self.w.set_target_file('/usr/bin/true');return QDialog.Accepted
        with patch.object(FunctionPickerDialog,'exec_',side_effect=changed),patch.object(FunctionPickerDialog,'procedure',return_value='0x401000'),patch.object(self.w,'action_decompile') as start:
            self.complete();start.assert_not_called()
    def test_cancel_does_not_start_analysis(self):
        with patch.object(FunctionPickerDialog,'exec_',return_value=QDialog.Rejected),patch.object(self.w,'action_decompile') as start:
            self.complete();start.assert_not_called()

if __name__=='__main__':unittest.main(verbosity=2)

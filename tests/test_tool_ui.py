"""Normal desktop menu routing and dependency/update explanations."""
import os
os.environ['QT_QPA_PLATFORM'] = 'offscreen'
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'app'))
from PyQt5.QtCore import QProcess
from PyQt5.QtWidgets import QApplication, QMainWindow
from rehkc_tool_ui import install_tool_menu, update_message


class ToolUi(unittest.TestCase):
    def test_incompatible_upstream_and_python_requirements_are_explicit(self):
        text = update_message({'updates':[
            {'component':'ghidra','installed':'12.1.4','latest_tag':'12.2',
             'java_minimum':'25','compatibility':'unsupported_by_bundled_rea'},
            {'component':'package','installed':'1','latest_tag':'2',
             'requires_python':'>=3.14','compatibility':'requires_rehkc_release'}]})
        self.assertIn('gereken Java: 25+',text)
        self.assertIn('desteklemiyor',text)
        self.assertIn('gereken Python: >=3.14',text)
        self.assertIn('REHKC sürüm güncellemesi gerekir',text)

    def test_menu_runs_status_without_blocking_event_loop(self):
        app = QApplication.instance() or QApplication([])
        window = QMainWindow()
        window.append_log = lambda *args:None
        answers = []
        with tempfile.TemporaryDirectory() as root, patch.dict(os.environ,{'REHKC_TOOLS_DIR':root}),patch('rehkc_tool_ui.QMessageBox.information', side_effect=lambda *args:answers.append(args[2])):
            install_tool_menu(app,window)
            menu = window.menuBar().actions()[0].menu()
            self.assertEqual(len(menu.actions()),5)
            menu.actions()[0].trigger()
            deadline = time.monotonic()+5
            ticks = 0
            while not answers and time.monotonic()<deadline:
                app.processEvents(); ticks += 1; time.sleep(.005)
            self.assertTrue(answers)
            self.assertIn('kurulu değil',answers[0])
            self.assertGreater(ticks,0)
            self.assertEqual(window.managed_tools_process.state(),QProcess.NotRunning)
            window.managed_tools_timer.stop()
            window.close()
        window.deleteLater();app.processEvents()


if __name__ == '__main__':unittest.main(verbosity=2)

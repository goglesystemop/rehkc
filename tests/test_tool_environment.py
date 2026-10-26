"""Desktop menus need to discover user-installed engines without login shell setup."""
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('rehkc_boot', Path(__file__).resolve().parents[1]/'app/rehkc_boot.py')
boot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(boot)


class ToolEnvironment(unittest.TestCase):
    def test_menu_path_discovers_local_jdk_and_cli_tools(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            local = home/'.local/bin'
            local.mkdir(parents=True)
            jdk = home/'jdk/bin'
            jdk.mkdir(parents=True)
            compiler = jdk/'javac'
            compiler.write_text('#!/bin/sh\nexit 0\n')
            compiler.chmod(0o755)
            (local/'javac').symlink_to(compiler)
            (local/'radare2').write_text('#!/bin/sh\nexit 0\n')
            (local/'radare2').chmod(0o755)
            with patch.object(boot.Path, 'home', return_value=home), patch.dict(os.environ, {'PATH':str(home/'empty')}, clear=True):
                boot.tool_environment()
                self.assertEqual(os.environ['JAVA_HOME'], str(jdk.parent))
                self.assertEqual(boot.shutil.which('radare2'), str(local/'radare2'))

    def test_explicit_jdk_and_path_keep_precedence(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            with patch.object(boot.Path, 'home', return_value=home), patch.dict(os.environ, {'PATH':'/custom/bin','JAVA_HOME':'/chosen/jdk'}, clear=True):
                boot.tool_environment()
                self.assertEqual(os.environ['JAVA_HOME'], '/chosen/jdk')
                self.assertEqual(os.environ['PATH'].split(os.pathsep)[:2], ['/chosen/jdk/bin','/custom/bin'])


if __name__ == '__main__':
    unittest.main()

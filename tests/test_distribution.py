"""Integration checks on a supplied built package; no real user data is changed."""
import argparse,hashlib,json,os,pathlib,shutil,subprocess,tempfile,unittest,time,shlex
P=argparse.ArgumentParser();P.add_argument('--package',required=True,type=pathlib.Path);ARGS,LEFT=P.parse_known_args();PACKAGE=ARGS.package.resolve()
def run(root,*args,ok=True):
 p=subprocess.run(['/bin/sh',str(root/'install.sh'),*map(str,args)],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=120)
 if ok and p.returncode:raise AssertionError(p.stdout)
 return p
class Distribution(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory(prefix='rehkc-install-check-');self.root=pathlib.Path(self.temp.name)
  self.data=self.root/'Ü boş % $quote\"'/ 'application';self.binary=self.root/'commands with spaces';self.desktop=self.root/'applications'
  self.args=['--data-dir',self.data,'--bin-dir',self.binary,'--desktop-dir',self.desktop]
 def tearDown(self):self.temp.cleanup()
 def test_check_is_read_only(self):
  run(PACKAGE,*self.args,'--check');self.assertFalse(self.data.exists());self.assertFalse(self.binary.exists())
 def test_install_idempotent_and_uninstall_preserves_data(self):
  sessions=self.data/'sessions';sessions.mkdir(parents=True);sentinel=sessions/'keep.json';sentinel.write_text('USER SESSION')
  (self.root/'config/chatgpt').mkdir(parents=True);credential=self.root/'config/chatgpt/accounts.json';credential.write_text('PRIVATE FIXTURE')
  run(PACKAGE,*self.args);launcher=self.binary/'rehkc';first=launcher.read_bytes()
  self.assertTrue(os.access(launcher,os.X_OK));self.assertTrue((self.data/'current').is_symlink())
  desktop=self.desktop/'io.github.goglesystemop.rehkc.desktop';self.assertIn('StartupWMClass=REHKC',desktop.read_text())
  run(PACKAGE,*self.args);self.assertEqual(first,launcher.read_bytes());self.assertEqual(sentinel.read_text(),'USER SESSION')
  # The installed copy must support read-only diagnostics, while refusing a
  # recursive reinstall into its own source tree. Neither may mutate state.
  receipt=self.data/'installation.json';before=receipt.read_bytes()
  run(self.data/'current',*self.args,'--check')
  self.assertEqual(before,receipt.read_bytes());self.assertEqual(first,launcher.read_bytes())
  failed=run(self.data/'current',*self.args,ok=False)
  self.assertNotEqual(failed.returncode,0);self.assertEqual(before,receipt.read_bytes())
  # Verify the executable portion is correctly parsed by the real GLib desktop parser.
  try:
   import gi
   from gi.repository import Gio
  except ImportError:Gio=None
  if Gio:
   info=Gio.DesktopAppInfo.new_from_filename(str(desktop));self.assertIsNotNone(info)
   marker=self.root/'desktop-launched'
   launcher.write_text('#!/bin/sh\nprintf launched > '+shlex.quote(str(marker))+'\n')
   try:
    self.assertTrue(info.launch([],None))
    end=time.monotonic()+5
    while not marker.exists() and time.monotonic()<end:time.sleep(.02)
    self.assertEqual(marker.read_text(),'launched')
   finally:launcher.write_bytes(first)
  run(self.data/'current',*self.args,'--uninstall');self.assertFalse(launcher.exists());self.assertFalse(desktop.exists())
  self.assertEqual(sentinel.read_text(),'USER SESSION');self.assertEqual(credential.read_text(),'PRIVATE FIXTURE')
 def test_foreign_launcher_requires_explicit_backup_and_is_restored(self):
  self.binary.mkdir();old=self.binary/'rehkc';old.write_bytes(b'ORIGINAL LAUNCHER');old.chmod(0o700)
  failed=run(PACKAGE,*self.args,ok=False);self.assertNotEqual(failed.returncode,0);self.assertEqual(old.read_bytes(),b'ORIGINAL LAUNCHER')
  run(PACKAGE,*self.args,'--replace-existing');run(PACKAGE,*self.args,'--uninstall');self.assertEqual(old.read_bytes(),b'ORIGINAL LAUNCHER');self.assertEqual(old.stat().st_mode&0o777,0o700)
 def test_modified_launcher_survives_uninstall(self):
  run(PACKAGE,*self.args);p=self.binary/'rehkc';p.write_text('USER EDIT')
  run(PACKAGE,*self.args,'--uninstall');self.assertEqual(p.read_text(),'USER EDIT')
 def test_corrupt_payload_is_rejected_before_install(self):
  copy=self.root/'tampered';shutil.copytree(PACKAGE,copy,symlinks=True,copy_function=shutil.copy2,ignore=shutil.ignore_patterns('__pycache__','*.pyc'))
  p=copy/'app/rehkc_paths.py';replacement=p.with_suffix('.replacement');replacement.write_text('CORRUPT');os.replace(replacement,p)
  result=run(copy,*self.args,ok=False);self.assertNotEqual(result.returncode,0);self.assertFalse((self.binary/'rehkc').exists())
 def test_owned_prefix_cannot_be_user_home(self):
  result=run(PACKAGE,'--data-dir',pathlib.Path.home(),ok=False);self.assertNotEqual(result.returncode,0)
if __name__=='__main__':unittest.main(argv=[__file__,*LEFT],verbosity=2)

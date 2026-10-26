"""Failure, isolation and update policy checks; downloads are small local fixtures."""
import copy
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import time
import unittest
from unittest.mock import patch
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'app'))
import rehkc_tools as tools


class ManagedTools(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.catalog = tools.load_catalog()

    def tearDown(self):
        self.temp.cleanup()

    def test_catalog_rejects_untrusted_origin_and_incompatible_jdk(self):
        for mutate in [lambda c:c['tools']['ghidra'].update(url='https://example.org/engine.zip'),
                       lambda c:c['tools']['ghidra'].update(root='../escape'),
                       lambda c:c['tools']['jdk'].update(version='25.0.1'),
                       lambda c:c['tools']['ghidra'].update(version='12.2'),
                       lambda c:c['tools']['retdec'].update(sha256='wrong')]:
            catalog = copy.deepcopy(self.catalog)
            mutate(catalog)
            with self.assertRaises(ValueError):tools.validate_catalog(catalog)

    def test_checksum_failure_never_caches_or_activates(self):
        spec = dict(self.catalog['tools']['jdk'], bytes=3, sha256='0'*64)
        with patch.object(tools, 'request', return_value=io.BytesIO(b'bad')):
            with self.assertRaises(ValueError):tools.download(spec, self.root/'cache')
        self.assertEqual(list((self.root/'cache').iterdir()), [])
        self.assertFalse((self.root/'active.json').exists())

    def test_zip_traversal_and_tar_escape_are_refused(self):
        archive = self.root/'bad.zip'
        with zipfile.ZipFile(archive, 'w') as z:z.writestr('../escape', b'bad')
        with self.assertRaises(ValueError):tools.unpack(archive, {'format':'zip'}, self.root/'zip')
        archive = self.root/'bad.tar'
        with tarfile.open(archive,'w') as t:
            info = tarfile.TarInfo('escape');info.type=tarfile.SYMTYPE;info.linkname='../../escape';t.addfile(info)
        with self.assertRaises(tarfile.FilterError):tools.unpack(archive, {'format':'tar'}, self.root/'tar')
        self.assertFalse((self.root.parent/'escape').exists())

    def test_failed_install_preserves_previous_set_and_cleans_stage(self):
        previous = {'release':'old', 'catalog':{'private_fixture':True}}
        tools.atomic_json(self.root/'active.json', previous)
        with patch.object(tools,'host_compatibility'), patch.object(tools,'download',side_effect=OSError('offline')):
            with self.assertRaises(OSError):tools.install(self.root, self.catalog, progress=lambda *a,**k:None)
        self.assertEqual(json.loads((self.root/'active.json').read_text()), previous)
        self.assertEqual(list((self.root/'releases').iterdir()), [])

    def test_failed_health_does_not_switch_existing_set(self):
        destination = self.root/'releases'/tools.catalog_id(self.catalog)
        destination.mkdir(parents=True)
        tools.atomic_json(self.root/'active.json', {'release':'old'})
        with patch.object(tools,'host_compatibility'),patch.object(tools,'health',side_effect=ValueError('missing libX11')):
            with self.assertRaises(ValueError):tools.install(self.root, self.catalog)
        self.assertEqual(json.loads((self.root/'active.json').read_text()), {'release':'old'})

    def test_managed_env_and_explicit_directory_overrides(self):
        tools.atomic_json(self.root/'active.json',{'release':tools.catalog_id(self.catalog),'catalog':self.catalog})
        env = {'PATH':'/custom/bin','JAVA_HOME':'/chosen/java','GHIDRA_INSTALL_DIR':'/chosen/ghidra'}
        tools.apply_environment(self.root, env)
        self.assertEqual(env['JAVA_HOME'],'/chosen/java')
        self.assertEqual(env['GHIDRA_INSTALL_DIR'],'/chosen/ghidra')
        self.assertTrue(env['RETDEC_INSTALL_DIR'].startswith(str(self.root/'releases')))
        self.assertTrue(env['PATH'].endswith(':/custom/bin'))
        self.assertNotIn('LD_LIBRARY_PATH', env)

    def test_weekly_check_is_cached_and_read_only_for_payloads(self):
        report = {'next_check':time.time()+100,'updates':[]}
        tools.atomic_json(self.root/'updates.json', report)
        before = (self.root/'updates.json').read_bytes()
        with patch.object(tools,'fetch_json', side_effect=AssertionError('unexpected network')):
            self.assertTrue(tools.check_updates(self.root, if_due=True)['skipped'])
        self.assertEqual((self.root/'updates.json').read_bytes(), before)
        self.assertFalse((self.root/'active.json').exists())

    def test_offline_check_retries_next_day_without_installing(self):
        with patch.object(tools,'fetch_json', side_effect=OSError('offline')), patch('importlib.metadata.version',return_value='1.0'):
            report = tools.check_updates(self.root)
        self.assertTrue(report['errors'])
        self.assertEqual(report['next_check']-report['checked_at'], tools.RETRY)
        self.assertFalse(report['automatically_installed'])
        self.assertFalse((self.root/'active.json').exists())

    def test_release_checks_include_python_requirements_and_ghidra_java(self):
        calls = []
        def response(url):
            calls.append(url)
            if url == tools.CATALOG_URL:return self.catalog
            if 'matching-refs' in url:return [{'ref':f'refs/tags/v{sys.version_info.major}.{sys.version_info.minor}.999'}, {'ref':f'refs/tags/v{sys.version_info.major}.{sys.version_info.minor}.9999rc1'}]
            if 'pypi.org' in url:return {'info':{'version':'999.0','requires_python':'>=3.14'}}
            return {'tag_name':'Ghidra_99.0_build' if '/ghidra/' in url else 'v99.0', 'html_url':'https://github.com/release'}
        props = b'application.java.min=99\napplication.java.max=\n'
        with patch.object(tools,'fetch_json',side_effect=response),patch.object(tools,'request',return_value=io.BytesIO(props)),patch('importlib.metadata.version',return_value='1.0'):
            report = tools.check_updates(self.root)
        self.assertEqual(report['next_check']-report['checked_at'], tools.WEEK)
        self.assertTrue(any(item.get('java_minimum')=='99' for item in report['updates']))
        self.assertTrue(any(item.get('requires_python')=='>=3.14' for item in report['updates']))
        self.assertTrue(any(item['component']=='Python' for item in report['updates']))
        self.assertFalse((self.root/'active.json').exists())

    def test_host_python_and_glibc_constraints(self):
        with patch.object(tools.platform,'libc_ver',return_value=('glibc','2.28')):
            with self.assertRaisesRegex(ValueError,'glibc'):tools.host_compatibility(self.catalog)
        with patch.object(tools.platform,'libc_ver',return_value=('glibc','2.40')),patch.object(tools.sys,'version_info',(3,15,0)):
            with self.assertRaisesRegex(ValueError,'Python'):tools.host_compatibility(self.catalog)

    def test_rollback_checks_health_before_switch(self):
        previous = dict(self.catalog, revision=self.catalog['revision']-1)
        old = {'release':tools.catalog_id(previous),'catalog':previous}
        current = {'release':tools.catalog_id(self.catalog),'catalog':self.catalog}
        tools.atomic_json(self.root/'previous.json',old); tools.atomic_json(self.root/'active.json',current)
        with patch.object(tools,'health',side_effect=ValueError('broken previous version')):
            with self.assertRaises(ValueError):tools.rollback(self.root)
        self.assertEqual(json.loads((self.root/'active.json').read_text()),current)
        with patch.object(tools,'health',return_value={'ok':True}):tools.rollback(self.root)
        self.assertEqual(json.loads((self.root/'active.json').read_text()),old)
        self.assertEqual(json.loads((self.root/'previous.json').read_text()),current)


if __name__ == '__main__':unittest.main(verbosity=2)

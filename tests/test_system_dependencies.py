"""Distro dispatch, privileged package commands and failure behavior; no host changes."""
import contextlib
import importlib.util
import io
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('rehkc_installer',ROOT/'installer.py')
installer=importlib.util.module_from_spec(spec);spec.loader.exec_module(installer)


class SystemDependencies(unittest.TestCase):
    def test_debian_family_and_arch_derivatives(self):
        fixtures=[({'ID':'debian'},'apt-get'),({'ID':'ubuntu','ID_LIKE':'debian'},'apt-get'),
          ({'ID':'linuxmint','ID_LIKE':'ubuntu debian'},'apt-get'),
          ({'ID':'neon','ID_LIKE':'ubuntu debian'},'apt-get'),
          ({'ID':'arch'},'pacman'),({'ID':'cachyos','ID_LIKE':'arch'},'pacman'),
          ({'ID':'manjaro','ID_LIKE':'arch'},'pacman'),
          ({'ID':'derivative','ID_LIKE':'arch'},'pacman')]
        for release,expected in fixtures:
            with self.subTest(release=release):self.assertEqual(installer.dependency_manager(release),expected)

    def test_explicit_distro_identity_beats_like_and_other_installed_manager(self):
        with patch.object(installer.platform,'freedesktop_os_release',return_value={'ID':'arch','ID_LIKE':'debian'}),patch.object(installer.shutil,'which',return_value='/usr/bin/apt-get'):
            self.assertEqual(installer.dependency_manager(),'pacman')

    def test_unknown_ambiguous_or_missing_os_release_is_rejected(self):
        for release in [{},{'ID':'unknown'},{'ID':'unknown','ID_LIKE':'arch debian'}]:
            with self.subTest(release=release),self.assertRaises(ValueError):installer.dependency_manager(release)
        with patch.object(installer.platform,'freedesktop_os_release',side_effect=OSError('missing')):
            with self.assertRaisesRegex(ValueError,'os-release'):installer.dependency_manager()

    def test_arch_uses_full_upgrade_and_keeps_confirmation(self):
        with patch.object(installer.os,'geteuid',return_value=1000):command=installer.system_dependencies('pacman')
        self.assertEqual(command[:4],['sudo','pacman','-Syu','--needed'])
        self.assertNotIn('--noconfirm',command)
        self.assertTrue({'libglvnd','libxkbcommon-x11','xcb-util-cursor','xcb-util-wm','wayland','dbus','binutils'} <= set(command))
        self.assertFalse(any(p.startswith('libxcb-') for p in command))

    def test_debian_command_and_shared_libraries_remain(self):
        with patch.object(installer.os,'geteuid',return_value=1000):command=installer.system_dependencies('apt-get')
        self.assertEqual(command[:4],['sudo','apt-get','install','--no-install-recommends'])
        self.assertIn('libxcb-cursor0',command);self.assertIn('libxtst6',command)
        self.assertNotIn('--needed',command)

    def test_root_dependency_helper_does_not_require_sudo(self):
        with patch.object(installer.os,'geteuid',return_value=0):
            self.assertEqual(installer.system_dependencies('pacman')[:3],['pacman','-Syu','--needed'])
        with self.assertRaises(ValueError):installer.system_dependencies('other')

    def test_actual_dispatch_calls_selected_manager_once(self):
        with patch.object(installer.platform,'freedesktop_os_release',return_value={'ID':'manjaro','ID_LIKE':'arch'}),patch.object(installer.os,'geteuid',return_value=1000),patch.object(installer.shutil,'which',side_effect=lambda name:'/usr/bin/'+name),patch.object(installer.subprocess,'run') as run,contextlib.redirect_stdout(io.StringIO()):
            installer.install_system_dependencies()
            self.assertEqual(run.call_count,1)
            self.assertEqual(run.call_args.args[0][:4],['sudo','pacman','-Syu','--needed'])
            self.assertTrue(run.call_args.kwargs['check'])

    def test_missing_manager_or_sudo_never_runs_another_manager(self):
        for missing in ['pacman','sudo']:
            with self.subTest(missing=missing),patch.object(installer,'dependency_manager',return_value='pacman'),patch.object(installer.os,'geteuid',return_value=1000),patch.object(installer.shutil,'which',side_effect=lambda name:None if name==missing else '/usr/bin/'+name),patch.object(installer.subprocess,'run') as run:
                with self.assertRaisesRegex(ValueError,missing):installer.install_system_dependencies()
                run.assert_not_called()

    def test_package_failure_stops_before_application_install(self):
        with tempfile.TemporaryDirectory() as temporary:
            target=Path(temporary)/'application'
            with patch.object(sys,'argv',['installer.py','--install-system-deps','--data-dir',str(target)]),patch.object(installer.os,'geteuid',return_value=1000),patch.object(installer,'dependency_manager',return_value='pacman'),patch.object(installer.shutil,'which',side_effect=lambda name:'/usr/bin/'+name),patch.object(installer.subprocess,'run',side_effect=subprocess.CalledProcessError(1,['pacman'])),patch.object(installer,'payload_manifest') as manifest,contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(subprocess.CalledProcessError):installer.main()
                manifest.assert_not_called();self.assertFalse(target.exists())

    def test_print_is_read_only_and_matches_install_command(self):
        output=io.StringIO()
        with patch.object(sys,'argv',['installer.py','--print-system-deps']),patch.object(installer,'dependency_manager',return_value='pacman'),patch.object(installer.os,'geteuid',return_value=1000),patch.object(installer.subprocess,'run') as run,patch.object(installer,'payload_manifest') as manifest,contextlib.redirect_stdout(output):
            self.assertEqual(installer.main(),0)
            self.assertEqual(shlex.split(output.getvalue())[:4],['sudo','pacman','-Syu','--needed'])
            run.assert_not_called();manifest.assert_not_called()

    def test_conflicting_or_sudo_invocation_cannot_change_system(self):
        for flags in [['--check','--install-system-deps'],['--uninstall','--install-system-deps'],['--install-system-deps']]:
            with self.subTest(flags=flags),patch.object(sys,'argv',['installer.py',*flags]),patch.object(installer.os,'geteuid',return_value=0),patch.object(installer.subprocess,'run') as run:
                with self.assertRaises(ValueError):installer.main()
                run.assert_not_called()


if __name__=='__main__':unittest.main(verbosity=2)

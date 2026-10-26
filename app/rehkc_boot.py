"""Relocatable REHKC entry point, with explicit dependency diagnostics."""
import argparse
import glob
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import time

APP = Path(__file__).resolve().parent
ROOT = APP.parent
VERSION = '0.2.0'
sys.path.insert(0, str(APP))


def tool_environment():
    """Explicit environment wins; load managed engines, then external fallbacks."""
    import rehkc_tools
    try:
        rehkc_tools.apply_environment()
    except (OSError, ValueError, KeyError) as exc:
        print('Managed analysis tools: '+str(exc),file=sys.stderr)
    # A desktop session can predate ~/.local/bin, so its menu PATH may omit it.
    # Keep explicitly configured PATH entries first, then discover user tools.
    search_path = os.environ.get('PATH', '/usr/local/bin:/usr/bin:/bin').split(os.pathsep)
    local_bin = str(Path.home()/'.local/bin')
    if local_bin not in search_path:
        search_path.append(local_bin)
    os.environ['PATH'] = os.pathsep.join(search_path)
    if not os.environ.get('GHIDRA_INSTALL_DIR'):
        candidates=[]
        for pattern in [str(Path.home()/'.local/opt/ghidra*'),'/opt/ghidra*','/usr/share/ghidra*','/usr/local/share/ghidra*']:
            candidates.extend(sorted(glob.glob(pattern), reverse=True)[:20])
        command=shutil.which('analyzeHeadless')
        if command:candidates.insert(0,str(Path(command).resolve().parent.parent))
        for candidate in candidates:
            if (Path(candidate)/'support/analyzeHeadless').is_file() and (Path(candidate)/'Ghidra/application.properties').is_file():
                os.environ['GHIDRA_INSTALL_DIR']=candidate;break
    if not os.environ.get('JAVA_HOME'):
        javac=shutil.which('javac')
        if javac:os.environ['JAVA_HOME']=str(Path(javac).resolve().parent.parent)
    if not os.environ.get('RETDEC_INSTALL_DIR'):
        candidates=[]
        executable=shutil.which('retdec-decompiler')
        if executable:candidates.append(str(Path(executable).resolve().parent.parent))
        for pattern in [str(Path.home()/'.local/opt/retdec*'),'/opt/retdec*','/usr/local/retdec*']:
            candidates.extend(sorted(glob.glob(pattern),reverse=True)[:20])
        for candidate in candidates:
            if (Path(candidate)/'bin/retdec-decompiler').is_file():os.environ['RETDEC_INSTALL_DIR']=candidate;break
    paths=[]
    for key in ['JAVA_HOME','RETDEC_INSTALL_DIR']:
        if os.environ.get(key):paths.append(str(Path(os.environ[key])/'bin'))
    os.environ['PATH']=os.pathsep.join(paths+[os.environ.get('PATH','/usr/local/bin:/usr/bin:/bin')])
    os.environ['REA_BIN_PATH']=str(APP/'rea-engine')
    os.environ['REA_DIAGNOSTIC_ROOT']=str(APP)


def dependencies():
    missing=set()
    plugins=list((ROOT/'runtime/python/lib').glob('python*/site-packages/PyQt5/Qt5/plugins/platforms/libqxcb.so'))
    for name in ['QtCore','QtGui','QtWidgets']:
        plugins.extend((ROOT/'runtime/python/lib').glob('python*/site-packages/PyQt5/'+name+'*.so'))
    if plugins and shutil.which('ldd'):
        for library in plugins:
            p=subprocess.run(['ldd',str(library)],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=10)
            for line in p.stdout.splitlines():
                if '=> not found' in line:missing.add(line.strip().split()[0])
    return {'version':VERSION,'architecture':platform.machine(),'libc':platform.libc_ver(),
        'python':platform.python_version(),'missing_x11_libraries':sorted(missing),
        'optional_tools':{name:shutil.which(name) for name in ['objdump','strings','readelf','nm','radare2','r2','rabin2','retdec-decompiler','java','javac']},
        'ghidra_configured':bool(os.environ.get('GHIDRA_INSTALL_DIR'))}


def main():
    parser=argparse.ArgumentParser(description='REHKC — REA Linux desktop')
    parser.add_argument('--version',action='store_true')
    parser.add_argument('--doctor',action='store_true',help='Runtime/dependency report; no software is installed')
    parser.add_argument('--tools',choices=['install','status','check-updates','update','rollback'],help='Manage analysis engines and their dependencies')
    parser.add_argument('--if-due',action='store_true',help='Skip update check until the next weekly check is due')
    parser.add_argument('--engine',nargs=argparse.REMAINDER,help='Run the bundled REA CLI/MCP')
    parser.add_argument('--smoke-test',action='store_true',help='Open a disposable, isolated GUI and verify startup')
    parser.add_argument('--report',type=Path)
    parser.add_argument('--screenshot',type=Path)
    parser.add_argument('target',nargs='?')
    args=parser.parse_args()
    if args.tools:
        import rehkc_tools
        return rehkc_tools.main([args.tools]+(['--if-due'] if args.if_due else []))
    tool_environment()
    if args.version:print('REHKC '+VERSION+' / REA 6.7.0');return 0
    if args.engine is not None:
        os.execv(str(APP/'rea-engine'),[str(APP/'rea-engine'),*args.engine])
    if args.doctor:
        result=dependencies();print(json.dumps(result,ensure_ascii=False,indent=2));return 1 if result['missing_x11_libraries'] else 0
    private=None
    if args.smoke_test:
        private=tempfile.TemporaryDirectory(prefix='rehkc-smoke-')
        os.environ['REHKC_CONFIG_DIR']=private.name+'/config'
        os.environ['REHKC_DATA_DIR']=private.name+'/data'
    if not os.environ.get('SSL_CERT_FILE'):
        for candidate in ['/etc/ssl/certs/ca-certificates.crt','/etc/pki/tls/certs/ca-bundle.crt','/etc/ssl/cert.pem']:
            if Path(candidate).is_file():os.environ['SSL_CERT_FILE']=candidate;break
    # Isolate the bundled Qt5 plugins from desktop/system Qt6 plugin overrides.
    os.environ.pop('QT_PLUGIN_PATH',None)
    os.environ.pop('QT_QPA_PLATFORM_PLUGIN_PATH',None)
    try:
        from PyQt5.QtCore import QTimer, QT_VERSION_STR, PYQT_VERSION_STR, qVersion
        from PyQt5.QtWidgets import QApplication
        import rea_gui as gui
    except ImportError as exc:
        print('GUI dependency error: '+str(exc)+'\nRun ./run --doctor and see docs/INSTALL.md.',file=sys.stderr);return 1
    application=QApplication([sys.argv[0]])
    application.setApplicationName('REHKC')
    application.setOrganizationName('REHKC')
    application.setDesktopFileName('io.github.goglesystemop.rehkc')
    window=gui.ReaMainWindow(target_file=args.target)
    window.setWindowTitle('REHKC — REA Desktop')
    window.show()
    if not args.smoke_test:
        from rehkc_tool_ui import install_tool_menu
        install_tool_menu(application,window)
    if args.smoke_test:
        start=time.monotonic();finishing=False
        def check():
            nonlocal finishing
            if finishing:return
            workers=[window.catalog_worker,window.model_worker]
            ready=all(worker is not None and not worker.isRunning() for worker in workers)
            if not ready and time.monotonic()-start<30:return
            finishing=True
            result=dependencies();result.update(qt=qVersion(),qt_binding_build=QT_VERSION_STR,pyqt=PYQT_VERSION_STR,
                platform=application.platformName(),visible=window.isVisible(),
                desktop_file=application.desktopFileName(),
                providers=[window.combo_provider.itemData(i) for i in range(window.combo_provider.count())],
                engine_catalog=len(window.command_catalog or {}),
                config_isolated=str(gui.CONFIG_DIR).startswith(private.name),
                sessions_isolated=str(gui.SESSION_DIR).startswith(private.name))
            ok=ready and result['visible'] and result['engine_catalog']>100 and result['providers']==['lmstudio','ollama','chatgpt'] and result['config_isolated'] and result['sessions_isolated']
            result['ok']=ok
            if args.screenshot:window.grab().save(str(args.screenshot))
            if args.report:args.report.write_text(json.dumps(result,ensure_ascii=False,indent=2))
            print(json.dumps(result,ensure_ascii=False,indent=2),flush=True)
            window.close();application.exit(0 if ok else 1)
        timer=QTimer();timer.setInterval(100);timer.timeout.connect(check);timer.start()
    code=application.exec_()
    if private:private.cleanup()
    return code

if __name__=='__main__':raise SystemExit(main())

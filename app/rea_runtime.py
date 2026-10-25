"""Use the original shipped JS and Bun runtime for diagnostics with real filesystem paths.
CLI and MCP use the same verified, unchanged JS through the shipped Bun runtime.
"""
import hashlib
import json
import os
from pathlib import Path
import sys


def _verified(binary, root):
    root = Path(root)
    manifest = json.loads((root/'doctor-runtime/bundle-manifest.json').read_text())
    bundle = root/'doctor-runtime/scripts/entry-binary.mjs'
    if hashlib.sha256(Path(binary).read_bytes()).hexdigest() != manifest['binary_sha256']:
        raise ValueError('Doctor uyumluluk paketi seçili motor sürümüyle eşleşmiyor.')
    if hashlib.sha256(bundle.read_bytes()).hexdigest() != manifest['bundle_sha256']:
        raise ValueError('Doctor uyumluluk paketinin kod bütünlüğü doğrulanamadı.')
    for item in manifest['companion_files']:
        path = root/item['destination']
        if hashlib.sha256(path.read_bytes()).hexdigest() != item['sha256']:
            raise ValueError('Doctor destek dosyasının bütünlüğü doğrulanamadı: '+item['destination'])
    return str(bundle)


def diagnostic_command(args):
    args = list(args)
    if len(args) < 2 or '--help' in args or '--schema' in args:
        return args
    if args[1] != 'doctor' and args[1:3] != ['mcp', 'doctor']:
        return args
    binary = Path(args[0]).absolute()
    if binary.name != 'rea.bin':
        return args
    root = Path(os.environ.get('REA_DIAGNOSTIC_ROOT', str(binary.parent)))
    manifest = root/'doctor-runtime/bundle-manifest.json'
    if not manifest.is_file():
        return args
    bundle = _verified(str(binary), str(root))
    # A dedicated entry limits BUN_BE_BUN to diagnostics and its own child server.
    return [sys.executable, str(Path(__file__).with_name('rea_runtime.py')), '--diagnostic-exec', str(binary), bundle, *args[1:]]


def engine_main():
    root = Path(__file__).resolve().parent
    binary = root/'rea.bin'
    if sys.argv[1:2] == ['--diagnostic-exec']:
        if len(sys.argv) < 5:
            raise SystemExit('Geçersiz doctor başlatma parametreleri.')
        binary = Path(sys.argv[2])
        env = dict(os.environ, BUN_BE_BUN='1')
        os.execve(str(binary), [str(binary), sys.argv[3], *sys.argv[4:]], env)
    args = [str(binary), *sys.argv[1:]]
    resolved = diagnostic_command(args)
    if resolved != args:
        os.execv(resolved[0], resolved)
    # The shipped engine's unchanged JS has real import.meta paths here.
    # This keeps Ghidra bridge resolution inside this package, without /bridge.
    bundle = _verified(str(binary), str(root))
    env = dict(os.environ, BUN_BE_BUN='1')
    os.execve(str(binary), [str(binary), bundle, *sys.argv[1:]], env)


if __name__ == '__main__':
    engine_main()

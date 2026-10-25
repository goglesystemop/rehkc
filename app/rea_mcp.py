"""Private, bounded MCP stdio session and a selected-file static tool boundary."""
import hashlib
import json
import os
from pathlib import Path
import selectors
import signal
import stat
import subprocess
import time


class McpCancelled(Exception):
    pass


def target_signature(path):
    st = os.stat(path)
    if not stat.S_ISREG(st.st_mode) or st.st_size > 128 * 1024 * 1024:
        raise ValueError('MCP analizi için en fazla 128 MB normal dosya seçin.')
    return (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)


def owned_children(root_pid):
    """Remember descendant start identities before their parent can exit/reparent them."""
    entries = {}
    for path in Path('/proc').glob('[0-9]*/stat'):
        try:
            fields = path.read_text().rsplit(') ', 1)[1].split()
            entries[int(path.parent.name)] = (int(fields[1]), fields[19])
        except (OSError, ValueError, IndexError):
            continue
    owned = {root_pid}
    changed = True
    while changed:
        changed = False
        for pid, (parent, _) in entries.items():
            if parent in owned and pid not in owned:
                owned.add(pid); changed = True
    return {pid: entries[pid][1] for pid in owned if pid != root_pid and pid in entries}


def signal_owned(children, sig):
    for pid, started in children.items():
        try:
            fields = Path('/proc', str(pid), 'stat').read_text().rsplit(') ', 1)[1].split()
            if fields[19] == started:
                os.kill(pid, sig)
        except (OSError, ValueError, IndexError):
            pass


class McpClient:
    MAX_MESSAGE = 8 * 1024 * 1024

    def __init__(self, binary, stopped, deadline):
        self.stopped, self.deadline = stopped, deadline
        self.process = subprocess.Popen([binary, '--mcp'], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, bufsize=0, start_new_session=True,
            env={k:v for k,v in os.environ.items() if k not in ('BUN_BE_BUN','HOPPER_TARGET_PATH','HOPPER_TARGET_KIND','HOPPER_LOADER_ARGS_JSON')})
        self.selector = selectors.DefaultSelector()
        for stream, name in [(self.process.stdout, 'stdout'), (self.process.stderr, 'stderr')]:
            os.set_blocking(stream.fileno(), False)
            self.selector.register(stream, selectors.EVENT_READ, name)
        os.set_blocking(self.process.stdin.fileno(), False)
        self.buffer, self.stderr = bytearray(), bytearray()
        self.next_id = 0
        self.pending = None
        self.opened = False

    def check(self, deadline, ignore_cancel=False):
        if self.stopped.is_set() and not ignore_cancel:
            raise McpCancelled('MCP analizi durduruldu.')
        if time.monotonic() > deadline:
            raise TimeoutError('MCP/otonom analiz zaman sınırı aşıldı.')

    def write(self, value, deadline, ignore_cancel=False):
        import select
        data = json.dumps(value, ensure_ascii=False).encode('utf-8') + b'\n'
        offset = 0
        while offset < len(data):
            self.check(deadline, ignore_cancel)
            if self.process.poll() is not None:
                raise RuntimeError('MCP sunucusu kapandı: '+self.stderr.decode('utf-8','replace')[-1200:])
            if not select.select([], [self.process.stdin], [], .05)[1]:
                continue
            try:
                offset += os.write(self.process.stdin.fileno(), data[offset:offset+4096])
            except BlockingIOError:
                continue

    def notify(self, method, params, timeout=1):
        self.write({'jsonrpc':'2.0','method':method,'params':params}, time.monotonic()+timeout, True)

    def call(self, method, params, timeout=90, ignore_cancel=False):
        deadline = min(self.deadline, time.monotonic()+timeout) if not ignore_cancel else time.monotonic()+timeout
        self.next_id += 1
        identifier = self.next_id
        self.pending = identifier
        self.write({'jsonrpc':'2.0','id':identifier,'method':method,'params':params}, deadline, ignore_cancel)
        while True:
            self.check(deadline, ignore_cancel)
            while b'\n' in self.buffer:
                raw, _, rest = self.buffer.partition(b'\n'); self.buffer = bytearray(rest)
                if not raw.strip():
                    continue
                response = json.loads(raw)
                if not isinstance(response, dict):
                    raise ValueError('Geçersiz MCP protokol yanıtı.')
                if response.get('id') != identifier:
                    continue
                self.pending = None
                if 'error' in response:
                    raise RuntimeError('MCP: '+str(response['error'])[:1500])
                if not isinstance(response.get('result'), dict):
                    raise ValueError('MCP sonuç nesnesi eksik.')
                return response['result']
            if len(self.buffer) > self.MAX_MESSAGE:
                raise ValueError('MCP yanıtı 8 MB sınırını aştı.')
            for key, _ in self.selector.select(.05):
                block = os.read(key.fd, 65536)
                if not block:
                    self.selector.unregister(key.fileobj)
                    continue
                if key.data == 'stderr':
                    self.stderr.extend(block)
                    del self.stderr[:-65536]
                else:
                    self.buffer.extend(block)
            if len(self.buffer) > self.MAX_MESSAGE:
                raise ValueError('MCP yanıtı 8 MB sınırını aştı.')
            if not self.selector.get_map() or (self.process.poll() is not None and not self.buffer):
                raise RuntimeError('MCP bağlantısı kesildi: '+self.stderr.decode('utf-8','replace')[-1200:])

    def start(self):
        info = self.call('initialize', {'protocolVersion':'2025-11-25','capabilities':{},
            'clientInfo':{'name':'rea-copilot','version':'1'}}, timeout=15)
        self.notify('notifications/initialized', {})
        tools, cursor = {}, None
        for _ in range(4):
            result = self.call('tools/list', {} if cursor is None else {'cursor':cursor}, timeout=15)
            if not isinstance(result.get('tools'), list):
                raise ValueError('MCP araç listesi geçersiz.')
            for item in result['tools']:
                if not isinstance(item, dict) or not isinstance(item.get('name'), str):
                    raise ValueError('MCP araç kimliği geçersiz.')
                tools[item['name']] = item
            cursor = result.get('nextCursor')
            if not cursor:
                break
        if cursor or len(tools)>512:
            raise ValueError('MCP araç envanteri sınırı aşıldı.')
        return info.get('serverInfo', {}), tools

    def close(self):
        process = self.process
        children = owned_children(process.pid)
        try:
            if self.pending is not None and process.poll() is None:
                try:self.notify('notifications/cancelled', {'requestId':self.pending,'reason':'Copilot stopped'}, .3)
                except Exception:pass
            if self.opened and process.poll() is None:
                try:self.call('tools/call', {'name':'close_binary','arguments':{}}, timeout=2, ignore_cancel=True)
                except Exception:pass
            try:process.stdin.close()
            except OSError:pass
            try:process.wait(timeout=.7)
            except subprocess.TimeoutExpired:pass
            try:os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:pass
            signal_owned(children, signal.SIGTERM)
            try:process.wait(timeout=.3)
            except subprocess.TimeoutExpired:pass
            try:os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:pass
            signal_owned(children, signal.SIGKILL)
            process.wait()
        finally:
            self.selector.close()
            for stream in (process.stdout, process.stderr):
                stream.close()


# The model never receives a path/provider/snapshot/shell argument.
SCHEMAS = {
    'inspect_with_objdump': ('Inspect the selected file with GNU objdump. For architecture/format use file_headers; for section tables use section_headers; for function names use symbols; for assembly use disassemble.',
        {'operation':{'type':'string','enum':['file_headers','section_headers','symbols','disassemble']},'symbol':{'type':'string','maxLength':256,'description':'Only for operation=disassemble. Omit for file_headers, section_headers and symbols.'}}, ['operation']),
    'inspect_binary_layout': ('Inspect ELF layout and security-related file declarations of the selected file.', {}, []),
    'list_procedures': ('List functions in the selected file using Ghidra; use before decompiling an unknown function.', {}, []),
    'list_strings': ('List analyzed strings in the selected file using Ghidra.', {}, []),
    'search_strings': ('Find a literal string in the selected file using Ghidra.', {'pattern':{'type':'string','minLength':1,'maxLength':256}}, ['pattern']),
    'procedure_pseudo_code': ('Decompile one named function or 0x address using Ghidra; returns recovered code, not original source.', {'procedure':{'type':'string','minLength':1,'maxLength':256,'description':'Exact symbol name, e.g. main. Use 0x401000 only for a hexadecimal address. Never prefix a symbol name with 0x.'}}, ['procedure']),
    'procedure_assembly': ('Read the selected function assembly using Ghidra.', {'procedure':{'type':'string','minLength':1,'maxLength':256,'description':'Exact symbol name, e.g. main. Use 0x401000 only for a hexadecimal address. Never prefix a symbol name with 0x.'}}, ['procedure']),
}


class SelectedTargetTools:
    def __init__(self, client, path, inventory, emit, max_calls=8):
        self.client, self.path, self.inventory, self.emit = client, str(Path(path).absolute()), inventory, emit
        self.signature = target_signature(self.path)
        self.calls = 0
        self.max_calls = max_calls
        self.events = []
        self.ready = False
        self.available = {name for name in SCHEMAS if name in inventory}
        if not os.environ.get('REA_PWNTOOLS_PYTHON'):
            self.available.discard('inspect_binary_layout')
        if 'open_binary' not in inventory or 'provider_id' not in inventory['open_binary'].get('inputSchema',{}).get('properties',{}):
            self.available &= {'inspect_with_objdump','inspect_binary_layout'}
        if not self.available:
            raise ValueError('Bu MCP sunucusu desteklenen statik araçları bildirmedi.')

    def definitions(self):
        return [{'type':'function','function':{'name':name,'description':SCHEMAS[name][0],
            'parameters':{'type':'object','properties':SCHEMAS[name][1],'required':SCHEMAS[name][2],'additionalProperties':False}}} for name in SCHEMAS if name in self.available]

    def check(self):
        if target_signature(self.path) != self.signature:
            raise ValueError('Hedef dosya değişti; MCP analizi durduruldu.')
        self.client.check(self.client.deadline)

    def record(self, name, arguments, requested_by, operation):
        self.check()
        if self.calls >= self.max_calls:
            raise ValueError('MCP araç çağrısı bütçesi tükendi.')
        self.calls += 1
        event = {'id':'tool-'+str(self.calls),'tool':str(name),'arguments':arguments if isinstance(arguments,dict) else {'invalid_arguments':str(arguments)[:2000]},'requested_by':requested_by,'status':'running'}
        self.emit(dict(event))
        started = time.monotonic()
        try:
            result = operation()
            self.check()
            is_error = result.get('isError') is True
            structured = result.get('structuredContent')
            if isinstance(structured, dict) and structured.get('ok') is False:
                is_error = True
            event['status'] = 'error' if is_error else 'ok'
            if is_error:
                value = structured
                if not isinstance(value,dict):
                    try:
                        value=json.loads(next((b.get('text','') for b in result.get('content',[]) if b.get('type')=='text'),''))
                    except (ValueError,TypeError):value={}
                code=value.get('error',{}).get('code') if isinstance(value,dict) and isinstance(value.get('error'),dict) else None
                if code in ('provider_unavailable','unreadable_output'):
                    self.available.discard(name)
                    if name=='open_binary':
                        self.available &= {'inspect_with_objdump','inspect_binary_layout'}
            raw = json.dumps(result,ensure_ascii=False)
            event.update(output=raw[:131072], output_truncated=len(raw)>131072,
                         output_sha256=hashlib.sha256(raw.encode()).hexdigest())
            return result
        except (McpCancelled, TimeoutError):
            event['status']='cancelled' if self.client.stopped.is_set() else 'error'
            event['error']='İşlem durduruldu veya zaman sınırı aşıldı.'
            raise
        except Exception as exc:
            event.update(status='error', error=str(exc)[:2000])
            raise
        finally:
            event['elapsed']=round(time.monotonic()-started,3)
            self.events.append(event)
            self.emit(dict(event))

    def execute(self, name, arguments):
        def operation():
            if name not in self.available:
                raise ValueError('Bu araç statik analiz kapsamında izinli değil: '+str(name)[:80])
            if not isinstance(arguments, dict):
                raise ValueError('Araç parametreleri nesne olmalı.')
            supplied=dict(arguments)
            if name=='inspect_with_objdump' and supplied.get('symbol') in ('',None):
                supplied.pop('symbol',None)
            props, required = SCHEMAS[name][1:]
            if set(supplied)-set(props) or set(required)-set(supplied):
                raise ValueError('Araç parametreleri şemaya uymuyor; dosya/provider değiştirilemez.')
            for key,value in supplied.items():
                if not isinstance(value,str) or '\0' in value or '\n' in value or len(value)>256 or not value.strip():
                    raise ValueError('Geçersiz araç parametresi: '+key)
                if 'enum' in props[key] and value not in props[key]['enum']:
                    raise ValueError('Bu objdump işlemi izinli değil.')
            args = dict(supplied)
            if name in ('inspect_with_objdump','inspect_binary_layout'):
                args['path']=self.path
                if name=='inspect_with_objdump':
                    args['follow_debug_links']=False
                    if 'symbol' in args and args['operation']!='disassemble':
                        raise ValueError('Symbol yalnız disassemble ile kullanılabilir.')
            else:
                if not self.ready:
                    # Mark as opened before requesting so cancellation still attempts provider cleanup.
                    self.client.opened = True
                    opened = self.record('open_binary', {'path':self.path,'provider_id':'ghidra'}, 'prerequisite',
                        lambda:self.client.call('tools/call', {'name':'open_binary','arguments':{'path':self.path,'provider_id':'ghidra'}}, timeout=120))
                    if self.events[-1]['status']!='ok':
                        return opened
                    self.ready=True
                if name=='search_strings':
                    args.update(mode='literal',case_sensitive=False)
            return self.client.call('tools/call', {'name':name,'arguments':args}, timeout=90)
        return self.record(name, arguments, 'copilot', operation)


def validate_runs(runs):
    """Sessions retain audit data only; nothing in a restored log can execute a tool."""
    if not isinstance(runs,list) or len(runs)>12 or len(json.dumps(runs,ensure_ascii=False))>16*1024*1024:
        raise ValueError('Geçersiz veya çok büyük MCP günlüğü.')
    ids=set()
    for run in runs:
        if not isinstance(run,dict) or any(not isinstance(run.get(k),str) for k in ('id','target','provider_model','status')):
            raise ValueError('Geçersiz MCP oturum kaydı.')
        if not run['id'] or run['id'] in ids or any(len(run[k])>8192 for k in ('id','target','provider_model','status')):
            raise ValueError('Geçersiz MCP oturum kimliği.')
        ids.add(run['id'])
        if not isinstance(run.get('events'),list) or len(run['events'])>8:
            raise ValueError('Geçersiz MCP araç günlüğü.')
        for event in run['events']:
            if not isinstance(event,dict) or any(not isinstance(event.get(k),str) for k in ('id','tool','requested_by','status')) or not isinstance(event.get('arguments'),dict):
                raise ValueError('Geçersiz MCP araç kaydı.')
            if event['status'] not in ('running','ok','error','cancelled') or len(json.dumps(event,ensure_ascii=False))>384*1024:
                raise ValueError('Geçersiz MCP araç sonucu.')
            if 'output' in event and not isinstance(event['output'],str):
                raise ValueError('Geçersiz MCP araç çıktısı.')

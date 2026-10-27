"""Private, bounded MCP stdio session and a selected-file static tool boundary."""
import hashlib
from contextlib import contextmanager
import re
import json
import os
from pathlib import Path
import selectors
import signal
import stat
import subprocess
import time
from rea_analysis import (StaticAnalysis, ResultCache, digest_file, engine_identity,
                          memory_policy, signature, evidence, observation)


DEFAULT_ANALYSIS_TIMEOUT = 3600
DEFAULT_TOOL_TIMEOUT = 300
DEFAULT_GHIDRA_STARTUP_MS = 900000
GHIDRA_RESPONSE_GRACE = 30


class McpTimeout(TimeoutError):
    """A timeout identifies the actual operation and the budget that expired."""
    def __init__(self, operation, scope, limit, elapsed):
        self.operation, self.scope = operation, scope
        self.limit, self.elapsed = limit, elapsed
        super().__init__(f"{operation}: {scope} zaman sınırı doldu "
                         f"(sınır {limit:g} sn, geçen {elapsed:.1f} sn). "
                         "İşlem durduruldu; araç günlüğündeki tamamlanan sonuçlar korundu.")

    def details(self):
        return {'operation':self.operation, 'scope':self.scope,
                'limit_seconds':self.limit, 'elapsed_seconds':round(self.elapsed, 3)}


class McpCancelled(Exception):
    pass


def target_signature(path):
    return signature(path)


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

    def __init__(self, binary, stopped, deadline, started=None):
        self.binary = binary
        self.stopped, self.deadline = stopped, deadline
        self.started = time.monotonic() if started is None else started
        self.request_context = None
        self.last_operation = None
        environment = {k:v for k,v in os.environ.items() if k not in ('BUN_BE_BUN','HOPPER_TARGET_PATH','HOPPER_TARGET_KIND','HOPPER_LOADER_ARGS_JSON')}
        raw = environment.setdefault('REA_GHIDRA_STARTUP_TIMEOUT_MS', str(DEFAULT_GHIDRA_STARTUP_MS))
        if not environment.get('GHIDRA_HEADLESS_MAXMEM') and not environment.get('GHIDRA_MAXMEM'):
            environment['GHIDRA_HEADLESS_MAXMEM'] = memory_policy()['ghidra_heap']
        if not re.fullmatch(r'[1-9]\d*', raw) or int(raw) > 2147483647:
            raise ValueError('REA_GHIDRA_STARTUP_TIMEOUT_MS, 1..2147483647 arasında milisaniye olmalı.')
        self.ghidra_initial_timeout = int(raw)/1000 + GHIDRA_RESPONSE_GRACE
        self.process = subprocess.Popen([binary, '--mcp'], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, bufsize=0, start_new_session=True,
            env=environment)
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
            now = time.monotonic()
            if not ignore_cancel and self.deadline <= deadline:
                operation = self.request_context['operation'] if self.request_context else 'MCP analizi / son işlem: '+(self.last_operation or 'başlatma')
                raise McpTimeout(operation, 'toplam analiz', self.deadline-self.started, now-self.started)
            context = self.request_context or {'operation':'MCP iletişimi', 'limit':max(0, deadline-now), 'started':now}
            raise McpTimeout(context['operation'], context.get('scope','araç çağrısı'), context['limit'], now-context['started'])

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

    @contextmanager
    def request_budget(self, operation, timeout, ignore_cancel=False):
        started = time.monotonic()
        deadline = started + timeout
        if not ignore_cancel:
            deadline = min(self.deadline, deadline)
        previous = self.request_context
        self.request_context = {'operation':operation, 'limit':timeout, 'started':started,
                                'scope':'iletişim' if ignore_cancel else 'araç çağrısı'}
        try:
            yield deadline
        finally:
            self.request_context = previous

    def notify(self, method, params, timeout=1):
        with self.request_budget(method, timeout, True) as deadline:
            self.write({'jsonrpc':'2.0','method':method,'params':params}, deadline, True)

    def call(self, method, params, timeout=DEFAULT_TOOL_TIMEOUT, ignore_cancel=False, operation=None):
        if operation is None:
            operation = str(params.get('name', method)) if method == 'tools/call' else method
        self.last_operation = operation
        with self.request_budget(operation, timeout, ignore_cancel) as deadline:
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
            'clientInfo':{'name':'rea-copilot','version':'1'}}, timeout=30)
        self.notify('notifications/initialized', {})
        tools, cursor = {}, None
        for _ in range(4):
            result = self.call('tools/list', {} if cursor is None else {'cursor':cursor}, timeout=30)
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
        if getattr(self, '_closed', False):return
        self._closed = True
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
    'inspect_file': ('Quick bounded static preflight: file size, PE architecture, entry point, sections, entropy and possible packer indicators. No global Ghidra analysis.', {}, []),
    'quick_functions': ('Quick entry-point and symbol discovery with rabin2, without global analysis. Incomplete function inventory; use list_procedures only when full discovery is necessary.', {}, []),
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
    def __init__(self, client, path, inventory, emit, max_calls=8, digest=None, expected_signature=None):
        self.client, self.path, self.inventory, self.emit = client, str(Path(path).absolute()), inventory, emit
        self.signature = target_signature(self.path)
        if expected_signature is not None and self.signature != expected_signature:
            raise ValueError('Hedef ön inceleme sırasında değişti; analiz başlatılmadı.')
        self.calls = 0
        self.max_calls = max_calls
        self.events = []
        self.ready = False
        self.ghidra_initialized = False
        self.primary_failed = None
        self.analysis = StaticAnalysis(self.path, self.check)
        self.cache = None
        if getattr(client, 'binary', None):
            self.cache = ResultCache(digest or digest_file(self.path, self.check), engine_identity(client.binary,self.check),target=self.path)
        self.available = {name for name in SCHEMAS if name in inventory}
        if not os.environ.get('REA_PWNTOOLS_PYTHON'):
            self.available.discard('inspect_binary_layout')
        if 'open_binary' not in inventory or 'provider_id' not in inventory['open_binary'].get('inputSchema',{}).get('properties',{}):
            self.available &= {'inspect_with_objdump','inspect_binary_layout'}
        self.available.update(('inspect_file','quick_functions'))
        if not self.available:
            raise ValueError('Bu MCP sunucusu desteklenen statik araçları bildirmedi.')

    def definitions(self):
        return [{'type':'function','function':{'name':name,'description':SCHEMAS[name][0],
            'parameters':{'type':'object','properties':SCHEMAS[name][1],'required':SCHEMAS[name][2],'additionalProperties':False}}} for name in SCHEMAS if name in self.available]

    def check(self):
        if target_signature(self.path) != self.signature:
            raise ValueError('Hedef dosya değişti; MCP analizi durduruldu.')
        self.client.check(self.client.deadline)

    def record(self, name, arguments, requested_by, operation, phase=None, timeout=None):
        self.check()
        if self.calls >= self.max_calls:
            raise ValueError('MCP araç çağrısı bütçesi tükendi.')
        self.calls += 1
        event = {'id':'tool-'+str(self.calls),'tool':str(name),'arguments':arguments if isinstance(arguments,dict) else {'invalid_arguments':str(arguments)[:2000]},'requested_by':requested_by,'status':'running'}
        if phase is not None:event['phase'] = phase
        if timeout is not None:event['timeout_seconds'] = timeout
        self.emit(dict(event))
        started = time.monotonic()
        try:
            result = operation()
            self.check()
            is_error = result.get('isError') is True
            structured = result.get('structuredContent')
            if result.get('cache_hit'):event['cache_hit'] = True
            if isinstance(structured, dict):
                for field in ('cache_hit','engine','partial','fallback_from'):
                    if field in structured:event[field] = structured[field]
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
                if code in ('provider_unavailable','unreadable_output') and not self.cache:
                    self.available.discard(name)
                    if name=='open_binary':
                        self.available &= {'inspect_with_objdump','inspect_binary_layout'}
            raw = json.dumps(result,ensure_ascii=False)
            event.update(output=raw[:131072], output_truncated=len(raw)>131072,
                         output_sha256=hashlib.sha256(raw.encode()).hexdigest())
            return result
        except (McpCancelled, TimeoutError) as exc:
            event['status']='cancelled' if self.client.stopped.is_set() else 'error'
            event['error']=str(exc)
            if isinstance(exc, McpTimeout):event['timeout'] = exc.details()
            raise
        except Exception as exc:
            event.update(status='error', error=str(exc)[:2000])
            raise
        finally:
            event['elapsed']=round(time.monotonic()-started,3)
            self.events.append(event)
            self.emit(dict(event))

    def execute(self, name, arguments, requested_by='copilot'):
        uses_ghidra = name not in ('inspect_with_objdump','inspect_binary_layout','inspect_file','quick_functions')
        initial = uses_ghidra and not self.ghidra_initialized
        timeout = self.client.ghidra_initial_timeout if initial else DEFAULT_TOOL_TIMEOUT
        phase = 'Ghidra ilk analiz' if initial else 'Ghidra' if uses_ghidra else 'statik araç'
        fallback_active = [False]
        def alternative(supplied, reason):
            fallback_active[0] = True
            cached=self.cache.get('alternative/'+name,supplied) if self.cache else None
            if cached is not None:
                self.check();cached['cache_hit']=True
                return cached
            result=self.analysis.fallback(name,supplied,reason)
            if self.cache:self.cache.put('alternative/'+name,supplied,result)
            return result
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
            cached = self.cache.get(name, supplied) if self.cache and name != 'inspect_file' else None
            if cached is not None:
                self.check()
                cached['cache_hit'] = True
                return cached
            def save(result):
                self.check()
                structured = result.get('structuredContent')
                if not isinstance(structured, dict):structured={}
                if not result.get('isError') and structured.get('ok') is not False and not structured.get('fallback_from'):
                    if self.cache:self.cache.put(name, supplied, result)
                return result
            if name == 'inspect_file':
                return evidence('static-preflight', name, self.analysis.preflight())
            if name == 'quick_functions':
                return save(self.analysis.quick_functions())
            if uses_ghidra and self.cache and memory_policy()['available_bytes'] < 768*1024**2:
                return alternative(supplied, 'Ghidra için kullanılabilir bellek 768 MiB altında; JVM başlatılmadı.')
            if uses_ghidra and self.primary_failed is not None:
                return alternative(supplied, self.primary_failed)
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
                        lambda:self.client.call('tools/call', {'name':'open_binary','arguments':{'path':self.path,'provider_id':'ghidra'}}, timeout=self.client.ghidra_initial_timeout, operation='Ghidra ilk analiz / open_binary'),
                        phase='Ghidra ilk analiz', timeout=self.client.ghidra_initial_timeout)
                    if self.events[-1]['status']!='ok':
                        if self.cache:
                            self.primary_failed = 'Ghidra open_binary başarısız: '+json.dumps(opened,ensure_ascii=False)[:1200]
                            return alternative(supplied, self.primary_failed)
                        return opened
                    self.ready=True
                if name=='search_strings':
                    args.update(mode='literal',case_sensitive=False)
            try:
                result = self.client.call('tools/call', {'name':name,'arguments':args}, timeout=timeout, operation=phase+' / '+name)
            except (TimeoutError, RuntimeError) as exc:
                self.check()  # Cancellation/overall deadline must never start another engine.
                if not uses_ghidra or not self.cache:raise
                self.primary_failed = str(exc)
                self.client.close()
                self.available.discard('inspect_with_objdump');self.available.discard('inspect_binary_layout')
                return alternative(supplied, exc)
            if uses_ghidra and (result.get('isError') or result.get('structuredContent',{}).get('ok') is False) and self.cache:
                return alternative(supplied, json.dumps(result,ensure_ascii=False)[:1200])
            if name=='procedure_pseudo_code' and self.cache:
                value=observation(result)
                code=value.get('normalized_result',value.get('observed_result'))
                if not isinstance(code,str) or not code.strip():
                    return alternative(supplied, 'Ghidra seçili fonksiyon için kod gövdesi üretmedi.')
            if uses_ghidra and not result.get('isError') and not (isinstance(result.get('structuredContent'),dict) and result['structuredContent'].get('ok') is False):
                self.ghidra_initialized = True
            return save(result)
        def attempt():
            try:return operation()
            except (TimeoutError, RuntimeError) as exc:
                self.check()
                if fallback_active[0] or not uses_ghidra or not self.cache:raise
                self.primary_failed=str(exc)
                self.client.close()
                self.available.discard('inspect_with_objdump');self.available.discard('inspect_binary_layout')
                return alternative(arguments, exc)
        return self.record(name, arguments, requested_by, attempt, phase=phase, timeout=timeout)


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

"""Official Sign in with ChatGPT public-client flow; no API keys or browser cookies.
Credentials belong to REA only. Existing Codex/ChatGPT credentials are never read.
"""
import copy
import contextlib
import fcntl
import hashlib
import http.client
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import secrets
import socket
import stat
import threading
import time
from urllib.parse import urlencode, urlsplit, parse_qs
import uuid
from PyQt5.QtCore import QThread, pyqtSignal
from rea_copilot import McpCopilotWorker, size, excerpt
from rea_mcp import McpCancelled

ISSUER = 'https://auth.openai.com'
RESOURCE = 'https://api.openai.com/v1'
SCOPES = 'openid profile email offline_access resource.invoke chatgpt.tokens.use.direct'
PLAN_SCOPES = {'resource.invoke', 'chatgpt.tokens.use.direct'}
from rehkc_paths import config_dir
AUTH_DIR = config_dir()/'chatgpt'


def error_message(code, status=None):
    safe = str(code) if isinstance(code,str) and len(code)<100 and all(c.isalnum() or c=='_' for c in code) else 'request_failed'
    if safe in ('subscription_sharing_usage_limit_exceeded','subscription_sharing_usage_unavailable') or status==429:
        return 'ChatGPT plan kullanım sınırı/erişimi: '+safe+'. Kullanımı yönet düğmesinden ChatGPT ayarlarını kontrol edin.'
    if safe in ('invalid_grant','invalid_token') or status==401:
        return 'ChatGPT oturumu yenilenemedi; Continue with ChatGPT ile yeniden giriş yapın.'
    return 'ChatGPT isteği tamamlanamadı'+(' (HTTP '+str(status)+')' if status else '')+': '+safe


def https_json(url, body=None, token=None, form=False, empty_ok=False):
    """Pinned HTTPS origins; never follow redirects or include remote response bodies in errors."""
    u=urlsplit(url)
    if u.scheme!='https' or u.hostname not in ('auth.openai.com','api.openai.com') or u.port not in (None,443) or u.username or u.password or u.fragment:
        raise ValueError('ChatGPT için resmî HTTPS adresi gerekli.')
    c=http.client.HTTPSConnection(u.hostname,timeout=15)
    headers={'Accept':'application/json'}
    if token:headers['Authorization']='Bearer '+token
    data=None
    if body is not None:
        headers['Content-Type']='application/x-www-form-urlencoded' if form else 'application/json'
        data=(urlencode(body) if form else json.dumps(body)).encode()
    try:
        c.request('POST' if body is not None else 'GET',u.path+('?' +u.query if u.query else ''),data,headers)
        r=c.getresponse();raw=r.read(4*1024*1024+1)
        if len(raw)>4*1024*1024:raise ValueError('ChatGPT yanıtı boyut sınırını aştı.')
        if not 200<=r.status<300:
            try:
                e=json.loads(raw).get('error',{});code=e.get('code') or e.get('type') if isinstance(e,dict) else e
            except (ValueError,AttributeError):code='request_failed'
            raise ValueError(error_message(code,r.status))
        if not raw and empty_ok:return {}
        d=json.loads(raw)
        if not isinstance(d,dict):raise ValueError('Geçersiz ChatGPT yanıtı.')
        return d
    finally:c.close()


class ChatGPTStore:
    """Owner-only atomic store; flock serializes rotating refreshes across REA processes."""
    def __init__(self, directory=None):
        self.directory=Path(directory) if directory is not None else AUTH_DIR
        self.path=self.directory/'accounts.json'

    @contextlib.contextmanager
    def locked(self):
        self.directory.mkdir(mode=0o700,parents=True,exist_ok=True)
        st=self.directory.lstat()
        if not stat.S_ISDIR(st.st_mode) or st.st_uid!=os.getuid():raise ValueError('ChatGPT kayıt dizini güvenli değil.')
        self.directory.chmod(0o700)
        fd=os.open(str(self.directory/'accounts.lock'),os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
        try:
            end=time.monotonic()+20
            while True:
                try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);break
                except BlockingIOError:
                    if time.monotonic()>end:raise TimeoutError('ChatGPT oturumu başka bir işlemde; tekrar deneyin.')
                    time.sleep(.05)
            yield
        finally:os.close(fd)

    def _read(self):
        if not self.path.exists():return {'host_id':'urn:uuid:'+str(uuid.uuid4()),'active':None,'accounts':{}}
        fd=os.open(str(self.path),os.O_RDONLY|os.O_NOFOLLOW)
        with os.fdopen(fd) as f:
            st=os.fstat(f.fileno())
            if st.st_uid!=os.getuid() or stat.S_IMODE(st.st_mode)&0o077 or st.st_size>1024*1024:
                raise ValueError('ChatGPT kimlik dosyası yalnız kullanıcıya açık ve en fazla 1 MiB olmalı.')
            d=json.load(f)
        if not isinstance(d,dict) or not isinstance(d.get('accounts'),dict) or not isinstance(d.get('host_id'),str):raise ValueError('ChatGPT hesap kaydı geçersiz.')
        return d

    def _write(self,d):
        temp=self.directory/('accounts-'+uuid.uuid4().hex+'.tmp')
        try:
            fd=os.open(str(temp),os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
            with os.fdopen(fd,'w') as f:json.dump(d,f);f.flush();os.fsync(f.fileno())
            os.replace(temp,self.path)
        finally:
            if temp.exists():temp.unlink()

    @staticmethod
    def public(d):
        result=[]
        for key,a in d['accounts'].items():
            result.append({'id':key,'label':a.get('email') or a.get('name') or 'ChatGPT hesabı',
                'registration':a['client_id'][-8:],'signed_in':bool(a.get('access_token')),
                'plan_enabled':PLAN_SCOPES<=set(a.get('scopes',[])) and bool(a.get('access_token')), 'welcomed':bool(a.get('welcomed'))})
        return {'active':d.get('active'),'accounts':result}

    def summary(self):
        if not self.path.exists():return {'active':None,'accounts':[]}
        with self.locked():return self.public(self._read())

    def prepare(self,new=False):
        with self.locked():
            d=self._read();self._write(d)
            a=copy.deepcopy(d['accounts'].get(d.get('active'))) if not new else None
            if not a and d.get('pending_registration'):
                a={'client_id':d['pending_registration'],'subject':None}
            return d['host_id'],a

    def retain_registration(self,client_id):
        with self.locked():
            d=self._read();d['pending_registration']=client_id;self._write(d)

    def activate(self,key):
        with self.locked():
            d=self._read()
            if key not in d['accounts']:raise ValueError('ChatGPT hesabı bulunamadı.')
            d['active']=key;self._write(d)
            return self.public(d)

    def save_registration(self,host_id,client_id,claims,tokens,old=None):
        if old and ((old.get('subject') and claims['sub']!=old['subject']) or client_id!=old['client_id']):
            raise ValueError('Dönen ChatGPT hesabı seçili kayıtla eşleşmedi; eski oturum korundu.')
        scopes=tokens.get('scope','').split()
        if tokens.get('token_type','').lower()!='bearer' or not isinstance(tokens.get('access_token'),str):raise ValueError('ChatGPT kimlik yanıtı eksik.')
        key=hashlib.sha256((claims['iss']+'|'+claims['sub']+'|'+client_id).encode()).hexdigest()[:24]
        a={'client_id':client_id,'subject':claims['sub'],'issuer':claims['iss'],
           'email':claims.get('email',''),'name':claims.get('name',''),'scopes':scopes,
           'access_token':tokens['access_token'],'refresh_token':tokens.get('refresh_token',''),
           'id_token':tokens['id_token'],'expires_at':time.time()+int(tokens['expires_in']),
           'earliest_refresh_at':tokens.get('earliest_refresh_at',0)}
        with self.locked():
            d=self._read()
            if d['host_id']!=host_id:raise ValueError('ChatGPT ana makine kimliği değişti.')
            a['welcomed']=bool(d['accounts'].get(key,{}).get('welcomed'))
            d['accounts'][key]=a;d['active']=key
            if d.get('pending_registration')==client_id:d.pop('pending_registration',None)
            self._write(d)
            return self.public(d)

    def mark_welcomed(self):
        with self.locked():
            d=self._read();a=d['accounts'].get(d.get('active'))
            if a:a['welcomed']=True;self._write(d)

    def token(self,account_id=None):
        with self.locked():
            d=self._read();key=account_id or d.get('active');a=d['accounts'].get(key,{})
            if not a.get('access_token'):raise ValueError('Continue with ChatGPT ile giriş yapın.')
            if not PLAN_SCOPES<=set(a.get('scopes',[])):raise ValueError('ChatGPT plan kullanım izni verilmedi; yeniden giriş yapıp izin verin.')
            if a.get('expires_at',0)<time.time()+60:
                if not a.get('refresh_token'):raise ValueError('ChatGPT oturumu sona erdi; yeniden giriş yapın.')
                t=https_json(ISSUER+'/api/accounts/oauth/token',{'grant_type':'refresh_token','client_id':a['client_id'],
                    'refresh_token':a['refresh_token'],'resource':RESOURCE},form=True)
                if not t.get('access_token') or not t.get('refresh_token') or t.get('token_type','').lower()!='bearer':raise ValueError('ChatGPT yenileme yanıtı eksik; eski kayıt korundu.')
                scopes=t.get('scope',' '.join(a['scopes'])).split()
                if not PLAN_SCOPES<=set(scopes):raise ValueError('Yenilenen oturumda ChatGPT plan kullanım izni yok.')
                a.update(access_token=t['access_token'],refresh_token=t['refresh_token'],expires_at=time.time()+int(t['expires_in']),scopes=scopes)
                if t.get('id_token'):a['id_token']=t['id_token']
                self._write(d)
            return a['access_token']

    def sign_out(self):
        confirmed=True
        with self.locked():
            d=self._read();a=d['accounts'].get(d.get('active'))
            if not a:return self.public(d),confirmed
            if a.get('refresh_token'):
                try:
                    meta=https_json(ISSUER+'/.well-known/openid-configuration');url=meta['revocation_endpoint']
                    if urlsplit(url).hostname!='auth.openai.com':raise ValueError('Geçersiz iptal adresi.')
                    https_json(url,{'token':a['refresh_token'],'token_type_hint':'refresh_token','client_id':a['client_id']},form=True,empty_ok=True)
                except Exception:confirmed=False
            for key in ('access_token','refresh_token','id_token','expires_at','earliest_refresh_at'):a.pop(key,None)
            self._write(d);return self.public(d),confirmed


def validate_identity(id_token,client_id,nonce):
    import jwt
    metadata=https_json(ISSUER+'/.well-known/openid-configuration')
    if metadata.get('issuer')!=ISSUER or urlsplit(metadata.get('jwks_uri','')).hostname!='auth.openai.com':raise ValueError('OpenAI kimlik sağlayıcısı doğrulanamadı.')
    header=jwt.get_unverified_header(id_token)
    if header.get('alg')!='RS256':raise ValueError('Desteklenmeyen OpenAI kimlik imzası.')
    keys=https_json(metadata['jwks_uri']).get('keys',[])
    matching=[k for k in keys if k.get('kid')==header.get('kid') and k.get('kty')=='RSA' and k.get('use','sig')=='sig']
    if len(matching)!=1:raise ValueError('OpenAI imza anahtarı bulunamadı.')
    key=jwt.PyJWK.from_dict(matching[0],algorithm='RS256').key
    claims=jwt.decode(id_token,key,algorithms=['RS256'],audience=client_id,issuer=ISSUER,
        options={'require':['exp','sub','iss','aud','nonce']},leeway=20)
    if not isinstance(claims.get('nonce'),str) or not secrets.compare_digest(claims['nonce'],nonce):raise ValueError('OpenAI giriş nonce değeri eşleşmedi.')
    if isinstance(claims['aud'],list) and len(claims['aud'])>1 and claims.get('azp')!=client_id:raise ValueError('OpenAI yetkili istemcisi eşleşmedi.')
    return claims


class ChatGPTAccountWorker(QThread):
    completed=pyqtSignal(dict)
    failed=pyqtSignal(str)
    open_browser=pyqtSignal(str)
    def __init__(self,store,operation='login',new=False,parent=None):
        super().__init__(parent);self.store,self.operation,self.new=store,operation,new
        self.stopped=threading.Event()
    def cancel(self):self.stopped.set()
    def run(self):
        try:
            if self.operation=='logout':
                result,confirmed=self.store.sign_out();result['revocation_confirmed']=confirmed;self.completed.emit(result);return
            if self.stopped.is_set():raise McpCancelled('ChatGPT girişi durduruldu.')
            host,old=self.store.prepare(self.new);state=secrets.token_urlsafe(32);nonce=secrets.token_urlsafe(32);verifier=secrets.token_urlsafe(64)
            outcome={};cancel=self.stopped
            class Handler(BaseHTTPRequestHandler):
                def log_message(self,*args):pass
                def do_GET(self):
                    parsed=urlsplit(self.path)
                    params=parse_qs(parsed.query,keep_blank_values=True)
                    valid=(len(self.path)<8192 and parsed.path=='/auth/callback' and self.headers.get('Host')=='127.0.0.1:'+str(self.server.server_port)
                        and all(len(v)==1 for v in params.values()) and secrets.compare_digest(params.get('state',[''])[0].encode('utf-8'),state.encode('utf-8')))
                    self.send_response(200 if valid else 400);self.send_header('Content-Type','text/plain; charset=utf-8');self.send_header('Cache-Control','no-store');self.send_header('Referrer-Policy','no-referrer');self.end_headers()
                    self.wfile.write(('Giriş alındı. REA penceresine dönebilirsiniz.' if valid else 'Geçersiz giriş dönüşü.').encode())
                    if valid:outcome.update({k:v[0] for k,v in params.items()})
            with HTTPServer(('127.0.0.1',0),Handler) as server:
                server.timeout=.2;redirect='http://127.0.0.1:'+str(server.server_port)+'/auth/callback'
                params={'client_id':old['client_id'] if old else 'dynamic_agent_client','ext_agent_host_id':host,
                    'response_type':'code','redirect_uri':redirect,'scope':SCOPES,'resource':RESOURCE,'state':state,
                    'nonce':nonce,'code_challenge_method':'S256','code_challenge':__import__('base64').urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip('=')}
                if old:
                    if old.get('id_token'):params['id_token_hint']=old['id_token']
                    if old.get('email'):params['login_hint']=old['email']
                else:params['agent_name_hint']='REA'
                self.open_browser.emit(ISSUER+'/api/accounts/authorize?'+urlencode(params))
                end=time.monotonic()+600
                while not outcome and not cancel.is_set() and time.monotonic()<end:server.handle_request()
            if cancel.is_set():raise McpCancelled('ChatGPT girişi durduruldu.')
            if not outcome:raise ValueError('ChatGPT giriş süresi doldu; tekrar deneyin.')
            if outcome.get('error'):raise ValueError('ChatGPT girişi/plan izni tamamlanmadı. Tekrar giriş yapabilirsiniz.')
            client_id=outcome.get('client_id') or (old['client_id'] if old else '')
            if not client_id or client_id=='dynamic_agent_client' or len(client_id)>256 or (old and client_id!=old['client_id']):raise ValueError('ChatGPT istemci kaydı doğrulanamadı.')
            code=outcome.get('code','')
            if not code or len(code)>4096:raise ValueError('ChatGPT giriş kodu eksik.')
            if not old or not old.get('subject'):self.store.retain_registration(client_id)
            tokens=https_json(ISSUER+'/api/accounts/oauth/token',{'grant_type':'authorization_code','client_id':client_id,
                'code':code,'code_verifier':verifier,'redirect_uri':redirect,'resource':RESOURCE},form=True)
            claims=validate_identity(tokens['id_token'],client_id,nonce)
            if cancel.is_set():raise McpCancelled('ChatGPT girişi durduruldu; önceki hesap korundu.')
            self.completed.emit(self.store.save_registration(host,client_id,claims,tokens,old))
        except Exception as exc:
            # Never forward token endpoint bodies, callback URLs, token values or JWT parser details.
            message=str(exc) if isinstance(exc,(ValueError,McpCancelled,TimeoutError)) and ('ChatGPT' in str(exc) or 'OpenAI' in str(exc)) else 'ChatGPT girişi tamamlanamadı; bağlantıyı kontrol edip yeniden deneyin.'
            self.failed.emit(message[:600])


class CloudModelListWorker(QThread):
    completed=pyqtSignal(list);failed=pyqtSignal(str);connection_received=pyqtSignal(str);memory_received=pyqtSignal(dict)
    def __init__(self,store,parent=None):super().__init__(parent);self.store=store;self.names={}
    def run(self):
        try:
            data=https_json(RESOURCE+'/models',token=self.store.token()).get('models')
            if not isinstance(data,list):raise ValueError('ChatGPT model kataloğu geçersiz.')
            visible=[m for m in data if isinstance(m,dict) and m.get('visibility')=='list' and isinstance(m.get('slug'),str) and isinstance(m.get('display_name'),str)]
            if len(visible)>256:raise ValueError('ChatGPT model kataloğu sınırı aşıldı.')
            self.names={m['slug']:m['display_name'] for m in visible};self.connection_received.emit('Bağlı')
            self.memory_received.emit({'states':{},'error':''});self.completed.emit(list(self.names))
        except Exception as exc:self.connection_received.emit('API / oturum hatası');self.failed.emit(str(exc)[:600])


def response_input(messages, native_groups):
    items=[];instructions=[]
    for m in messages:
        if m['role']=='system':instructions.append(m['content']);continue
        if m['role']=='tool':items.append({'type':'function_call_output','call_id':m['tool_call_id'],'output':m['content']});continue
        if m.get('tool_calls'):
            key=m['tool_calls'][0]['id']
            if key not in native_groups:raise ValueError('ChatGPT araç turu eşleşmesi eksik.')
            items.extend(copy.deepcopy(native_groups[key]));continue
        items.append({'role':m['role'],'content':m['content']})
    return '\n'.join(instructions),items


def cloud_tools(tools):
    if not tools:return []
    return [{'type':'namespace','name':'rea_tools','description':'Selected-file static REA analysis only.',
        'tools':[{'type':'function',**t['function'],'strict':False} for t in tools]}]


class ResponsesTransport:
    def model_round(self,messages,tools,require_tools=False):
        self.check()
        if hasattr(self,'note_wait'):self.note_wait('ChatGPT oturum doğrulaması',15)
        token=self.store.token(self.account_id);self.check()
        instructions,items=response_input(messages,self.native_groups)
        payload={'model':self.model,'instructions':instructions,'input':items,'store':False,'stream':True,'include':['reasoning.encrypted_content']}
        if tools:payload.update(tools=cloud_tools(tools),tool_choice='required' if require_tools else 'auto')
        # No API key path, max_output_tokens, temperature, hosted MCP, previous_response_id, or tool_search.
        conn=http.client.HTTPSConnection('api.openai.com',timeout=8);self.connection=conn
        text=[];terminal=False;output=[];completed_items={}
        try:
            if hasattr(self,'note_wait'):self.note_wait('ChatGPT bağlantısı',8)
            conn.connect();self.active_socket=conn.sock
            wait_limit=min(90,max(1,self.timeout-(time.monotonic()-self.started)))
            self.active_socket.settimeout(wait_limit)
            if hasattr(self,'note_wait'):self.note_wait('ChatGPT yanıtı / '+self.model[:80],wait_limit)
            self.check();conn.request('POST','/v1/responses',json.dumps(payload).encode(),{'Authorization':'Bearer '+token,'Content-Type':'application/json','Accept':'text/event-stream'})
            response=conn.getresponse();self.connection_received.emit('Bağlı' if response.status==200 else 'HTTP '+str(response.status))
            if response.status!=200:
                raw=response.read(8192)
                try:code=json.loads(raw).get('error',{}).get('code','request_failed')
                except (ValueError,AttributeError):code='request_failed'
                raise ValueError(error_message(code,response.status))
            content_type=response.getheader('Content-Type')
            if content_type and 'text/event-stream' not in content_type.lower():raise ValueError('ChatGPT SSE akışı alınamadı.')
            # Some transports omit Content-Type; strict SSE framing and a genuine
            # response.completed event below are still required before any tool executes.
            received=0;lines=[]
            while True:
                self.check()
                if hasattr(self,'note_wait'):self.note_wait('ChatGPT akışı / '+self.model[:80],wait_limit)
                raw=response.readline(1048577);received+=len(raw)
                if len(raw)>1048576 or received>4*1024*1024:raise ValueError('ChatGPT akış boyut sınırı aşıldı.')
                if not raw:break
                line=raw.decode().rstrip('\r\n')
                if line.startswith('data:'):lines.append(line[5:].lstrip());continue
                if line or not lines:continue
                value='\n'.join(lines);lines=[]
                if value=='[DONE]':break
                event=json.loads(value);kind=event.get('type');r=event.get('response',{})
                actual=r.get('model')
                if isinstance(actual,str) and actual:self.actual_model=actual;self.model_received.emit(actual)
                if kind=='response.output_text.delta':
                    delta=event.get('delta','')
                    if not isinstance(delta,str) or sum(map(len,self.pieces))+len(delta)>131072:raise ValueError('ChatGPT yanıt metni sınırı aşıldı.')
                    if self.first_text is None:self.first_text=time.monotonic()-self.started
                    text.append(delta);self.pieces.append(delta);self.chunk_received.emit(delta)
                elif kind=='response.output_item.done':
                    index=event.get('output_index');item=event.get('item')
                    if type(index) is not int or not 0<=index<256 or not isinstance(item,dict):raise ValueError('ChatGPT akış öğesi geçersiz.')
                    if index in completed_items and completed_items[index]!=item:raise ValueError('ChatGPT yinelenen akış öğesi tutarsız.')
                    completed_items[index]=item
                elif kind=='response.completed':
                    if r.get('status')!='completed':raise ValueError('ChatGPT yanıtı tamamlanmadı.')
                    output=r.get('output',[])
                    if not isinstance(output,list):raise ValueError('ChatGPT çıktı yapısı geçersiz.')
                    if not output and completed_items:
                        if sorted(completed_items)!=list(range(len(completed_items))):raise ValueError('ChatGPT tamamlanan akış öğeleri eksik.')
                        output=[completed_items[i] for i in sorted(completed_items)]
                    terminal=True;break
                elif kind in ('response.failed','response.incomplete','error'):
                    error=r.get('error') or event.get('error') or {};raise ValueError(error_message(error.get('code',kind) if isinstance(error,dict) else kind))
            if not terminal:raise ValueError('ChatGPT akışı response.completed olmadan kesildi; araç çağrıları çalıştırılmadı.')
            if not isinstance(output,list):raise ValueError('ChatGPT çıktı yapısı geçersiz.')
            calls=[]
            for item in output:
                if item.get('type')=='function_call':
                    if not tools or item.get('namespace')!='rea_tools' or item.get('status','completed')!='completed':raise ValueError('ChatGPT izinli araç alanı dışında çağrı döndürdü.')
                    call_id=item.get('call_id');name=item.get('name');args=item.get('arguments')
                    if not isinstance(call_id,str) or not call_id or len(call_id)>128 or not isinstance(name,str) or len(name)>80 or not isinstance(args,str) or len(args)>16384:raise ValueError('Geçersiz ChatGPT araç çağrısı.')
                    calls.append({'id':call_id,'type':'function','function':{'name':name,'arguments':args}})
                elif item.get('type') not in ('reasoning','message'):raise ValueError('ChatGPT desteklenmeyen bir işlem döndürdü; çalıştırılmadı.')
            if len(calls)>4 or len({c['id'] for c in calls})!=len(calls):raise ValueError('ChatGPT araç çağrısı sayısı/kimliği geçersiz.')
            if calls:self.native_groups[calls[0]['id']]=output
            return ''.join(text),calls
        finally:conn.close();self.connection=None;self.active_socket=None


class CloudCopilotWorker(ResponsesTransport,McpCopilotWorker):
    def __init__(self,store,model,messages,target,rea_bin,context_limit=12000,session_pool=None):
        self.store=store;self.account_id=store.summary()['active'];self.native_groups={}
        super().__init__(RESOURCE,'',model,messages,target,rea_bin,context_limit=context_limit,provider='chatgpt',session_pool=session_pool)
    def fit(self,tools):
        messages=super().fit(tools)
        # Native encrypted reasoning and namespace wrappers also count toward the character budget.
        while True:
            instructions,items=response_input(messages,self.native_groups)
            cost=size({'instructions':instructions,'input':items})+size(cloud_tools(tools))
            if cost<=self.context_limit:return messages
            if self.history:self.history.pop(0)
            elif len(self.rounds)>1:self.rounds.pop(0)
            elif self.rounds:
                responses=[m for m in self.rounds[-1] if m['role']=='tool' and len(m['content'])>350]
                if not responses:raise ValueError('ChatGPT araç/akıl yürütme verisi bağlam sınırını aştı; MCP günlüğü korundu.')
                m=max(responses,key=lambda m:len(m['content']));m['content']=excerpt(m['content'],max(300,len(m['content'])//2))
            else:raise ValueError('ChatGPT araç şeması ve mesajı bağlam sınırını aşıyor; taslak korundu.')
            messages=super().fit(tools)


class CloudChatWorker(ResponsesTransport,QThread):
    log_line=pyqtSignal(str,str);chunk_received=pyqtSignal(str);completed=pyqtSignal(str);cancelled=pyqtSignal(str);failed=pyqtSignal(str)
    connection_received=pyqtSignal(str);model_received=pyqtSignal(str);metrics_received=pyqtSignal(dict)
    is_mcp=False
    def __init__(self,store,model,messages):
        super().__init__();self.store=store;self.account_id=store.summary()['active'];self.model=model;self.messages=copy.deepcopy(messages)
        self.native_groups={};self.stopped=threading.Event();self.timeout=300;self.started=None;self.pieces=[];self.actual_model='';self.first_text=None;self.active_socket=self.connection=None
    def cancel(self):McpCopilotWorker.cancel(self)
    def check(self):
        if self.stopped.is_set():raise McpCancelled('ChatGPT isteği durduruldu.')
        if self.started is not None and time.monotonic()-self.started>self.timeout:raise TimeoutError('ChatGPT isteği zaman sınırını aştı.')
    def run(self):
        self.started=time.monotonic();outcome='Hata';error=None
        try:
            text,calls=self.model_round(self.messages,[])
            if calls or not text.strip():raise ValueError('ChatGPT görünür sohbet yanıtı üretmedi.')
            self.check();outcome='Tamamlandı'
        except McpCancelled:outcome='Durduruldu'
        except Exception as exc:
            if self.stopped.is_set():outcome='Durduruldu'
            else:error=str(exc)[:600]
        self.metrics_received.emit({'model':self.actual_model,'elapsed':time.monotonic()-self.started,'first_text':self.first_text,'outcome':outcome})
        if outcome=='Durduruldu':self.cancelled.emit(''.join(self.pieces))
        elif error:self.failed.emit(error)
        else:self.completed.emit(''.join(self.pieces))

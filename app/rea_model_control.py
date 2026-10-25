"""Explicit model memory control through native LM Studio / Ollama HTTP APIs.
No downloads, file deletion, shell commands or generated prompts.
"""
import http.client
import json
import socket
import threading
import time
from urllib.parse import urlsplit
from PyQt5.QtCore import QThread, pyqtSignal


class ModelControlWorker(QThread):
    completed = pyqtSignal(dict)
    failed = pyqtSignal(str)
    progress = pyqtSignal(str)

    def __init__(self, provider, server_base, api_key, model, operation, parent=None, load_configs=None):
        super().__init__(parent)
        self.provider, self.server_base, self.api_key = provider, server_base.rstrip('/'), api_key
        self.model, self.operation = model, operation
        self.stopped = threading.Event()
        self.connection = None
        self.active_socket = None
        self.load_configs = dict(load_configs or {})
        self.captured_load_configs = {}

    def cancel(self):
        self.stopped.set()
        sock = self.active_socket
        if sock is not None:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            sock.close()

    def check(self):
        if self.stopped.is_set():
            raise RuntimeError('İstemci işlemi durduruldu; sunucudaki durum yeniden kontrol edilmelidir.')

    def request(self, path, body=None):
        self.check()
        url = urlsplit(self.server_base)
        if url.scheme not in ('http', 'https') or not url.hostname or url.username or url.password or url.query or url.fragment:
            raise ValueError('Model yönetimi için geçerli bir HTTP/HTTPS sunucu adresi kullanın.')
        cls = http.client.HTTPSConnection if url.scheme == 'https' else http.client.HTTPConnection
        connection = cls(url.hostname, url.port, timeout=8)
        self.connection = connection
        try:
            connection.connect()
            self.active_socket = connection.sock
            self.check()
            connection.sock.settimeout(180 if body is not None else 10)
            headers = {'Accept': 'application/json', 'Content-Type': 'application/json'}
            if self.api_key:
                headers['Authorization'] = 'Bearer ' + self.api_key
            connection.request('POST' if body is not None else 'GET', url.path.rstrip('/') + path,
                               None if body is None else json.dumps(body).encode('utf-8'), headers)
            response = connection.getresponse()
            raw = response.read(4 * 1024 * 1024 + 1)
            self.check()
            if len(raw) > 4 * 1024 * 1024:
                raise ValueError('Model yönetimi yanıtı 4 MB sınırını aştı.')
            if response.status < 200 or response.status >= 300:
                detail = raw.decode('utf-8', 'replace')[:600]
                raise ValueError('HTTP ' + str(response.status) + ': ' + detail)
            data = json.loads(raw)
            if not isinstance(data, dict) or data.get('error'):
                raise ValueError('Sunucu model işlemini tamamlamadı: ' + str(data.get('error') if isinstance(data, dict) else 'Geçersiz JSON'))
            return data
        finally:
            connection.close()
            self.connection = None
            self.active_socket = None

    def lm_models(self):
        data = self.request('/api/v1/models').get('models')
        if not isinstance(data, list):
            raise ValueError('LM Studio model yönetimi için /api/v1/models desteği gerekli.')
        for model in data:
            if not isinstance(model, dict) or not isinstance(model.get('key'), str) or not isinstance(model.get('loaded_instances'), list):
                raise ValueError('LM Studio model/envanter yanıtı eksik; bellek değiştirilmedi.')
            for instance in model['loaded_instances']:
                if not isinstance(instance, dict) or not isinstance(instance.get('id'), str) or not instance['id']:
                    raise ValueError('LM Studio instance kimliği geçersiz; bellek değiştirilmedi.')
        return data

    def ollama_running(self):
        models = self.request('/api/ps').get('models')
        if not isinstance(models, list):
            raise ValueError('Ollama bellek envanteri alınamadı.')
        names = []
        for model in models:
            if not isinstance(model, dict) or not isinstance(model.get('name') or model.get('model'), str):
                raise ValueError('Ollama model kimliği geçersiz; işlem durduruldu.')
            names.append(model.get('name') or model['model'])
        return list(dict.fromkeys(names))

    def verify(self, predicate, description):
        for _ in range(30):
            self.check()
            if predicate():
                return
            if self.stopped.wait(.2):
                self.check()
        raise ValueError(description + ' Sunucunun bildirdiği bellek durumu istekle eşleşmedi.')

    def lmstudio(self):
        catalog = self.lm_models()
        matches = [m for m in catalog if m['key'] == self.model or any(i['id'] == self.model for i in m['loaded_instances'])]
        if len(matches) != 1:
            raise ValueError('Seçili model LM Studio envanterinde tek bir modelle eşleşmedi; bellek değiştirilmedi.')
        chosen = matches[0]
        selected_ids = {i['id'] for i in chosen['loaded_instances']}
        initial = [i['id'] for m in catalog for i in m['loaded_instances'] if self.operation == 'load' or m['key'] == chosen['key']]
        # Preserve supported native load settings when explicitly reloading this same model.
        fields = ('context_length', 'eval_batch_size', 'flash_attention', 'num_experts', 'offload_kv_cache_to_gpu')
        for model in catalog:
            if model['loaded_instances']:
                config = model['loaded_instances'][0].get('config', {})
                if not isinstance(config, dict):
                    raise ValueError('LM Studio yükleme ayarları geçersiz; bellek değiştirilmedi.')
                self.captured_load_configs[model['key']] = {k: config[k] for k in fields if k in config}
        config = self.captured_load_configs.get(chosen['key'], self.load_configs.get(chosen['key'], {}))
        load_body = {'model': chosen['key'], **{k: config[k] for k in fields if k in config}}
        for instance in dict.fromkeys(initial):
            self.progress.emit('LM Studio: boşaltılıyor — ' + instance)
            response = self.request('/api/v1/models/unload', {'instance_id': instance})
            if response.get('instance_id') != instance:
                raise ValueError('LM Studio boşaltılan instance kimliğini doğrulamadı; yüklemeye geçilmedi.')
        def gone():
            ids = {i['id'] for m in self.lm_models() for i in m['loaded_instances']}
            return not ids if self.operation == 'load' else not (ids & selected_ids)
        self.verify(gone, 'Model boşaltma doğrulanamadı.')
        if self.operation == 'unload':
            return {'operation': 'unload', 'model': chosen['key'], 'unloaded': initial}
        self.progress.emit('LM Studio: yükleniyor — ' + chosen['key'])
        response = self.request('/api/v1/models/load', load_body)
        instance = response.get('instance_id')
        if response.get('status') != 'loaded' or not isinstance(instance, str) or not instance:
            raise ValueError('LM Studio yükleme başarısını doğrulamadı. Boşaltılan modeller geri yüklenmedi.')
        def loaded():
            all_ids = [i['id'] for m in self.lm_models() for i in m['loaded_instances']]
            return all_ids == [instance]
        self.verify(loaded, 'Seçili modelin tek başına yüklenmesi doğrulanamadı.')
        return {'operation': 'load', 'model': instance, 'unloaded': initial}

    def ollama(self):
        normalize = lambda name: name if ':' in name.rsplit('/', 1)[-1] else name + ':latest'
        catalog = self.request('/api/tags').get('models')
        if not isinstance(catalog, list):
            raise ValueError('Ollama model listesi alınamadı; bellek değiştirilmedi.')
        names = [m.get('name') or m.get('model') for m in catalog if isinstance(m, dict)]
        matches = [name for name in names if isinstance(name, str) and normalize(name) == normalize(self.model)]
        if len(set(matches)) != 1:
            raise ValueError('Seçili model Ollama envanterinde bulunamadı; model indirilmedi ve bellek değiştirilmedi.')
        chosen = matches[0]
        running = self.ollama_running()
        initial = running if self.operation == 'load' else [name for name in running if normalize(name) == normalize(chosen)]
        for model in initial:
            self.progress.emit('Ollama: boşaltılıyor — ' + model)
            self.request('/api/generate', {'model': model, 'keep_alive': 0, 'stream': False})
        def gone():
            left = self.ollama_running()
            return not left if self.operation == 'load' else all(normalize(name) != normalize(chosen) for name in left)
        self.verify(gone, 'Model boşaltma doğrulanamadı.')
        if self.operation == 'unload':
            return {'operation': 'unload', 'model': chosen, 'unloaded': initial}
        self.progress.emit('Ollama: yükleniyor — ' + chosen)
        response = self.request('/api/generate', {'model': chosen, 'keep_alive': -1, 'stream': False})
        if response.get('done') is not True:
            raise ValueError('Ollama yüklemeyi doğrulamadı. Boşaltılan modeller geri yüklenmedi.')
        self.verify(lambda: {normalize(m) for m in self.ollama_running()} == {normalize(chosen)}, 'Seçili modelin tek başına yüklenmesi doğrulanamadı.')
        return {'operation': 'load', 'model': chosen, 'unloaded': initial}

    def run(self):
        try:
            if self.operation not in ('load', 'unload') or not isinstance(self.model, str) or not self.model.strip():
                raise ValueError('Geçerli model ve işlem seçin.')
            if self.provider == 'lmstudio':
                result = self.lmstudio()
            elif self.provider == 'ollama':
                result = self.ollama()
            else:
                raise ValueError('Bu sağlayıcı için model yönetimi desteklenmiyor.')
            self.check()
            self.completed.emit(result)
        except Exception as exc:
            message = ("İstemci işlemi durduruldu; sunucudaki durum yeniden kontrol edilmelidir." if self.stopped.is_set() else str(exc))
            if self.api_key:
                message = message.replace(self.api_key, '[gizli]')
            self.failed.emit(message)

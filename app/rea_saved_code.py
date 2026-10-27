"""Validate saved code evidence and verify the target asynchronously before reuse."""
import copy
import hashlib
import re
import time
from rea_extra_engines import ExtraEngineWorker
from rea_analysis import StaticAnalysis, digest_file


def text_digest(text):
    return hashlib.sha256(text.encode('utf-8')).hexdigest()


def validate_saved_code(saved, target, panes):
    if not isinstance(saved, dict) or set(saved) - {'decomp', 'disasm'}:
        raise ValueError('Geçersiz kayıtlı kod bilgisi.')
    validated = {}
    for pane, item in saved.items():
        if not isinstance(item, dict) or set(item) != {'view_sha256', 'record'}:
            raise ValueError('Geçersiz kayıtlı kod görünümü.')
        record = item['record']
        if not isinstance(record, dict) or record.get('format') != 'rehkc-code-export' or type(record.get('schema_version')) is not int or record['schema_version'] != 1:
            raise ValueError('Desteklenmeyen kayıtlı kod biçimi.')
        fields = {'format', 'schema_version', 'target', 'target_sha256', 'procedure', 'kind', 'engine',
                  'engine_version', 'engine_identity', 'analysis_completed_at', 'cache_hit',
                  'refresh_requested', 'analysis_session_reused', 'partial', 'limitations', 'fallback_from', 'code'}
        if set(record) != fields:
            raise ValueError('Kayıtlı kod alanları uyuşmuyor.')
        strings = fields - {'schema_version', 'cache_hit', 'refresh_requested', 'analysis_session_reused', 'partial', 'limitations', 'fallback_from'}
        if any(not isinstance(record[k], str) or len(record[k]) > (8*1024*1024 if k == 'code' else 8192) for k in strings):
            raise ValueError('Geçersiz veya büyük kayıtlı kod alanı.')
        if any(type(record[k]) is not bool for k in ('cache_hit', 'refresh_requested', 'analysis_session_reused', 'partial')):
            raise ValueError('Geçersiz kayıtlı kod durumu.')
        if record['target'] != target or not re.fullmatch('[0-9a-f]{64}', record['target_sha256']) or not record['engine'].strip() or not record['code'].strip():
            raise ValueError('Kayıtlı kod hedef/motor kimliği uyuşmuyor.')
        if record['kind'] != ('assembly' if pane == 'disasm' else 'pseudocode'):
            raise ValueError('Kayıtlı kod sekmesi uyuşmuyor.')
        if not isinstance(record['limitations'], list) or len(record['limitations']) > 100 or any(not isinstance(n, str) or len(n) > 8192 for n in record['limitations']):
            raise ValueError('Geçersiz kayıtlı kod sınırlamaları.')
        if not isinstance(record['fallback_from'], list) or len(record['fallback_from']) > 8:
            raise ValueError('Geçersiz kayıtlı alternatif motor bilgisi.')
        for failure in record['fallback_from']:
            if not isinstance(failure, dict) or set(failure) != {'engine', 'error'} or any(not isinstance(failure[k], str) or len(failure[k]) > 8192 for k in failure):
                raise ValueError('Geçersiz kayıtlı motor hatası.')
        if item['view_sha256'] != text_digest(panes[pane]):
            raise ValueError('Kayıtlı kod görünümü değişmiş; motor bilgisiyle eşleşmiyor.')
        validated[pane] = copy.deepcopy(item)
    return validated


class SavedCodeVerifier(ExtraEngineWorker):
    def __init__(self, target, saved, parent=None):
        super().__init__('restore_code_exports', target, parent=parent)
        self.saved = copy.deepcopy(saved)

    def analyze(self):
        self.started = time.monotonic()
        service = StaticAnalysis(self.target, self.check)
        digest = digest_file(self.target, self.check, progress=self.analysis_progress.emit)
        service.unchanged()
        matched = [pane for pane, item in self.saved.items() if item['record']['target_sha256'] == digest]
        return {'target': self.target, 'target_sha256': digest, 'matched': matched}

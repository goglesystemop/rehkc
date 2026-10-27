"""Export observed code with its provenance, without settings or chat history."""
from datetime import datetime, timezone
import json
import re
from rea_analysis import observation


def code_record(result, procedure='', kind='pseudocode'):
    value = observation(result)
    code = value.get('observed_result', value.get('normalized_result'))
    if not isinstance(code, str) or not code.strip() or result.get('isError') or value.get('ok') is False:
        raise ValueError('Dışa aktarılabilir kod sonucu yok.')
    provider = value.get('provider') or {}
    engine = value.get('engine') or provider.get('name') or provider.get('id')
    if not engine:
        raise ValueError('Sonucun motor bilgisi yok; yeniden analiz edin.')
    notes = ['Statik analiz çıktısıdır; özgün kaynak kod değildir. Tamlık ve doğruluk garanti edilmez.']
    notes.extend(str(note) for note in value.get('limitations', []))
    indicators = result.get('preflight', {}).get('packer_indicators', [])
    if indicators:
        notes.append('Paketleyici/koruma işaretleri: ' + ', '.join(indicators) +
                     '. Kod yalnız yükleyiciye ait olabilir; asıl programın kurtarıldığı anlamına gelmez.')
    failures = [{'engine': str(item.get('engine', 'bilinmiyor')), 'error': str(item.get('error', ''))}
                for item in value.get('fallback_from', [])]
    if failures:
        notes.append('Alternatif motor kullanıldı; önceki motor hataları aşağıda korunmuştur.')
    digest = result.get('target_sha256', '')
    if not re.fullmatch('[0-9a-f]{64}', digest):
        raise ValueError('Sonucun hedef SHA256 bilgisi yok; yeniden analiz edin.')
    return {'format': 'rehkc-code-export', 'schema_version': 1,
            'target': result['target'], 'target_sha256': digest,
            'procedure': result.get('procedure', procedure), 'kind': kind,
            'engine': str(engine), 'engine_version': str(provider.get('version') or 'bilinmiyor'),
            'engine_identity': result.get('engine_identity', ''),
            'analysis_completed_at': result.get('analysis_completed_at') or 'bilinmiyor',
            'cache_hit': bool(result.get('cache_hit')), 'refresh_requested': bool(result.get('refresh_requested')),
            'analysis_session_reused': bool(result.get('analysis_session_reused')),
            'partial': bool(value.get('partial') or indicators or failures),
            'limitations': list(dict.fromkeys(notes)), 'fallback_from': failures, 'code': code}


def render_code(record, selection=None, file_format='md'):
    if file_format not in ('md', 'txt', 'json'):
        raise ValueError('Desteklenmeyen dışa aktarma biçimi.')
    data = dict(record, exported_at=datetime.now(timezone.utc).isoformat(),
                scope='selection' if selection else 'complete_result', code=selection or record['code'])
    if data['scope'] == 'selection':
        data['limitations'] = list(data['limitations']) + ['Yalnız seçili metin; fonksiyonun tamamını içermeyebilir.']
    if file_format == 'json':
        return json.dumps(data, ensure_ascii=False, indent=2) + '\n'
    labels = [('Hedef', 'target'), ('Hedef SHA256', 'target_sha256'), ('Fonksiyon/adres', 'procedure'),
              ('Çıktı türü', 'kind'), ('Motor', 'engine'), ('Motor sürümü', 'engine_version'),
              ('Motor kimliği', 'engine_identity'), ('Analiz tamamlandı (UTC)', 'analysis_completed_at'),
              ('Dışa aktarıldı (UTC)', 'exported_at'), ('Kapsam', 'scope'), ('Önbellekten', 'cache_hit'),
              ('Yeniden analiz', 'refresh_requested'), ('Açık oturum kullanıldı', 'analysis_session_reused'), ('Kısmi', 'partial')]
    # Metadata is JSON quoted so filenames/tool errors cannot introduce Markdown blocks.
    lines = ['REHKC — seçili kod', '', *[name + ': ' + json.dumps(data[key], ensure_ascii=False) for name, key in labels],
             '', 'Sınırlamalar:', *['- ' + json.dumps(note, ensure_ascii=False) for note in data['limitations']]]
    if data['fallback_from']:
        lines += ['', 'Önceki motor hataları:', json.dumps(data['fallback_from'], ensure_ascii=False)]
    lines += ['', 'Kod:', '']
    if file_format == 'md':
        # A fence longer than any run in the payload preserves arbitrary recovered code.
        fence = '`' * max(3, 1 + max((len(m) for m in re.findall(r'`+', data['code'])), default=0))
        lines += [fence + ('asm' if data['kind'] == 'assembly' else 'c'), data['code'], fence]
    else:
        lines += [data['code']]
    return '\n'.join(lines) + '\n'

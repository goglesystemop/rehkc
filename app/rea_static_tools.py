"""Bounded static strings/ELF mitigation inspection. Never executes the target."""
import hashlib, os, re, stat, tempfile
from rea_extra_engines import ExtraEngineWorker


def parse_command_catalog(text):
    """Only parse the CLI Commands section, not integration/global option names."""
    section = text.partition('Commands:')[2].split('Integrations:')[0].split('Global Options:')[0]
    return dict(re.findall(r'^  ([a-z][a-z0-9-]+)\s{2,}(.+)$', section, re.MULTILINE))


def elf_mitigations(raw):
    """Return observations, preserving unknown/not-applicable instead of inferring safety."""
    match = re.search(r'^\s*Type:\s+(\w+)', raw, re.MULTILINE)
    if not match:
        raise ValueError('readelf ELF başlık türünü bildirmedi.')
    kind = match.group(1)
    programs = {}
    for line in raw.splitlines():
        fields = line.split()
        if len(fields) >= 8 and fields[0] in ('GNU_STACK', 'GNU_RELRO', 'LOAD', 'INTERP') and fields[1].startswith('0x'):
            programs.setdefault(fields[0], []).append(''.join(fields[6:-1]))
    executable = kind in ('DYN', 'EXEC')
    nx = ('Etkin (GNU_STACK çalıştırılabilir değil)' if 'E' not in programs['GNU_STACK'][0]
          else 'Etkin değil (çalıştırılabilir GNU_STACK)') if programs.get('GNU_STACK') else 'Bilinmiyor (GNU_STACK yok)'
    if not executable:
        nx = 'Uygulanamaz / yürütülebilir ELF değil'
    now = bool(re.search(r'\(BIND_NOW\)|\(FLAGS(?:_1)?\).*\b(?:BIND_NOW|NOW)\b', raw))
    relro = 'Tam RELRO (GNU_RELRO + NOW)' if programs.get('GNU_RELRO') and now else 'Kısmi RELRO (GNU_RELRO, NOW yok)' if programs.get('GNU_RELRO') else 'GNU_RELRO yok'
    if not executable:
        relro = 'Uygulanamaz / yürütülebilir ELF değil'
    pie = ('PIE işareti var (FLAGS_1 PIE)' if re.search(r'\(FLAGS_1\).*\bPIE\b', raw)
           else 'DYN + INTERP: PIE adayı' if kind == 'DYN' and programs.get('INTERP')
           else 'DYN; paylaşımlı kütüphane/PIE ayrımı doğrulanamadı' if kind == 'DYN'
           else 'PIE değil (EXEC)' if kind == 'EXEC' else 'Uygulanamaz / yürütülebilir ELF değil')
    canary = bool(re.search(r'\b__stack_chk_(?:fail(?:_local)?|guard)(?:@|\b)', raw))
    fortified = sorted(set(re.findall(r'\b(__[A-Za-z0-9_]+_chk)(?:@|\b)', raw)))
    return {'elf_type': kind, 'nx': nx, 'relro': relro, 'pie': pie,
            'stack_canary': 'Sembol kanıtı var' if canary else 'Sembol kanıtı bulunamadı; yokluğu kanıtlanmış değil',
            'fortify_symbols': fortified,
            'writable_executable_load': any('W' in flags and 'E' in flags for flags in programs.get('LOAD', [])),
            'needed': re.findall(r'\(NEEDED\).*\[([^\]]+)\]', raw),
            'search_paths': re.findall(r'\((?:RPATH|RUNPATH)\).*\[([^\]]*)\]', raw)}


class StaticInspectionWorker(ExtraEngineWorker):
    """The shared bounded runner is composed explicitly, not inherited implicitly."""
    def extract_strings(self):
        data=self.service.strings()
        report=['REHKC — statik string incelemesi','Hedef: '+self.target,
                'Adresler dosya içindeki bayt ofsetleridir; hedef çalıştırılmadı.',
                f"Taranan: {data['scanned_bytes']} / {data['file_bytes']} bayt; bulunan parça: {len(data['strings'])}",
                'KISMİ SONUÇ — çıktı kotası doldu.' if data['partial'] else 'Dosya taraması tamamlandı.',
                *data['limitations'],'']
        report += [f"0x{row['offset']:08x} [{row['encoding']}] {row['text']}" for row in data['strings']]
        return dict(data,engine=self.engine,target=self.target,report='\n'.join(report))

    def security_audit(self):
        with open(self.target,'rb') as source:magic=source.read(4)
        if magic[:2]==b'MZ':
            info=self.service.preflight()
            if info['format']!='PE':raise ValueError('Geçerli PE başlığı bulunamadı; güvenlik sonucu çıkarılmadı.')
            flags=info['pe_security']
            wx=[section['name'] for section in info['sections'] if section['executable'] and section['writable']]
            observations=dict(flags,writable_executable_sections=wx,packer_indicators=info['packer_indicators'])
            lines=['REHKC — PE güvenlik özellikleri (statik başlık gözlemleri)','Hedef: '+self.target,
                   'Bu bir açık taraması, imza doğrulaması veya güvenlik garantisi değildir.','',
                   'Mimari: '+info['architecture'],
                   'ASLR / DYNAMIC_BASE bayrağı: '+str(flags['dynamic_base']),
                   'Relocation dizini bildirimi: '+str(flags['relocation_directory_declared']),
                   'DEP / NX_COMPAT bayrağı: '+str(flags['nx_compatible']),
                   'CFG / GUARD_CF bayrağı: '+str(flags['guard_cf']),
                   'HIGH_ENTROPY_VA bayrağı: '+str(flags['high_entropy_va']),
                   'İmza tablosu bildirimi: '+str(flags['certificate_table_declared']),
                   'İmza tablosu dosya sınırları içinde: '+str(flags['certificate_table_in_file']),
                   'İmza doğrulanmadı; sertifika güveni veya dosyanın güvenli olduğu sonucu çıkarılmaz.',
                   'CLR/.NET dizini bildirimi: '+str(flags['clr_directory_declared']),
                   'Yazılabilir ve çalıştırılabilir bölümler: '+(', '.join(wx) or 'Gözlenmedi'),
                   'Paketleyici işaretleri: '+(', '.join(info['packer_indicators']) or 'Gözlenmedi'),'',
                   'Bayraklar işletim sisteminin korumayı gerçekten uyguladığını kanıtlamaz.',
                   'CFG hedef tablosu ve relocation içeriği doğrulanmadı; HIGH_ENTROPY_VA yalnız uygun 64-bit ASLR ile anlamlıdır.']
            return dict(engine=self.engine,target=self.target,format='PE',observations=observations,report='\n'.join(lines))
        if magic!=b'\x7fELF':raise ValueError('Security Audit PE ve ELF başlıklarını destekler; dosya biçimi desteklenmiyor.')
        with open(self.target,'rb') as source:identity=source.read(16)
        if len(identity)!=16 or identity[4] not in (1,2) or identity[5] not in (1,2) or identity[6]!=1:
            raise ValueError('ELF kimlik başlığı geçersiz; güvenlik sonucu çıkarılmadı.')
        tool=self.service.executable('readelf')
        raw,warnings=self.service.command([tool,'-W','-h','-l','-d','-s','--',self.target],
            timeout=90,capture_stderr=True,operation='ELF güvenlik başlıkları / readelf',env=dict(os.environ,LC_ALL='C'))
        if warnings.strip():raise ValueError('readelf uyarı bildirdi; denetim tamamlanmadı: '+warnings[-5000:])
        observations=elf_mitigations(raw)
        lines=['REHKC — ELF güvenlik özellikleri (statik inceleme)','Hedef: '+self.target,
               'Bu rapor bir açık taraması veya güvenlik garantisi değildir.',
               'Canary/FORTIFY sembolleri tüm fonksiyonların korunduğunu kanıtlamaz.','',
               'ELF türü: '+observations['elf_type'],'NX: '+observations['nx'],
               'RELRO: '+observations['relro'],'PIE: '+observations['pie'],
               'Stack canary: '+observations['stack_canary'],
               'FORTIFY sembolleri: '+(', '.join(observations['fortify_symbols']) or 'Kanıt bulunamadı; yokluğu kanıtlanmış değil'),
               'W+X LOAD segmenti: '+str(observations['writable_executable_load']),
               'DT_NEEDED bildirimleri: '+(', '.join(observations['needed']) or 'Yok'),
               'RPATH/RUNPATH: '+('; '.join(observations['search_paths']) or 'Yok'),'',
               'Kütüphaneler çözülmedi, ldd kullanılmadı ve hedef çalıştırılmadı.']
        return dict(engine=self.engine,target=self.target,format='ELF',observations=observations,report='\n'.join(lines),raw_readelf=raw)

    def analyze(self):
        import time
        from rea_analysis import StaticAnalysis,digest_file
        self.started=time.monotonic();self.service=StaticAnalysis(self.target,self.check,progress=self.analysis_progress.emit)
        digest=digest_file(self.target,self.check,progress=self.analysis_progress.emit)
        if self.engine=='strings':result=self.extract_strings()
        elif self.engine=='security_audit':result=self.security_audit()
        else:raise ValueError('Bilinmeyen statik inceleme.')
        self.service.unchanged();result['target_sha256']=digest
        return result

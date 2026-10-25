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
    def extract_strings(self, cwd):
        tool = self.executable('strings')
        rows = []
        text_bytes = 0
        for encoding, label in [('S', '8-bit / UTF-8'), ('l', 'UTF-16LE'), ('b', 'UTF-16BE')]:
            raw, _ = self.command([tool, '-a', '-n', '4', '-t', 'x', '-e', encoding, '--', self.target], cwd)
            text_bytes += len(raw.encode('utf-8'))
            if text_bytes > 8 * 1024 * 1024:
                raise ValueError('Toplam string çıktısı 8 MB sınırını aştı; sonuç kısmi gösterilmedi.')
            for line in raw.split('\n'):
                self.check()
                match = re.match(r'^\s*([0-9a-fA-F]+) (.*)$', line)
                if not match:
                    continue
                rows.append({'offset': int(match.group(1), 16), 'encoding': label, 'text': match.group(2)})
                if len(rows) > 100000:
                    raise ValueError('String sayısı 100.000 sınırını aştı; sonuç kısmi gösterilmedi.')
        rows.sort(key=lambda row: (row['offset'], row['encoding']))
        report = ['Rea — statik string çıkarma', 'Hedef: ' + self.target,
                  'En az 4 karakter; tüm dosya; GNU strings -e S/l/b.',
                  'Adresler sanal adres değil, dosya içindeki bayt ofsetleridir.',
                  '8-bit metin UTF-8 olarak gösterilir; çözülemeyen baytlar değiştirme karakteriyle gösterilebilir.',
                  'UTF-16 taraması GNU strings kapsamıyla sınırlıdır.', '', 'Bulunan string sayısı: ' + str(len(rows)), '']
        report += [f"0x{row['offset']:08x} [{row['encoding']}] {row['text']}" for row in rows]
        return {'engine': self.engine, 'target': self.target, 'strings': rows, 'report': '\n'.join(report)}

    def security_audit(self, cwd):
        with open(self.target, 'rb') as source:
            if source.read(4) != b'\x7fELF':
                raise ValueError('Security Audit şu anda ELF dosyalarını destekliyor. Bu dosya ELF değil; güvenli/güvensiz sonucu çıkarılmadı.')
        tool = self.executable('readelf')
        raw, warnings = self.command([tool, '-W', '-h', '-l', '-d', '-s', '--', self.target], cwd)
        # A tool accepting a damaged ELF must not produce a confident clean result.
        if warnings.strip():
            raise ValueError('readelf uyarı bildirdi; denetim tamamlanmadı: ' + warnings[-5000:])
        if len(raw.encode('utf-8')) > 8 * 1024 * 1024:
            raise ValueError('ELF raporu 8 MB sınırını aştı; sonuç kısmi gösterilmedi.')
        observations = elf_mitigations(raw)
        lines = ['Rea — ELF güvenlik özellikleri (statik inceleme)', 'Hedef: ' + self.target,
                 'Bu rapor bir açık taraması veya güvenlik garantisi değildir.',
                 'Canary/FORTIFY sembolleri tüm fonksiyonların korunduğunu kanıtlamaz.', '',
                 'ELF türü: ' + observations['elf_type'], 'NX: ' + observations['nx'],
                 'RELRO: ' + observations['relro'], 'PIE: ' + observations['pie'],
                 'Stack canary: ' + observations['stack_canary'],
                 'FORTIFY sembolleri: ' + (', '.join(observations['fortify_symbols']) or 'Kanıt bulunamadı; yokluğu kanıtlanmış değil'),
                 'W+X LOAD segmenti: ' + ('Gözlendi' if observations['writable_executable_load'] else 'Gözlenmedi'),
                 'DT_NEEDED bildirimleri: ' + (', '.join(observations['needed']) or 'Yok'),
                 'RPATH/RUNPATH bildirimleri: ' + ('; '.join(observations['search_paths']) or 'Yok'),
                 '', 'Kütüphaneler çözülmedi, ldd kullanılmadı ve hedef çalıştırılmadı.']
        return {'engine': self.engine, 'target': self.target, 'observations': observations,
                'report': '\n'.join(lines), 'raw_readelf': raw}

    def analyze(self):
        self.check()
        before = os.stat(self.target)
        if not stat.S_ISREG(before.st_mode) or before.st_size > 128 * 1024 * 1024:
            raise ValueError('En fazla 128 MB boyutunda normal bir dosya seçin.')
        digest = hashlib.sha256()
        total = 0
        with open(self.target, 'rb') as source:
            while True:
                self.check()
                block = source.read(1024 * 1024)
                if not block:
                    break
                total += len(block)
                if total > 128 * 1024 * 1024:
                    raise ValueError('Dosya okuma sırasında 128 MB sınırını aştı.')
                digest.update(block)
        with tempfile.TemporaryDirectory(prefix='rea-static-inspection-') as cwd:
            if self.engine == 'strings':
                result = self.extract_strings(cwd)
            elif self.engine == 'security_audit':
                result = self.security_audit(cwd)
            else:
                raise ValueError('Bilinmeyen statik inceleme.')
        self.check()
        after = os.stat(self.target)
        signature = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
        if signature(before) != signature(after):
            raise ValueError('Hedef dosya analiz sırasında değişti; sonuç kullanılmadı.')
        result['target_sha256'] = digest.hexdigest()
        return result

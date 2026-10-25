"""Local static binary version comparison. Never executes either target."""
import os
import re
import stat
import time
import hashlib
import difflib
import tempfile
import subprocess
from PyQt5.QtCore import QThread, pyqtSignal, Qt
from PyQt5.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QFileDialog, QTabWidget, QTableWidget, QTableWidgetItem,
    QPlainTextEdit, QAbstractItemView, QHeaderView, QMessageBox)

LIMIT = 256 * 1024 * 1024
OUTPUT_LIMIT = 32 * 1024 * 1024
ITEM_LIMIT = 100000

class ComparisonCancelled(Exception):
    pass

class BinaryComparisonWorker(QThread):
    completed = pyqtSignal(dict)
    failed = pyqtSignal(str)
    cancelled = pyqtSignal()

    def __init__(self, old_path, new_path, parent=None):
        super().__init__(parent)
        self.old_path, self.new_path = old_path, new_path
        self.stopped = False
        self.process = None

    def cancel(self):
        self.stopped = True
        process = self.process
        if process:
            try:
                process.terminate()
            except OSError:
                pass

    def check(self):
        if self.stopped:
            raise ComparisonCancelled()

    def command(self, args):
        self.check()
        with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as error:
            environment = dict(os.environ, LC_ALL='C')
            try:
                process = subprocess.Popen(args, stdout=output, stderr=error, env=environment)
            except FileNotFoundError:
                raise ValueError('Gerekli araç bulunamadı: ' + args[0])
            self.process = process
            started = time.monotonic()
            try:
                while process.poll() is None:
                    self.check()
                    if time.monotonic() - started > 40:
                        raise ValueError('İnceleme zaman sınırını aştı: ' + args[0])
                    if os.fstat(output.fileno()).st_size > OUTPUT_LIMIT:
                        raise ValueError('İnceleme çıktısı 32 MB sınırını aştı.')
                    time.sleep(.02)
                self.check()
                if os.fstat(output.fileno()).st_size > OUTPUT_LIMIT:
                    raise ValueError('İnceleme çıktısı 32 MB sınırını aştı.')
                output.seek(0); error.seek(0)
                return process.returncode, output.read(), error.read(4096).decode('utf-8', 'replace')
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()
                self.process = None

    def inspect(self, path):
        self.check()
        path = os.path.abspath(path)
        before = os.stat(path)
        if not stat.S_ISREG(before.st_mode) or before.st_size > LIMIT:
            raise ValueError('Normal bir dosya seçin (en fazla 256 MB): ' + path)
        digest = hashlib.sha256()
        with open(path, 'rb') as stream:
            total = 0
            while True:
                self.check()
                block = stream.read(1024 * 1024)
                if not block: break
                total += len(block)
                if total > LIMIT: raise ValueError('Dosya 256 MB sınırını aştı.')
                digest.update(block)
        functions = {}
        code, output, error = self.command(['objdump', '-d', '-w', '--', path])
        function_error = ''
        if code:
            function_error = error.strip() or 'Bu dosya biçimi için disassembly alınamadı.'
        else:
            section = ''
            current = None
            function_count = 0
            for line in output.decode('utf-8', 'backslashreplace').splitlines():
                self.check()
                found = re.match(r'Disassembly of section (.+):', line)
                if found: section = found.group(1); current = None; continue
                found = re.match(r'^\s*([0-9a-fA-F]+) <(.+)>:$', line)
                if found:
                    current = {'name': found.group(2), 'section': section, 'address': found.group(1), 'bytes': [], 'assembly': []}
                    functions.setdefault((section, found.group(2)), []).append(current)
                    function_count += 1
                    if function_count > ITEM_LIMIT:
                        raise ValueError('Fonksiyon/etiket sayısı sınırı aşıldı.')
                    continue
                found = re.match(r'^\s*[0-9a-fA-F]+:\s+((?:[0-9a-fA-F]{2}\s+)+)(.*)$', line)
                if current is not None and found:
                    current['bytes'].extend(found.group(1).split())
                    current['assembly'].append(found.group(2).strip())
            functions = {key: [entry for entry in entries if entry['bytes']] for key, entries in functions.items()}
            functions = {key: entries for key, entries in functions.items() if entries}
            if not functions: function_error = 'Objdump ayrılabilir fonksiyon/etiket kodu bulamadı.'
        values = {}
        for encoding, label in [('S', '8-bit / UTF-8'), ('l', 'UTF-16LE')]:
            code, raw, error = self.command(['strings', '-a', '-n', '4', '-e', encoding, '--', path])
            if code: raise ValueError('String incelemesi başarısız: ' + error)
            # GNU strings emits UTF-16LE characters as single-byte text.
            for raw_line in raw.split(b'\n'):
                if not raw_line: continue
                key = (label, raw_line.hex())
                values[key] = raw_line.decode('utf-8', 'backslashreplace')
                if len(values) > ITEM_LIMIT: raise ValueError('String sayısı 100.000 sınırını aştı.')
        after = os.stat(path)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise ValueError('Dosya inceleme sırasında değişti. Yeniden karşılaştırın: ' + path)
        return {'path': path, 'sha256': digest.hexdigest(), 'size': before.st_size,
                'functions': functions, 'function_error': function_error, 'strings': values}

    def compare(self):
        old, new = self.inspect(self.old_path), self.inspect(self.new_path)
        functions = []
        unchanged = 0
        if not old['function_error'] and not new['function_error']:
            for key in sorted(old['functions'].keys() | new['functions'].keys()):
                self.check()
                left, right = old['functions'].get(key, []), new['functions'].get(key, [])
                if len(left) > 1 or len(right) > 1: status = 'Belirsiz eşleşme'
                elif not left: status = 'Eklendi'
                elif not right: status = 'Silindi'
                elif left[0]['bytes'] != right[0]['bytes']: status = 'Kod farklı'
                else: unchanged += 1; continue
                def render(entries):
                    return '\n\n'.join(f"{e['address']} <{e['name']}>:\n" + "Makine kodu: " + " ".join(e["bytes"]) + "\n" + '\n'.join(e['assembly']) for e in entries)
                before, after = render(left), render(right)
                diff = '\n'.join(difflib.unified_diff(before.splitlines(), after.splitlines(), fromfile='Eski', tofile='Yeni', lineterm=''))
                functions.append({'status': status, 'section': key[0], 'name': key[1], 'diff': diff})
        strings = []
        for key in sorted(old['strings'].keys() - new['strings'].keys()):
            strings.append({'status': 'Silindi', 'encoding': key[0], 'text': old['strings'][key]})
        for key in sorted(new['strings'].keys() - old['strings'].keys()):
            strings.append({'status': 'Eklendi', 'encoding': key[0], 'text': new['strings'][key]})
        return {'old': {k: old[k] for k in ('path','sha256','size','function_error')},
                'new': {k: new[k] for k in ('path','sha256','size','function_error')},
                'functions': functions, 'strings': strings, 'unchanged_functions': unchanged}

    def run(self):
        try: self.completed.emit(self.compare())
        except ComparisonCancelled: self.cancelled.emit()
        except Exception as exc: self.failed.emit(str(exc))


def comparison_report(result):
    lines = ['Rea — iki dosya karşılaştırması', '']
    for key, label in [('old','Eski'),('new','Yeni')]:
        item = result[key]
        lines += [label + ': ' + item['path'], 'SHA-256: ' + item['sha256'], 'Boyut: ' + str(item['size'])]
        if item['function_error']: lines += ['Fonksiyon incelemesi: ' + item['function_error']]
    lines += ['', 'Fonksiyon farkları: ' + str(len(result['functions'])), 'Aynı kod: ' + str(result['unchanged_functions']),
              'String ekleme/silme: ' + str(len(result['strings'])), '',
              'Kod farkı davranış farkı kanıtı değildir. Eşleştirme bölüm ve etiket adına göredir; sembolsüz dosyalarda kapsam sınırlıdır.',
              'Stringler: en az 4 karakter; 8-bit/UTF-8 ve GNU strings UTF-16LE taraması. Tekrar sayıları karşılaştırılmaz.', '']
    for item in result['functions']: lines += [f"{item['status']} — {item['section']}:{item['name']}", item['diff'], '']
    for item in result['strings']: lines += [f"{item['status']} [{item['encoding']}]: {item['text']}"]
    return '\n'.join(lines)


class CompareVersionsDialog(QDialog):
    def __init__(self, parent=None, initial_path=''):
        super().__init__(parent)
        self.setWindowTitle('Eski / yeni dosya karşılaştırması')
        self.resize(1050, 760)
        self.worker = None
        self.result_data = None
        layout = QVBoxLayout(self)
        for attr, label, initial in [('old_path','Eski dosya:', initial_path),('new_path','Yeni dosya:', '')]:
            row = QHBoxLayout();row.addWidget(QLabel(label));field = QLineEdit(initial);setattr(self,attr,field);row.addWidget(field,1)
            browse=QPushButton('Seç…');browse.clicked.connect(lambda checked=False, editor=field:self._browse(editor));row.addWidget(browse);layout.addLayout(row)
        note = QLabel('Dosyalar çalıştırılmaz. Fonksiyonlar bölüm/etiket adına ve makine koduna göre karşılaştırılır; sembolleri silinmiş dosyalarda kapsam sınırlıdır. Stringler: en az 4 karakter, 8-bit/UTF-8 + UTF-16LE taraması.')
        note.setWordWrap(True);layout.addWidget(note)
        row=QHBoxLayout();self.btn_start=QPushButton('Karşılaştır');self.btn_start.clicked.connect(self.start);row.addWidget(self.btn_start)
        self.btn_stop=QPushButton('Durdur');self.btn_stop.setEnabled(False);self.btn_stop.clicked.connect(self.stop);row.addWidget(self.btn_stop)
        self.btn_export=QPushButton('Raporu kaydet');self.btn_export.setEnabled(False);self.btn_export.clicked.connect(self.export);row.addWidget(self.btn_export)
        layout.addLayout(row);self.status=QLabel('Eski ve yeni dosyayı seçin.');self.status.setTextFormat(Qt.PlainText);self.status.setWordWrap(True);layout.addWidget(self.status)
        tabs=QTabWidget();self.functions=QTableWidget(0,3);self.functions.setHorizontalHeaderLabels(['Durum','Fonksiyon / etiket','Bölüm'])
        self.strings=QTableWidget(0,3);self.strings.setHorizontalHeaderLabels(['Durum','Kodlama','Metin'])
        for table in (self.functions,self.strings):
            table.setEditTriggers(QAbstractItemView.NoEditTriggers);table.setSelectionBehavior(QAbstractItemView.SelectRows);table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        tabs.addTab(self.functions,'Fonksiyon farkları');tabs.addTab(self.strings,'Eklenen / silinen stringler');layout.addWidget(tabs)
        self.detail=QPlainTextEdit();self.detail.setReadOnly(True);layout.addWidget(self.detail)
        self.functions.currentCellChanged.connect(self.show_function)
        self.strings.currentCellChanged.connect(self.show_string)

    def _browse(self, field):
        path,_=QFileDialog.getOpenFileName(self,'Karşılaştırılacak dosya',field.text())
        if path:field.setText(path)

    def start(self):
        if self.worker and self.worker.isRunning():return
        if not self.old_path.text().strip() or not self.new_path.text().strip():
            QMessageBox.warning(self,'Dosya seçin','Eski ve yeni dosyayı seçin.');return
        self.result_data=None;self.functions.setRowCount(0);self.strings.setRowCount(0);self.detail.clear();self.btn_export.setEnabled(False)
        self.worker=BinaryComparisonWorker(self.old_path.text(),self.new_path.text(),self)
        self.worker.completed.connect(self.show_result);self.worker.failed.connect(lambda error:self.status.setText('Hata: '+error));self.worker.cancelled.connect(lambda:self.status.setText('Karşılaştırma durduruldu.'))
        self.worker.finished.connect(self.finished_work)
        self.btn_start.setEnabled(False);self.btn_stop.setEnabled(True);self.old_path.setEnabled(False);self.new_path.setEnabled(False);self.status.setText('Karşılaştırılıyor…')
        self.worker.start()

    def stop(self):
        if self.worker:self.worker.cancel()

    def finished_work(self):
        self.btn_start.setEnabled(True);self.btn_stop.setEnabled(False);self.old_path.setEnabled(True);self.new_path.setEnabled(True)

    def show_result(self,result):
        self.result_data=result
        errors=[label+': '+result[key]['function_error'] for key,label in [('old','Eski'),('new','Yeni')] if result[key]['function_error']]
        self.status.setText(f"Fonksiyon farkı: {len(result['functions'])}; aynı kod: {result['unchanged_functions']}; string ekleme/silme: {len(result['strings'])}. İlk 5000 satır gösterilir; rapor tüm sonuçları içerir." + (' Fonksiyon karşılaştırması yapılamadı: '+'; '.join(errors) if errors else ''))
        for table, items, keys in [(self.functions,result['functions'],('status','name','section')),(self.strings,result['strings'],('status','encoding','text'))]:
            table.setRowCount(min(5000,len(items)))
            for row,item in enumerate(items[:5000]):
                for col,key in enumerate(keys):
                    cell=QTableWidgetItem(item[key]);cell.setToolTip(item[key]);table.setItem(row,col,cell)
        self.btn_export.setEnabled(True)
        if self.functions.rowCount():self.functions.selectRow(0)

    def show_function(self,row,*args):
        if self.result_data and 0<=row<min(5000,len(self.result_data['functions'])):self.detail.setPlainText(self.result_data['functions'][row]['diff'])

    def show_string(self,row,*args):
        if self.result_data and 0<=row<min(5000,len(self.result_data['strings'])):self.detail.setPlainText(self.result_data['strings'][row]['text'])

    def export(self):
        if not self.result_data:return
        path,_=QFileDialog.getSaveFileName(self,'Karşılaştırma raporunu kaydet','karsilastirma.txt','Metin (*.txt)')
        if not path:return
        if not os.path.splitext(path)[1]:path+='.txt'
        try:
            from rea_gui import atomic_private_write
            atomic_private_write(path,comparison_report(self.result_data))
        except Exception as exc:QMessageBox.warning(self,'Kayıt hatası',str(exc))

    def reject(self):
        if self.worker and self.worker.isRunning():
            self.worker.cancel()
            if not self.worker.wait(2500):return
        super().reject()

    def closeEvent(self,event):
        if self.worker and self.worker.isRunning():
            self.worker.cancel()
            if not self.worker.wait(2500):event.ignore();return
        super().closeEvent(event)

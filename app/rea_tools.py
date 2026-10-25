"""Bounded, read-only CLI and REA-provider readiness checks."""
import os
import time
import glob
import json
import shutil
import tempfile
import subprocess
from pathlib import Path
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QColor
from PyQt5.QtWidgets import (QDialog,QVBoxLayout,QHBoxLayout,QLabel,QPushButton,
 QTableWidget,QTableWidgetItem,QHeaderView,QAbstractItemView,QPlainTextEdit,QFileDialog,QMessageBox)

TOOLS = [
 ('GNU objdump',('objdump',),('--version',)), ('GNU strings',('strings',),('--version',)),
 ('GNU nm',('nm',),('--version',)), ('GNU readelf',('readelf',),('--version',)),
 ('GDB',('gdb',),('--version',)), ('Java',('java',),('-version',)),
 ('procps ps',('ps',),('--version',)), ('Radare2',('radare2','r2'),('-v',)),
 ('Rizin',('rizin','rz'),('-v',)), ('RetDec',('retdec-decompiler','retdec-decompiler.py'),('--version',)),
 ('JADX CLI',('jadx',),('--version',)), ('Apktool',('apktool',),('--version',)),
 ('Android adb',('adb',),('version',)), ('Frida CLI',('frida',),('--version',)),
 ('TShark',('tshark',),('--version',)), ('Binwalk',('binwalk',),('--version',)),
 ('sigrok-cli',('sigrok-cli',),('--version',))]

class ToolsCancelled(Exception): pass

class ToolStatusWorker(QThread):
    row_ready=pyqtSignal(dict)
    completed=pyqtSignal(list)
    failed=pyqtSignal(str)
    cancelled=pyqtSignal()
    def __init__(self,rea_bin,parent=None):
        super().__init__(parent);self.rea_bin=rea_bin;self.stopped=False;self.process=None

    def cancel(self):
        self.stopped=True
        process=self.process
        if process:
            try:process.terminate()
            except OSError:pass

    def check(self):
        if self.stopped:raise ToolsCancelled()

    def probe(self,args,timeout=4,limit=65536):
        from rea_runtime import diagnostic_command
        try:
            args = diagnostic_command(args)
        except (OSError, ValueError, KeyError) as exc:
            return -1, str(exc)
        self.check()
        with tempfile.TemporaryFile() as output:
            try:process=subprocess.Popen(args,stdout=output,stderr=subprocess.STDOUT,env=dict(os.environ,LC_ALL='C'))
            except OSError as exc:return -1,str(exc)
            self.process=process;started=time.monotonic()
            try:
                while process.poll() is None:
                    self.check()
                    if time.monotonic()-started>timeout:return -1,'Sürüm/tanılama komutu zaman aşımına uğradı.'
                    if os.fstat(output.fileno()).st_size>limit:return -1,'Tanılama çıktısı sınırı aşıldı.'
                    time.sleep(.02)
                self.check()
                if os.fstat(output.fileno()).st_size>limit:return -1,'Tanılama çıktısı sınırı aşıldı.'
                output.seek(0);return process.returncode,output.read(limit).decode('utf-8','replace').strip()
            finally:
                if process.poll() is None:process.kill();process.wait()
                self.process=None

    def cli_row(self,name,commands,args):
        path=next((shutil.which(command) for command in commands if shutil.which(command)),None)
        if not path:return dict(name=name,status='Bulunamadı',path='—',version='—',detail='PATH üzerinde bulunamadı: '+', '.join(commands))
        code,text=self.probe([path,*args])
        version=next((line.strip() for line in text.splitlines() if line.strip()),'')[:180]
        return dict(name=name,status='Kullanılabilir (CLI)' if code==0 and version else 'Bulundu; doğrulanamadı' if code==0 else 'Çalıştırılamadı' if code < 0 else 'Bulundu; sürüm kontrolü başarısız',path=path,version=version or '—',
          detail='Sürüm komutu: '+ ' '.join([path,*args])+'\nÇıkış kodu: '+str(code)+'\n'+text[:6000]+'\n\nCLI kontrolü gerçek bir dosya üzerinde analiz yapmaz; biçim, lisans ve ek bağımlılıklar ayrıca gerekebilir.')

    def ghidra_location(self):
        candidates=[]
        configured=os.environ.get('GHIDRA_INSTALL_DIR')
        if configured:candidates.append(configured)
        for pattern in ('/opt/ghidra*','/usr/share/ghidra*','/usr/local/ghidra*',str(Path.home()/'.local/opt/ghidra*')):
            candidates.extend(sorted(glob.glob(pattern))[:20])
        command=shutil.which('analyzeHeadless')
        if command:candidates.append(str(Path(command).resolve().parent.parent))
        for root in candidates:
            properties=Path(root)/'Ghidra/application.properties'
            if properties.is_file():
                version='—'
                try:
                    with properties.open(errors='replace') as source:
                        for i,line in enumerate(source):
                            if i>1000:break
                            if line.startswith('application.version='):version=line.strip().split('=',1)[1];break
                except OSError:pass
                launcher=Path(root)/'support/analyzeHeadless'
                return str(launcher if launcher.is_file() else Path(root)),version
        return '', '—'

    def provider_rows(self,doctor):
        inspections={entry.get('id'):entry for entry in doctor.get('providerInspections',[])}
        rows=[]
        for key,name,env,commands in [('ghidra','Ghidra','GHIDRA_INSTALL_DIR',('analyzeHeadless','ghidraRun')),
          ('ida','IDA / MCP','REA_IDA_MCP_CONFIG',('idat','ida')),
          ('jadx','JADX MCP','REA_JADX_MCP_JAR',()),('kuna','Kuna','REA_KUNA_COMMAND',('kuna',))]:
            check=inspections.get(key)
            configured_path=os.environ.get(env,'')
            found=next((shutil.which(command) for command in commands if shutil.which(command)),None)
            version='—'
            if key=='ghidra':
                ghidra_path,version=self.ghidra_location();found=ghidra_path or found
            existing=configured_path if configured_path and os.path.exists(configured_path) else found
            if check is None:status='Bulundu; REA durumu bilinmiyor' if existing else 'REA durumu doğrulanamadı'
            elif check.get('available'):status='REA için hazır'
            elif check and check.get('configured'):status='REA için hazır değil'
            elif existing:status='Bulundu; REA ayarı eksik'
            elif check:status='Yapılandırılmamış / bulunamadı'
            else:status='REA durumu doğrulanamadı'
            details=[]
            if check:
                version=check.get('providerVersion') or version
                for item in check.get('checks',[]):
                    details.append(f"{item.get('name','Kontrol')}: {'OK' if item.get('ok') else 'Eksik / hata'}")
                    for field in ('detail','remediation'):
                        if item.get(field):details.append(str(item[field]))
            else:details.append('REA doctor bu sağlayıcı için kullanılabilir bir sonuç vermedi.')
            details.append('Yapılandırma değişkeni: '+env)
            if configured_path and not os.path.exists(configured_path):details.append('Yapılandırılmış yol mevcut değil: '+configured_path)
            rows.append(dict(name=name,status=status,path=configured_path or found or '—',version=version,detail='\n'.join(details)))
        hopper=next((x for x in doctor.get('scope_checks',doctor.get('checks',[])) if x.get('name')=='hopper'),None)
        hopper_path=os.environ.get('HOPPER_LAUNCHER_PATH') or shutil.which('hopper') or ''
        rows.append(dict(name='Hopper',status=('Bulundu; REA durumu bilinmiyor' if hopper_path and os.path.exists(hopper_path) else 'REA durumu doğrulanamadı') if hopper is None else 'REA kontrolü başarılı' if hopper.get('ok') else 'Bulundu; REA için hazır değil' if hopper_path and os.path.exists(hopper_path) else 'Bulunamadı / yapılandırılmamış',path=hopper_path or '—',version='—',detail='\n'.join(str(hopper.get(k,'')) for k in ('detail','remediation') if hopper.get(k)) if hopper else 'REA doctor kontrolü bulunamadı.'))
        return rows

    def scan(self):
        rows=[]
        def add(row):rows.append(row);self.row_ready.emit(row)
        for name,commands,args in TOOLS:
            self.check()
            if name == 'Java' and os.environ.get('JAVA_HOME'):
                commands=(os.path.join(os.environ['JAVA_HOME'],'bin','java'),*commands)
            add(self.cli_row(name,commands,args))
        binary=self.rea_bin if os.path.isfile(self.rea_bin) else shutil.which(self.rea_bin)
        if binary:
            code,text=self.probe([binary,'--version'])
            add(dict(name='REA motoru',status='Kullanılabilir (CLI)' if code==0 else 'Çalıştırılamadı',path=binary,version=text.splitlines()[0][:180] if text else '—',detail=text[:6000]))
            code,text=self.probe([binary,'doctor','--format','json'],timeout=20,limit=2*1024*1024)
            try:
                doctor=json.loads(text)
                if not isinstance(doctor,dict) or not isinstance(doctor.get('providerInspections'),list):raise ValueError('Tanılama şeması tanınmadı.')
                # doctor exit 1 means missing optional tools; its structured checks are still valid.
                for row in self.provider_rows(doctor):add(row)
            except (ValueError,TypeError,KeyError):
                for row in self.provider_rows({}):row['detail']+='\nREA tanılama hatası: '+text[:1500];add(row)
        else:
            add(dict(name='REA motoru',status='Bulunamadı',path=self.rea_bin,version='—',detail='Settings içindeki REA Standalone Binary Path yolunu kontrol edin.'))
            for row in self.provider_rows({}):add(row)
        return rows

    def run(self):
        try:self.completed.emit(self.scan())
        except ToolsCancelled:self.cancelled.emit()
        except Exception as exc:self.failed.emit(str(exc))


def tools_report(rows):
    lines=['Rea — analiz araçlarının durumu','', 'Bu rapor sürüm komutları ve REA doctor kontrolleridir; hedef dosya üzerinde gerçek analiz veya lisans testi değildir.','']
    for row in rows:lines += [row['name']+' — '+row['status'],'Yol: '+row['path'],'Sürüm: '+row['version'],row['detail'],'']
    return '\n'.join(lines)


class ToolStatusDialog(QDialog):
    def __init__(self,parent=None,rea_bin='rea'):
        super().__init__(parent);self.rea_bin=rea_bin;self.worker=None;self.rows=[]
        self.setWindowTitle('Analiz araçlarının durumu');self.resize(1100,750)
        layout=QVBoxLayout(self)
        note=QLabel('PATH araçları sürüm komutuyla, Ghidra ve diğer sağlayıcılar REA tanılamasıyla kontrol edilir. “CLI kullanılabilir” tam analiz veya lisans doğrulaması değildir.');note.setWordWrap(True);layout.addWidget(note)
        buttons=QHBoxLayout();self.refresh=QPushButton('Yeniden kontrol et');self.refresh.clicked.connect(self.start);buttons.addWidget(self.refresh)
        self.stop=QPushButton('Durdur');self.stop.clicked.connect(self.cancel);self.stop.setEnabled(False);buttons.addWidget(self.stop)
        self.export_button=QPushButton('Raporu kaydet');self.export_button.clicked.connect(self.export);self.export_button.setEnabled(False);buttons.addWidget(self.export_button);layout.addLayout(buttons)
        self.status=QLabel('Kontrol bekleniyor.');self.status.setTextFormat(Qt.PlainText);layout.addWidget(self.status)
        self.table=QTableWidget(0,4);self.table.setHorizontalHeaderLabels(['Araç','Durum','Sürüm','Yol']);self.table.setEditTriggers(QAbstractItemView.NoEditTriggers);self.table.setSelectionBehavior(QAbstractItemView.SelectRows);self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch);layout.addWidget(self.table)
        self.details=QPlainTextEdit();self.details.setReadOnly(True);layout.addWidget(self.details)
        self.table.currentCellChanged.connect(self.show_detail)

    def start(self):
        if self.worker and self.worker.isRunning():return
        self.rows=[];self.table.setRowCount(0);self.details.clear();self.export_button.setEnabled(False);self.refresh.setEnabled(False);self.stop.setEnabled(True);self.status.setText('Araçlar kontrol ediliyor…')
        self.worker=ToolStatusWorker(self.rea_bin,self);self.worker.row_ready.connect(self.add_row);self.worker.completed.connect(lambda rows:self.status.setText(f'{len(rows)} araç/sağlayıcı kontrol edildi.'))
        self.worker.failed.connect(lambda error:self.status.setText('Kontrol hatası: '+error));self.worker.cancelled.connect(lambda:self.status.setText('Kontrol durduruldu; listede tamamlanan sonuçlar var.'))
        self.worker.finished.connect(self.finished_work);self.worker.start()

    def add_row(self,row):
        index=len(self.rows);self.rows.append(row);self.table.insertRow(index)
        for column,key in enumerate(('name','status','version','path')):
            cell=QTableWidgetItem(row[key]);cell.setToolTip(row[key]);self.table.setItem(index,column,cell)
        status=row['status'];color='#047857' if status in ('Kullanılabilir (CLI)','REA için hazır','REA kontrolü başarılı') else '#B45309' if 'Bulundu' in status or 'doğrulanamadı' in status else '#B91C1C'
        self.table.item(index,1).setForeground(QColor(color))
        if index==0:self.table.selectRow(0)

    def show_detail(self,row,*args):
        if 0<=row<len(self.rows):self.details.setPlainText(self.rows[row]['detail'])

    def finished_work(self):
        self.refresh.setEnabled(True);self.stop.setEnabled(False);self.export_button.setEnabled(bool(self.rows))

    def cancel(self):
        if self.worker:self.worker.cancel()

    def export(self):
        if not self.rows:return
        path,_=QFileDialog.getSaveFileName(self,'Araç durum raporu','arac-durumu.txt','Metin (*.txt)')
        if not path:return
        if not os.path.splitext(path)[1]:path+='.txt'
        try:
            from rea_gui import atomic_private_write
            atomic_private_write(path,tools_report(self.rows))
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

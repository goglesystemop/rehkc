"""Non-blocking engine management attached to the normal desktop launcher."""
import json
from pathlib import Path
import sys
from PyQt5.QtCore import QProcess, QTimer
from PyQt5.QtWidgets import QMessageBox


def update_message(report):
    lines = []
    if report.get('approved_update_available'):
        lines.append('REHKC ile doğrulanmış yeni motor sürümleri hazır. Analiz motorları menüsünden güncelleyebilirsiniz.')
    for item in report.get('updates', []):
        line = item['component']+': '+item['installed']+' → '+item['latest_tag']
        if item.get('java_minimum'):
            line += '; gereken Java: '+item['java_minimum']+'+'
        if item.get('requires_python'):
            line += '; gereken Python: '+item['requires_python']
        if item['compatibility'] == 'unsupported_by_bundled_rea':
            line += ' (mevcut REA motoru bu Ghidra hattını desteklemiyor)'
        elif item['compatibility'] == 'requires_rehkc_release':
            line += ' (REHKC sürüm güncellemesi gerekir)'
        else:
            line += ' (uyumluluk doğrulaması bekliyor)'
        lines.append(line)
    if report.get('errors'):
        lines.append('Bazı kontroller tamamlanamadı; bir gün sonra yeniden denenecek.')
    return '\n'.join(lines) or 'Kontrol edilen bileşenler için yeni sürüm bulunmadı.'


def install_tool_menu(application, window):
    menu = window.menuBar().addMenu('Analiz motorları')
    process = QProcess(window)
    window.managed_tools_process = process
    state = {'action':None, 'manual':False}

    def start(action, manual=True):
        if process.state() != QProcess.NotRunning:
            if manual:
                window.append_log('Motor kurulumu veya güncelleme kontrolü zaten çalışıyor.', 'info')
            return
        state.update(action=action, manual=manual)
        process.setProgram(sys.executable)
        args = ['-I', '-B', str(Path(__file__).with_name('rehkc_tools.py')), action]
        if not manual:
            args.append('--if-due')
        process.setArguments(args)
        if manual:
            window.append_log('Analiz motorları: '+action+' işlemi başladı.', 'info')
        process.start()

    def finished(code, exit_status):
        out = bytes(process.readAllStandardOutput()).decode('utf-8', 'replace')
        error = bytes(process.readAllStandardError()).decode('utf-8', 'replace')
        try:
            report = json.loads(out)
        except ValueError:
            if state['manual']:
                window.append_log('Motor işlemi tamamlanamadı: '+error[-1800:], 'warn')
            return
        if report.get('skipped'):
            return
        if state['action'] == 'check-updates':
            text = update_message(report)
            if state['manual'] or report.get('updates') or report.get('approved_update_available') or report.get('errors'):
                window.append_log(text, 'warn' if report.get('errors') else 'info')
            if state['manual']:
                QMessageBox.information(window, 'Bileşen güncellemeleri', text)
        elif state['action'] == 'status':
            if report.get('managed'):
                text = '\n'.join(name+': '+value for name,value in report['versions'].items())
                text += '\n\nBağımlılık ve başlatma kontrolleri başarılı.'
            else:
                text = 'Yönetilen motorlar kurulu değil. Mevcut harici motorlar kullanılabilir.'
            QMessageBox.information(window, 'Analiz motorları', text)
        else:
            window.append_log('Analiz motorları hazır. Yeni motor grubunu kullanmak için REHKC’yi yeniden açın.', 'success')
    process.finished.connect(finished)
    process.errorOccurred.connect(lambda error: window.append_log('Motor işlemi başlatılamadı.', 'warn')
                                 if state['manual'] and error == QProcess.FailedToStart else None)
    for label, action in [('Motor durumu', 'status'), ('Güncellemeleri kontrol et', 'check-updates'),
                          ('Paketin motorlarını kur', 'install'), ('Doğrulanmış sürümlere güncelle', 'update'),
                          ('Önceki motor grubuna dön', 'rollback')]:
        menu.addAction(label).triggered.connect(lambda checked=False, action=action:start(action))

    def stop():
        if process.state() != QProcess.NotRunning:
            process.terminate()
            if not process.waitForFinished(500):
                process.kill(); process.waitForFinished(500)
    application.aboutToQuit.connect(stop)
    QTimer.singleShot(1500, lambda:start('check-updates', manual=False))
    timer = QTimer(window)
    timer.setInterval(3600000)
    timer.timeout.connect(lambda:start('check-updates', manual=False))
    timer.start()
    window.managed_tools_timer = timer

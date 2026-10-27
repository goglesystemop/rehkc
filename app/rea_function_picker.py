"""Bounded symbol/entry picker. Addresses are observations, not a complete inventory."""
import re
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
                            QTableWidget, QTableWidgetItem, QPushButton, QAbstractItemView)


def function_rows(value):
    if not isinstance(value, list):
        raise ValueError('Fonksiyon envanteri liste olmalı.')
    rows = {}
    for item in value[:1032]:
        if not isinstance(item, dict):
            continue
        address = item.get('address')
        if not isinstance(address, str) or not re.fullmatch(r'0x[0-9a-fA-F]{1,16}', address):
            continue
        address = hex(int(address, 16))
        name = item.get('name')
        name = name[:256] if isinstance(name, str) and name.strip() else '(adsız)'
        rows.setdefault(address, [])
        if name not in rows[address] and len(rows[address]) < 4:
            rows[address].append(name)
    return [{'address': address, 'name': ' / '.join(names)}
            for address, names in sorted(rows.items(), key=lambda row: int(row[0], 16))]


class FunctionPickerDialog(QDialog):
    def __init__(self, value, parent=None):
        super().__init__(parent)
        self.rows = function_rows(value)
        self.setWindowTitle('Fonksiyon bul ve analiz et')
        self.resize(740, 500)
        layout = QVBoxLayout(self)
        note = QLabel('Hızlı giriş/sembol listesi — tam fonksiyon envanteri değildir.\n'
                      'Ad veya adresle filtreleyin; seçim adres üzerinden analiz edilir.')
        note.setTextFormat(Qt.PlainText)
        layout.addWidget(note)
        self.search = QLineEdit()
        self.search.setPlaceholderText('Fonksiyon adı veya 0x adresi…')
        self.search.setClearButtonEnabled(True)
        layout.addWidget(self.search)
        self.table = QTableWidget(len(self.rows), 2)
        self.table.setHorizontalHeaderLabels(['Adres', 'Ad / sembol'])
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setColumnWidth(0, 180)
        for row, item in enumerate(self.rows):
            self.table.setItem(row, 0, QTableWidgetItem(item['address']))
            self.table.setItem(row, 1, QTableWidgetItem(item['name']))
        layout.addWidget(self.table)
        controls = QHBoxLayout()
        self.count = QLabel()
        controls.addWidget(self.count)
        controls.addStretch()
        self.decompile = QPushButton('Seçili fonksiyonu analiz et')
        self.decompile.setDefault(True)
        self.decompile.clicked.connect(self.accept)
        close = QPushButton('Vazgeç')
        close.clicked.connect(self.reject)
        controls.addWidget(self.decompile)
        controls.addWidget(close)
        layout.addLayout(controls)
        self.search.textChanged.connect(self.filter_rows)
        self.table.itemSelectionChanged.connect(self.update_selection)
        self.table.cellDoubleClicked.connect(lambda *_: self.accept())
        self.filter_rows('')
        self.search.setFocus()

    def filter_rows(self, text):
        query = text.strip().casefold()
        visible = []
        for row, item in enumerate(self.rows):
            match = query in (item['address'] + ' ' + item['name']).casefold()
            self.table.setRowHidden(row, not match)
            if match:
                visible.append(row)
        if self.procedure() is None or self.table.currentRow() not in visible:
            self.table.clearSelection()
            if visible:
                self.table.selectRow(visible[0])
        self.count.setText(f'{len(visible)} / {len(self.rows)} giriş' if self.rows else 'Giriş/sembol bulunamadı; adresle elle analiz edebilirsiniz.')
        self.update_selection()

    def procedure(self):
        selected = self.table.selectionModel().selectedRows()
        if not selected or self.table.isRowHidden(selected[0].row()):
            return None
        return self.rows[selected[0].row()]['address']

    def update_selection(self):
        self.decompile.setEnabled(self.procedure() is not None)

    def accept(self):
        if self.procedure() is not None:
            super().accept()

#!/usr/bin/env python3
"""
rea_gui.py — Desktop GUI for REA (Reverse Engineering Anything)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Light-themed, modern PyQt5 desktop interface integrated with Electra AI Center:
  • Prominent Binary Browser & Drag-and-Drop Loader
  • Quick Action Bar (Inspect, Disassemble, Decompile, Strings, Security Audit, Auto-Analyze)
  • Analysis Tabs (Overview, Disassembly, Decompiled C, Strings & Symbols, Hex View)
  • Real-Time Live Execution Log with streaming stdout/stderr
  • Interactive Electra AI Copilot with multi-turn chat & reverse engineering prompts
  • Model Selection & API Settings (Defaults to Electra Nano)
"""

import os
import sys
import json
import time
import hashlib
import binascii
import subprocess
import threading
from typing import Optional, List, Dict, Any
from rehkc_paths import config_dir, data_dir

from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer, QSize, QPoint, QUrl
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QStackedWidget, QFrame, QLineEdit,
    QTextEdit, QPlainTextEdit, QScrollArea, QSizePolicy, QDialog,
    QMessageBox, QProgressBar, QSplitter, QTabWidget, QComboBox,
    QTableWidget, QTableWidgetItem, QHeaderView, QCheckBox,
    QFileDialog, QMenu, QAction, QGroupBox, QSpinBox, QDoubleSpinBox,
    QShortcut, QListWidget, QInputDialog
)
from PyQt5.QtGui import (
    QFont, QColor, QPalette, QIcon, QCursor, QPixmap,
    QTextCursor, QTextCharFormat, QKeySequence, QTextDocument, QDesktopServices
)

# ─────────────────────────────────────────────────────────────────────────────
#  DEFAULT CONFIGURATION & PATHS
# ─────────────────────────────────────────────────────────────────────────────

def get_rea_bin_path() -> str:
    """Dynamically resolves the path to the rea.bin executable."""
    if os.environ.get("REA_BIN_PATH") and os.path.isfile(os.environ["REA_BIN_PATH"]):
        return os.environ["REA_BIN_PATH"]

    onefile_dir = os.environ.get("NUITKA_ONEFILE_DIRECTORY")
    if onefile_dir:
        cand = os.path.join(onefile_dir, "rea.bin")
        if os.path.isfile(cand):
            try:
                os.chmod(cand, 0o755)
            except Exception:
                pass
            return cand

    exe_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
    for name in ("rea-engine", "rea.bin", "rea"):
        cand = os.path.join(exe_dir, name)
        if os.path.isfile(cand) and cand != os.path.abspath(sys.argv[0]):
            return cand

    script_dir = os.path.dirname(os.path.abspath(__file__))
    for name in ("rea-engine", "rea.bin", "rea"):
        cand = os.path.join(script_dir, name)
        if os.path.isfile(cand) and cand != os.path.abspath(sys.argv[0]):
            return cand


    return "rea"

def get_icon_path() -> str:
    """Resolves icon path in standalone onefile mode or development."""
    onefile_dir = os.environ.get("NUITKA_ONEFILE_DIRECTORY")
    if onefile_dir:
        cand = os.path.join(onefile_dir, "ai-icon.png")
        if os.path.isfile(cand):
            return cand
    for p in (os.path.join(os.path.dirname(os.path.abspath(__file__)), "ai-icon.png"),):
        if os.path.isfile(p):
            return p
    return ""

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REA_BIN_PATH = get_rea_bin_path()
ICON_PATH = get_icon_path()

DEFAULT_SERVER_BASE = "https://makululinux.us:2007"
FALLBACK_SERVER_BASE = "https://api.makululinux.us"
CONFIG_DIR = str(config_dir())
CONFIG_FILE = os.path.join(CONFIG_DIR, "gui_settings.json")
ELECTRA_AUTH_FILE = os.path.expanduser("~/.config/ai_terminal/electra_auth.json")
ELECTRA_API_KEY_FILE = os.path.expanduser("~/.config/electra/api_key")

AVAILABLE_MODELS = [
    ("electra-nano", "Electra Nano (Default - Fast / Low Latency)"),
    ("electra", "Electra AI (Cloud Flagship)"),
    ("qwen3.8-coder", "Qwen 3.8 Coder (Reverse Engineering & Code Specialist)"),
]


# ─────────────────────────────────────────────────────────────────────────────
#  CREDENTIAL DISCOVERY & SETTINGS
# ─────────────────────────────────────────────────────────────────────────────

def discover_electra_api_key() -> str:
    """Discovers Electra API key from environment, auth file, or config."""
    # 1. Environment variable
    env_key = os.environ.get("ELECTRA_API_KEY", "").strip()
    if env_key:
        return env_key

    # 2. ~/.config/ai_terminal/electra_auth.json
    if os.path.isfile(ELECTRA_AUTH_FILE):
        try:
            with open(ELECTRA_AUTH_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                key = data.get("api_key", "").strip()
                if key:
                    return key
        except Exception:
            pass

    # 3. ~/.config/electra/api_key
    if os.path.isfile(ELECTRA_API_KEY_FILE):
        try:
            with open(ELECTRA_API_KEY_FILE, "r", encoding="utf-8") as f:
                key = f.read().strip()
                if key:
                    return key
        except Exception:
            pass

    return ""


def load_gui_settings() -> Dict[str, Any]:
    """Loads GUI configuration from disk, defaulting model to electra-nano."""
    default_settings = {
        "server_base": "http://127.0.0.1:1234",
        "api_key": "",
        "model": "",
        "provider": "lmstudio",
        "temperature": 0.3,
        "rea_bin": REA_BIN_PATH,
        "auto_scroll_log": True,
        "context_char_limit": 12000,
        "response_token_limit": 1024,
        "token_limit": 4096
    }
    if os.path.isfile(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                default_settings.update(data)
        except Exception:
            pass

    if not default_settings.get("api_key") and default_settings.get("provider") not in ("lmstudio", "ollama", "chatgpt"):
        default_settings["api_key"] = discover_electra_api_key()


    return default_settings


def save_gui_settings(settings: Dict[str, Any]) -> None:
    """Persists GUI configuration to disk."""
    try:
        os.makedirs(CONFIG_DIR, exist_ok=True)
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(settings, f, indent=2)
    except Exception as e:
        print(f"[REA-GUI] Warning: could not save settings: {e}", file=sys.stderr)


# ─────────────────────────────────────────────────────────────────────────────
#  LIGHT THEME QSS STYLESHEET
# ─────────────────────────────────────────────────────────────────────────────

LIGHT_THEME_QSS = """
/* Global Reset and Light Theme Foundation */
QWidget {
    background-color: #F8FAFC;
    color: #0F172A;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Ubuntu", "Helvetica Neue", sans-serif;
    font-size: 13px;
    selection-background-color: #2563EB;
    selection-color: #FFFFFF;
}

/* Window & Panels */
QMainWindow {
    background-color: #F8FAFC;
}

QFrame[class="card"] {
    background-color: #FFFFFF;
    border: 1px solid #E2E8F0;
    border-radius: 8px;
}

/* Header bar */
#HeaderFrame {
    background-color: #FFFFFF;
    border-bottom: 1px solid #E2E8F0;
    padding: 10px 16px;
}

#AppTitle {
    font-size: 18px;
    font-weight: 700;
    color: #1E293B;
}

#AppSubtitle {
    font-size: 11px;
    font-weight: 500;
    color: #64748B;
}

#BadgePill {
    background-color: #EFF6FF;
    color: #2563EB;
    font-size: 11px;
    font-weight: 600;
    padding: 3px 8px;
    border-radius: 10px;
    border: 1px solid #BFDBFE;
}

/* Base Buttons */
QPushButton {
    background-color: #FFFFFF;
    color: #334155;
    border: 1px solid #CBD5E1;
    border-radius: 6px;
    padding: 6px 14px;
    font-weight: 500;
}

QPushButton:hover {
    background-color: #F1F5F9;
    border-color: #94A3B8;
    color: #0F172A;
}

QPushButton:pressed {
    background-color: #E2E8F0;
}

/* Primary Vibrant Blue Buttons */
QPushButton[class="primary"], #btn_browse, #btn_hero_browse, #btn_auto_ai, #btn_send, #btn_run_cmd, #btn_save_settings, #btn_close_about {
    background-color: #2563EB;
    color: #FFFFFF;
    border: 1px solid #1D4ED8;
    font-weight: 600;
}

QPushButton[class="primary"]:hover, #btn_browse:hover, #btn_hero_browse:hover, #btn_auto_ai:hover, #btn_send:hover, #btn_run_cmd:hover, #btn_save_settings:hover, #btn_close_about:hover {
    background-color: #1D4ED8;
    border-color: #1E40AF;
    color: #FFFFFF;
}

QPushButton[class="primary"]:pressed, #btn_browse:pressed, #btn_hero_browse:pressed, #btn_auto_ai:pressed, #btn_send:pressed, #btn_run_cmd:pressed, #btn_save_settings:pressed, #btn_close_about:pressed {
    background-color: #1E40AF;
    color: #FFFFFF;
}

/* Action Toolbar Buttons */
QPushButton[class="action"] {
    background-color: #F8FAFC;
    color: #1E293B;
    border: 1px solid #E2E8F0;
    border-radius: 6px;
    padding: 6px 12px;
    font-weight: 600;
    text-align: center;
}

QPushButton[class="action"]:hover {
    background-color: #EFF6FF;
    border-color: #93C5FD;
    color: #1D4ED8;
}

/* Quick Chips */
QPushButton[class="chip"] {
    background-color: #F1F5F9;
    color: #475569;
    border: 1px solid #E2E8F0;
    border-radius: 12px;
    padding: 4px 10px;
    font-size: 11px;
    font-weight: 500;
}

QPushButton[class="chip"]:hover {
    background-color: #E0E7FF;
    border-color: #A5B4FC;
    color: #3730A3;
}

/* Input Fields */
QLineEdit, QTextEdit, QPlainTextEdit, QSpinBox, QDoubleSpinBox, QComboBox {
    background-color: #FFFFFF;
    color: #0F172A;
    border: 1px solid #CBD5E1;
    border-radius: 6px;
    padding: 6px 10px;
}

QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus, QComboBox:focus {
    border: 1px solid #2563EB;
}

QComboBox::drop-down {
    border: none;
    padding-right: 8px;
}

/* Tabs */
QTabWidget::pane {
    background-color: #FFFFFF;
    border: 1px solid #E2E8F0;
    border-top: none;
    border-radius: 0 0 8px 8px;
}

QTabBar::tab {
    background-color: #F1F5F9;
    color: #64748B;
    border: 1px solid #E2E8F0;
    border-bottom: none;
    padding: 7px 12px;
    font-weight: 600;
    margin-right: 4px;
    border-top-left-radius: 6px;
    border-top-right-radius: 6px;
}

QTabBar::tab:selected {
    background-color: #FFFFFF;
    color: #2563EB;
    border-bottom: 2px solid #2563EB;
}

QTabBar::tab:hover:!selected {
    background-color: #E2E8F0;
    color: #1E293B;
}

/* Dropdown Menu */
QMenu {
    background-color: #FFFFFF;
    color: #1E293B;
    border: 1px solid #CBD5E1;
    border-radius: 6px;
    padding: 4px;
}

QMenu::item {
    padding: 6px 20px 6px 12px;
    border-radius: 4px;
}

QMenu::item:selected {
    background-color: #EFF6FF;
    color: #1D4ED8;
}

QMenu::separator {
    height: 1px;
    background-color: #E2E8F0;
    margin: 4px 0;
}

/* Code & Log Viewers */
QPlainTextEdit[class="code-view"], QTextEdit[class="code-view"] {
    background-color: #FFFFFF;
    color: #1E293B;
    border: none;
    font-family: "DejaVu Sans Mono", "Fira Code", "Consolas", monospace;
    font-size: 12px;
    line-height: 1.4;
}

/* Scrollbars */
QScrollBar:vertical {
    border: none;
    background: #F1F5F9;
    width: 8px;
    border-radius: 4px;
}

QScrollBar::handle:vertical {
    background: #CBD5E1;
    border-radius: 4px;
    min-height: 20px;
}

QScrollBar::handle:vertical:hover {
    background: #94A3B8;
}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0px;
}

QScrollBar:horizontal {
    border: none;
    background: #F1F5F9;
    height: 8px;
    border-radius: 4px;
}

QScrollBar::handle:horizontal {
    background: #CBD5E1;
    border-radius: 4px;
    min-width: 20px;
}

/* Splitter */
QSplitter::handle {
    background-color: #E2E8F0;
}

QSplitter::handle:horizontal {
    width: 4px;
}

QSplitter::handle:vertical {
    height: 4px;
}
"""


# ─────────────────────────────────────────────────────────────────────────────
#  BACKGROUND WORKERS (Asynchronous Subprocesses & Network)
# ─────────────────────────────────────────────────────────────────────────────

class ToolExecutionWorker(QThread):
    """Drain both pipes concurrently with bounded output and cancellable process groups."""
    log_line = pyqtSignal(str, str)
    completed = pyqtSignal(str, str)
    failed = pyqtSignal(str, str)

    def __init__(self, command_id: str, cmd_args: List[str], cwd: Optional[str] = None,
                 timeout: float = 300, stdout_limit: int = 32 * 1024 * 1024,
                 stderr_limit: int = 4 * 1024 * 1024):
        super().__init__()
        self.command_id = command_id
        self.cmd_args = list(cmd_args)
        self.cwd = cwd or SCRIPT_DIR
        self.timeout = timeout
        self.stdout_limit = stdout_limit
        self.stderr_limit = stderr_limit
        self._process: Optional[subprocess.Popen] = None
        self._is_cancelled = False

    def cancel(self):
        # The polling loop owns process creation and cleanup, avoiding a spawn/cancel race.
        self._is_cancelled = True

    def _cleanup_process(self):
        import signal
        process = self._process
        if process is None:
            return
        try:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            if process.poll() is None:
                try:
                    process.wait(timeout=0.5)
                except subprocess.TimeoutExpired:
                    pass
            # Kill remaining descendants too, including ones holding an inherited pipe open.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
        finally:
            for stream in (process.stdout, process.stderr):
                if stream is not None:
                    stream.close()
            self._process = None

    def run(self):
        import codecs
        import selectors
        self.log_line.emit("Running: " + " ".join(self.cmd_args), "run")
        started = time.monotonic()
        output = {"stdout": bytearray(), "stderr": bytearray()}
        limits = {"stdout": self.stdout_limit, "stderr": self.stderr_limit}
        decoders = {name: codecs.getincrementaldecoder("utf-8")("replace") for name in output}
        pending = {name: "" for name in output}
        log_remaining = 256 * 1024
        log_events = 512
        log_notice = False

        def log_text(name, data, final=False):
            nonlocal log_remaining, log_events, log_notice
            text = decoders[name].decode(data, final=final)
            if not log_remaining:
                if text and not log_notice:
                    self.log_line.emit("Canlı günlük sınırına ulaşıldı; sonuç çıktısı toplanmaya devam ediyor.", "warn")
                    log_notice = True
                return
            pending[name] += text
            while pending[name] and log_remaining:
                newline = pending[name].find("\n")
                if newline < 0 and len(pending[name]) < 4096 and not final:
                    break
                size = min(newline + 1 if newline >= 0 else len(pending[name]), 4096, log_remaining)
                piece = pending[name][:size]
                pending[name] = pending[name][size:]
                log_remaining -= size
                if piece.strip():
                    self.log_line.emit(piece.rstrip(), "info" if name == "stdout" else "warn")
                    log_events -= 1
                    if not log_events:
                        log_remaining = 0
            if not log_remaining:
                pending[name] = ""

        try:
            if self._is_cancelled:
                raise RuntimeError("İşlem durduruldu.")
            from rea_runtime import diagnostic_command
            self.cmd_args = diagnostic_command(self.cmd_args)
            self._process = subprocess.Popen(self.cmd_args, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, cwd=self.cwd, start_new_session=True)
            with selectors.DefaultSelector() as selector:
                selector.register(self._process.stdout, selectors.EVENT_READ, "stdout")
                selector.register(self._process.stderr, selectors.EVENT_READ, "stderr")
                while selector.get_map() or self._process.poll() is None:
                    if self._is_cancelled:
                        raise RuntimeError("İşlem durduruldu.")
                    if time.monotonic() - started > self.timeout:
                        raise RuntimeError("Analiz zaman sınırını aştı.")
                    for key, _ in selector.select(timeout=0.05):
                        chunk = os.read(key.fd, 65536)
                        name = key.data
                        if not chunk:
                            selector.unregister(key.fileobj)
                            log_text(name, b"", final=True)
                            continue
                        if len(output[name]) + len(chunk) > limits[name]:
                            raise RuntimeError("Araç çıktısı sınırı aşıldı (" + name + ").")
                        output[name].extend(chunk)
                        log_text(name, chunk)
            if self._is_cancelled:
                raise RuntimeError("İşlem durduruldu.")
            ret_code = self._process.wait()
            full_output = output["stdout"].decode("utf-8", "replace")
            err_text = output["stderr"].decode("utf-8", "replace")
            if ret_code:
                detail = err_text.strip()[-12000:] or full_output[-12000:]
                try:
                    payload = json.loads(full_output)
                    if isinstance(payload, dict) and payload.get("error"):
                        error = payload["error"]
                        detail = str(error.get("code", "")) + ": " + str(error.get("message", ""))
                        remediation = error.get("remediation", {})
                        if remediation.get("action"):
                            detail += "\n" + str(remediation["action"])
                except (ValueError, TypeError, AttributeError):
                    pass
                raise RuntimeError(f"Exit code {ret_code}: {detail}")
            self._cleanup_process()
            self.log_line.emit(f"Command '{self.command_id}' finished in {time.monotonic() - started:.2f}s (exit code 0)", "success")
            self.completed.emit(self.command_id, full_output)
        except Exception as exc:
            self._cleanup_process()
            self.log_line.emit(f"Execution error: {exc}", "error")
            self.failed.emit(self.command_id, str(exc))
        finally:
            self._cleanup_process()


class ModelListWorker(QThread):
    completed = pyqtSignal(list)
    memory_received = pyqtSignal(dict)
    connection_received = pyqtSignal(str)
    failed = pyqtSignal(str)

    def __init__(self, server_base, api_key, parent=None, provider="lmstudio"):
        super().__init__(parent)
        self.server_base = server_base.rstrip("/")
        self.api_key = api_key
        self.provider = provider
        self._http_seen = False

    def _get(self, path):
        import urllib.request
        req = urllib.request.Request(self.server_base + path)
        if self.api_key:
            req.add_header("Authorization", "Bearer " + self.api_key)
        with urllib.request.urlopen(req, timeout=3) as response:
            self._http_seen = True
            return json.load(response)

    def run(self):
        try:
            payload = self._get("/v1/models")
            self.connection_received.emit("Bağlı")
            models = sorted({item["id"] for item in payload["data"]
                             if isinstance(item, dict) and isinstance(item.get("id"), str)
                             and item["id"].strip()})
            if not models:
                raise ValueError("Sunucu model listesi boş.")
            states = {}
            error = ""
            try:
                if self.provider == "ollama":
                    running = self._get("/api/ps")["models"]
                    loaded = {value for item in running for value in (item.get("name"), item.get("model")) if isinstance(value, str)}
                    # The default Ollama tag is sometimes omitted in the compatibility API.
                    loaded |= {name[:-7] for name in list(loaded) if name.endswith(":latest")}
                    states = {model: model in loaded or model + ":latest" in loaded for model in models}
                else:
                    try:
                        catalog = self._get("/api/v1/models")["models"]
                        for item in catalog:
                            key = item.get("key")
                            instances = item.get("loaded_instances")
                            if isinstance(key, str) and isinstance(instances, list):
                                states[key] = bool(instances)
                                for instance in instances:
                                    if isinstance(instance.get("id"), str):
                                        states[instance["id"]] = True
                    except Exception:
                        catalog = self._get("/api/v0/models")["data"]
                        states = {item["id"]: item["state"] == "loaded" for item in catalog
                                  if item.get("state") in ("loaded", "not-loaded") and isinstance(item.get("id"), str)}
            except Exception as exc:
                states = {}
                error = str(exc)
            self.memory_received.emit({"states": states, "error": error})
            self.completed.emit(models)
        except Exception as exc:
            self.connection_received.emit(f"HTTP {exc.code}" if hasattr(exc, "code") else "API hatası" if self._http_seen else "Ulaşılamıyor")
            self.failed.emit(str(exc))


SESSION_PANES = ("overview", "disasm", "decomp", "strings", "hex", "raw")
SESSION_DIR = str(data_dir()/"sessions")


def atomic_private_write(path, content):
    """Replace a local UTF-8 document atomically; never leave a partial session."""
    import tempfile
    directory = os.path.dirname(os.path.abspath(path))
    fd, temporary = tempfile.mkstemp(prefix=".rea-save-", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def read_session(path):
    if os.path.getsize(path) > 64 * 1024 * 1024:
        raise ValueError("Oturum dosyası 64 MB sınırını aşıyor.")
    with open(path, encoding="utf-8") as stream:
        data = json.load(stream)
    if not isinstance(data, dict) or data.get("format") != "makulu-rea-session" or data.get("version") != 1:
        raise ValueError("Desteklenmeyen Rea oturum dosyası.")
    for key in ("target_path", "draft", "log", "format_badge", "size_badge", "saved_at"):
        if not isinstance(data.get(key), str):
            raise ValueError("Geçersiz oturum alanı: " + key)
    if "\x00" in data["target_path"]:
        raise ValueError("Geçersiz hedef dosya yolu.")
    if not isinstance(data.get("messages"), list):
        raise ValueError("Geçersiz sohbet geçmişi.")
    for message in data["messages"]:
        if not isinstance(message, dict) or message.get("role") not in ("user", "assistant") or not isinstance(message.get("content"), str):
            raise ValueError("Geçersiz sohbet mesajı.")
    if not isinstance(data.get("panes"), dict) or any(not isinstance(data["panes"].get(k), str) for k in SESSION_PANES):
        raise ValueError("Geçersiz analiz verisi.")
    if type(data.get("active_tab")) is not int or not 0 <= data["active_tab"] <= 5:
        raise ValueError("Geçersiz analiz sekmesi.")
    if data.get("provider") not in ("lmstudio", "ollama", "chatgpt") or not isinstance(data.get("model"), str):
        raise ValueError("Geçersiz model seçimi.")
    signature = data.get("target_signature")
    if signature is not None and (not isinstance(signature, dict) or
            set(signature) != {"size", "mtime_ns"} or
            any(type(v) is not int for v in signature.values())):
        raise ValueError("Geçersiz dosya bilgisi.")
    data.setdefault("session_notes", "")
    data.setdefault("bookmarks", [])
    if not isinstance(data["session_notes"], str) or len(data["session_notes"]) > 1000000:
        raise ValueError("Geçersiz oturum notları.")
    if not isinstance(data["bookmarks"], list) or len(data["bookmarks"]) > 10000:
        raise ValueError("Geçersiz yer imleri.")
    ids = set()
    for item in data["bookmarks"]:
        if not isinstance(item, dict) or any(not isinstance(item.get(k), str) for k in ("id", "title", "note", "pane", "target_path", "quote")):
            raise ValueError("Geçersiz yer imi alanı.")
        if (not item["id"] or item["id"] in ids or not item["title"].strip() or len(item["title"]) > 200
                or item["pane"] not in SESSION_PANES or not item["quote"].strip()
                or len(item["note"]) > 100000 or len(item["quote"]) > 1000000 or "\x00" in item["target_path"]
                or any(type(item.get(k)) is not int for k in ("first_line", "last_line"))
                or not 1 <= item["first_line"] <= item["last_line"] <= 2147483647):
            raise ValueError("Geçersiz yer imi.")
        ids.add(item["id"])
    data.setdefault("mcp_enabled", False)
    data.setdefault("mcp_runs", [])
    if type(data["mcp_enabled"]) is not bool:
        raise ValueError("Geçersiz MCP modu.")
    from rea_mcp import validate_runs
    validate_runs(data["mcp_runs"])
    from rea_saved_code import validate_saved_code
    data['code_exports'] = validate_saved_code(data.get('code_exports', {}), data['target_path'], data['panes'])
    return data


def export_session_text(data, markdown=True):
    """Export chat and saved analysis as text, never credentials or endpoint settings."""
    heading = "# " if markdown else ""
    lines = [heading + "Rea analiz oturumu", "", "Kaydedildi: " + data["saved_at"],
             "Hedef: " + (data["target_path"] or "—"),
             "Sunucu: " + data["provider"], "Model: " + data["model"], ""]
    lines += [("## " if markdown else "") + "Sohbet", ""]
    for message in data["messages"]:
        label = "Sen" if message["role"] == "user" else "Asistan"
        lines.extend([("### " if markdown else "") + label, "", message["content"], ""])
    if data["draft"]:
        lines.extend([("## " if markdown else "") + "Gönderilmemiş taslak", "", data["draft"], ""])
    for name, content in data["panes"].items():
        if content:
            lines.extend([("## " if markdown else "") + "Analiz: " + name, ""])
            if markdown:
                # The fence must remain longer than every backtick run in the analysis.
                import re
                longest = max([len(x) for x in re.findall(r"`+", content)] or [0])
                fence = "`" * max(3, longest + 1)
                lines.extend([fence + "text", content, fence, ""])
            else:
                lines.extend([content, ""])
    if data.get("session_notes"):
        lines.extend([("## " if markdown else "") + "Oturum notları", "", data["session_notes"], ""])
    if data.get("bookmarks"):
        lines.extend([("## " if markdown else "") + "Yer imleri", ""])
        for item in data["bookmarks"]:
            lines.extend([("### " if markdown else "") + item["title"],
                f"Kaynak: {item['target_path'] or 'Dosya seçilmedi'} · {item['pane']} · satır {item['first_line']}–{item['last_line']}", "", item["note"], ""])
            if markdown:
                import re
                fence = "`" * max(3, max([len(x) for x in re.findall(r"`+", item["quote"])] or [0]) + 1)
                lines.extend([fence + "text", item["quote"], fence, ""])
            else:
                lines.extend([item["quote"], ""])
    if data.get("mcp_runs"):
        lines += [("## " if markdown else "") + "MCP analiz günlüğü", ""]
        for run in data["mcp_runs"]:
            lines += ["Hedef: " + run["target"], "Model: " + run["provider_model"], "Durum: " + run["status"],
                      "SHA-256: " + run.get("target_sha256", "—"), ""]
            for event in run["events"]:
                lines += [event["id"] + " · " + event["tool"] + " · " + event["status"],
                          "Parametreler: " + json.dumps(event["arguments"], ensure_ascii=False)]
                output = event.get("output", event.get("error", "İşlem sürüyordu"))
                if markdown:
                    import re
                    fence = "`" * max(3, max([len(x) for x in re.findall(r"`+", output)] or [0]) + 1)
                    lines += [fence + "text", output, fence, ""]
                else:
                    lines += [output, ""]
    return "\n".join(lines)


def bounded_messages(system_prompt, context, history, limit):
    """Bound content characters while retaining the current prompt and whole recent turns."""
    current = dict(history[-1])
    if len(system_prompt) + len(current["content"]) > limit:
        raise ValueError("Mesaj bağlam sınırını aşıyor. Mesajı kısaltın veya Settings içindeki sınırı artırın.")
    remaining = limit - len(system_prompt) - len(current["content"])
    prefix = "\n\nCurrent Binary Context from REA Analysis Studio:\n"
    context_message = ""
    if context and remaining > len(prefix):
        allowance = min(remaining, max(len(prefix), limit // 3))
        context_message = (prefix + context)[:allowance]
        remaining -= len(context_message)
    turns = []
    for message in history[:-1]:
        if message["role"] == "user":
            turns.append([])
        if turns:
            turns[-1].append(dict(message))
    kept = []
    for turn in reversed(turns):
        cost = sum(len(m["content"]) for m in turn)
        if cost > remaining:
            break
        kept[0:0] = turn
        remaining -= cost
    result = [{"role": "system", "content": system_prompt + context_message}]
    result.extend(kept)
    result.append(current)
    info = {"characters": sum(len(m["content"]) for m in result),
            "dropped_messages": len(history) - 1 - len(kept),
            "context_truncated": bool(context) and len(context_message) < len(prefix + context)}
    return result, info


class ElectraAiChatWorker(QThread):
    """Read an OpenAI-compatible SSE stream and close its connection on cancellation."""
    log_line = pyqtSignal(str, str)
    chunk_received = pyqtSignal(str)
    completed = pyqtSignal(str)
    cancelled = pyqtSignal(str)
    failed = pyqtSignal(str)
    connection_received = pyqtSignal(str)
    model_received = pyqtSignal(str)
    metrics_received = pyqtSignal(dict)

    def __init__(self, server_base, api_key, model, messages,
                 temperature=0.3, max_tokens=1024):
        super().__init__()
        self.server_base = server_base.rstrip("/")
        self.api_key = api_key
        self.model = model
        self.messages = messages
        self.temperature = temperature
        self.max_tokens = max_tokens
        self._is_cancelled = False
        self._connection = None
        self._socket = None

    def cancel(self):
        import socket
        self._is_cancelled = True
        sock = self._socket or getattr(self._connection, "sock", None)
        if sock:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    def run(self):
        import http.client
        from urllib.parse import urlsplit
        pieces = []
        started = time.monotonic()
        actual_model = ""
        first_text = None
        outcome = "Hata"
        http_seen = False
        try:
            url = urlsplit(self.server_base)
            if url.scheme not in ("http", "https") or not url.hostname:
                raise ValueError("Geçersiz sunucu adresi")
            cls = http.client.HTTPSConnection if url.scheme == "https" else http.client.HTTPConnection
            conn = cls(url.hostname, url.port, timeout=60)
            self._connection = conn
            headers = {"Content-Type": "application/json", "Accept": "text/event-stream",
                       "User-Agent": "REA-Desktop-GUI/1.0"}
            if self.api_key:
                headers["Authorization"] = "Bearer " + self.api_key
            payload = {"model": self.model, "messages": self.messages,
                       "temperature": self.temperature, "stream": True,
                       "max_tokens": self.max_tokens}
            self.log_line.emit(f"Streaming {self.model} at {self.server_base}", "run")
            if self._is_cancelled:
                return
            conn.connect()
            self._socket = conn.sock
            if self._is_cancelled:
                return
            conn.request("POST", url.path.rstrip("/") + "/v1/chat/completions",
                         json.dumps(payload).encode("utf-8"), headers)
            response = conn.getresponse()
            http_seen = True
            self.connection_received.emit("Bağlı" if response.status == 200 else f"HTTP {response.status}")
            if response.status != 200:
                raise RuntimeError(f"HTTP {response.status}: " + response.read(8192).decode("utf-8", "replace"))
            if "text/event-stream" not in response.getheader("Content-Type", ""):
                raise RuntimeError("Sunucu akış yanıtı (SSE) döndürmedi.")
            done = False
            finished = False
            event_data = []
            while not self._is_cancelled:
                raw = response.readline(1048577)
                if len(raw) > 1048576:
                    raise RuntimeError("Sunucu akış kaydı çok büyük.")
                if not raw:
                    break
                line = raw.decode("utf-8").rstrip("\r\n")
                if line.startswith("data:"):
                    event_data.append(line[5:].lstrip(" "))
                    continue
                if line or not event_data:
                    continue
                data = "\n".join(event_data)
                event_data = []
                if data == "[DONE]":
                    done = True
                    break
                event = json.loads(data)
                reported_model = event.get("model")
                if isinstance(reported_model, str) and reported_model and reported_model != actual_model:
                    actual_model = reported_model
                    self.model_received.emit(actual_model)
                if event.get("error"):
                    raise RuntimeError(str(event["error"]))
                for choice in event.get("choices", []):
                    if choice.get("index", 0) != 0:
                        continue
                    text = choice.get("delta", {}).get("content") or ""
                    if text and not self._is_cancelled:
                        if first_text is None:
                            first_text = time.monotonic() - started
                        pieces.append(text)
                        self.chunk_received.emit(text)
                    if choice.get("finish_reason") is not None:
                        finished = True
                        if choice["finish_reason"] == "length":
                            self.log_line.emit("Yanıt uzunluk sınırına ulaştı.", "warn")
            if not self._is_cancelled:
                if not (done or finished):
                    raise RuntimeError("Yanıt akışı tamamlanmadan bağlantı kesildi.")
                if not pieces:
                    raise RuntimeError("Model görünür yanıt üretmedi; yanıt sınırını artırmayı deneyin.")
                self.log_line.emit(f"Yanıt {time.monotonic() - started:.2f} saniyede tamamlandı.", "success")
                outcome = "Tamamlandı"
                self.completed.emit("".join(pieces))
        except Exception as exc:
            if not self._is_cancelled:
                if not http_seen:
                    self.connection_received.emit("Ulaşılamıyor")
                self.failed.emit(str(exc))
        finally:
            self.metrics_received.emit({"model": actual_model, "elapsed": time.monotonic() - started,
                "first_text": first_text, "outcome": "Durduruldu" if self._is_cancelled else outcome})
            if self._connection:
                self._connection.close()
            self._socket = None
            if self._is_cancelled:
                self.cancelled.emit("".join(pieces))


# ─────────────────────────────────────────────────────────────────────────────
#  SETTINGS DIALOG
# ─────────────────────────────────────────────────────────────────────────────

class SettingsDialog(QDialog):
    """Configuration dialog for API keys, server endpoints, and binary path."""

    def __init__(self, parent=None, settings: Optional[Dict[str, Any]] = None):
        super().__init__(parent)
        self.setWindowTitle("Electra AI & REA Settings")
        self.setMinimumWidth(520)
        self.setStyleSheet(LIGHT_THEME_QSS)

        self.settings = dict(settings or {})
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(16)
        layout.setContentsMargins(20, 20, 20, 20)

        # Title
        title = QLabel("Application & Provider Settings")
        title.setStyleSheet("font-size: 16px; font-weight: 700; color: #1E293B;")
        layout.addWidget(title)

        desc = QLabel("Configure Electra AI Center connectivity and local reverse engineering engine.")
        desc.setStyleSheet("color: #64748B; font-size: 12px;")
        desc.setWordWrap(True)
        layout.addWidget(desc)

        # Electra AI Server Group
        grp_ai = QGroupBox("Electra AI Center")
        grp_ai.setStyleSheet("font-weight: 600; color: #1E293B;")
        layout_ai = QVBoxLayout(grp_ai)
        layout_ai.setSpacing(10)

        # Server URL
        layout_ai.addWidget(QLabel("Server Endpoint URL:"))
        self.txt_server = QLineEdit(self.settings.get("server_base", DEFAULT_SERVER_BASE))
        layout_ai.addWidget(self.txt_server)

        # API Key
        layout_ai.addWidget(QLabel("Electra API Key / Token:"))
        key_layout = QHBoxLayout()
        self.txt_key = QLineEdit(self.settings.get("api_key", ""))
        self.txt_key.setEchoMode(QLineEdit.Password)
        self.btn_show_key = QPushButton("Show")
        self.btn_show_key.setFixedWidth(60)
        self.btn_show_key.clicked.connect(self._toggle_show_key)
        key_layout.addWidget(self.txt_key)
        key_layout.addWidget(self.btn_show_key)
        layout_ai.addLayout(key_layout)

        # Test Connection Button
        test_layout = QHBoxLayout()
        self.btn_test = QPushButton("Test Connection")
        self.btn_test.clicked.connect(self._test_connection)
        self.lbl_test_result = QLabel("")
        self.lbl_test_result.setStyleSheet("font-size: 11px;")
        test_layout.addWidget(self.btn_test)
        test_layout.addWidget(self.lbl_test_result)
        test_layout.addStretch()
        layout_ai.addLayout(test_layout)

        layout.addWidget(grp_ai)
        if self.settings.get("provider") == "chatgpt":
            grp_ai.hide()
            desc.setText("Bulut bağlantısı Continue with ChatGPT ile yönetilir; API anahtarı gerekmez. Kullanım planınızın kota ve izinlerine bağlıdır.")

        grp_context = QGroupBox("Sohbet sınırları")
        limits = QVBoxLayout(grp_context)
        limits.addWidget(QLabel("Bağlam sınırı (karakter):"))
        self.spin_context = QSpinBox()
        self.spin_context.setRange(1000, 1000000)
        self.spin_context.setSingleStep(1000)
        self.spin_context.setValue(int(self.settings.get("context_char_limit", 12000)))
        limits.addWidget(self.spin_context)
        note = QLabel("Eski konuşmalar ve analiz metni bu sınıra göre azaltılır. Modelin token sınırı farklı olabilir.")
        note.setWordWrap(True)
        limits.addWidget(note)
        limits.addWidget(QLabel("En fazla yanıt uzunluğu (token):"))
        self.spin_response = QSpinBox()
        self.spin_response.setRange(64, 32768)
        self.spin_response.setValue(int(self.settings.get("response_token_limit", 1024)))
        limits.addWidget(self.spin_response)
        if self.settings.get("provider") == "chatgpt":
            self.spin_response.setEnabled(False)
            self.spin_response.setToolTip("Bu sınır yerel sunucular içindir; ChatGPT planında modelin yanıt sınırları geçerlidir.")
        layout.addWidget(grp_context)

        # Local Engine Group
        grp_engine = QGroupBox("Local REA Engine")
        grp_engine.setStyleSheet("font-weight: 600; color: #1E293B;")
        layout_engine = QVBoxLayout(grp_engine)
        layout_engine.setSpacing(10)

        layout_engine.addWidget(QLabel("REA Standalone Binary Path:"))
        bin_layout = QHBoxLayout()
        self.txt_bin = QLineEdit(self.settings.get("rea_bin", REA_BIN_PATH))
        btn_browse_bin = QPushButton("Browse...")
        btn_browse_bin.clicked.connect(self._browse_binary)
        bin_layout.addWidget(self.txt_bin)
        bin_layout.addWidget(btn_browse_bin)
        layout_engine.addLayout(bin_layout)

        layout.addWidget(grp_engine)

        # Dialog Buttons
        btn_box = QHBoxLayout()
        btn_box.addStretch()

        btn_cancel = QPushButton("Cancel")
        btn_cancel.clicked.connect(self.reject)
        btn_box.addWidget(btn_cancel)

        btn_save = QPushButton("Save Settings")
        btn_save.setObjectName("btn_save_settings")
        btn_save.setProperty("class", "primary")
        btn_save.clicked.connect(self._save_and_close)
        btn_box.addWidget(btn_save)

        layout.addLayout(btn_box)

    def _toggle_show_key(self):
        if self.txt_key.echoMode() == QLineEdit.Password:
            self.txt_key.setEchoMode(QLineEdit.Normal)
            self.btn_show_key.setText("Hide")
        else:
            self.txt_key.setEchoMode(QLineEdit.Password)
            self.btn_show_key.setText("Show")

    def _browse_binary(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Select REA Standalone Binary", self.txt_bin.text() or SCRIPT_DIR
        )
        if path:
            self.txt_bin.setText(path)

    def _test_connection(self):
        self.lbl_test_result.setText("Pinging Electra AI...")
        self.lbl_test_result.setStyleSheet("color: #2563EB;")
        QApplication.processEvents()

        server = self.txt_server.text().strip().rstrip("/")
        key = self.txt_key.text().strip()

        def _do_test():
            import urllib.request
            try:
                url = f"{server}/v1/models"
                req = urllib.request.Request(url)
                if key:
                    req.add_header("Authorization", f"Bearer {key}")
                    req.add_header("x-goog-api-key", key)
                with urllib.request.urlopen(req, timeout=5) as r:
                    if r.status in (200, 204):
                        return True, "Connected successfully (HTTP 200)"
                    return False, f"Server responded with status {r.status}"
            except Exception as e:
                return False, f"Failed: {e}"

        ok, msg = _do_test()
        if ok:
            self.lbl_test_result.setText(f"[OK] {msg}")
            self.lbl_test_result.setStyleSheet("color: #10B981; font-weight: 600;")
        else:
            self.lbl_test_result.setText(f"[Failed] {msg}")
            self.lbl_test_result.setStyleSheet("color: #EF4444; font-weight: 500;")

    def _save_and_close(self):
        self.settings["server_base"] = self.txt_server.text().strip()
        self.settings["api_key"] = self.txt_key.text().strip()
        self.settings["rea_bin"] = self.txt_bin.text().strip()
        self.settings["context_char_limit"] = self.spin_context.value()
        self.settings["response_token_limit"] = self.spin_response.value()
        save_gui_settings(self.settings)
        self.accept()


# ─────────────────────────────────────────────────────────────────────────────
#  ABOUT DIALOG
# ─────────────────────────────────────────────────────────────────────────────

class AboutDialog(QDialog):
    """About dialog highlighting MakuluLinux Rea branding, upstream attribution, and links."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("About MakuluLinux Rea")
        self.setFixedWidth(540)
        self.setStyleSheet(LIGHT_THEME_QSS)
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(14)
        layout.setContentsMargins(24, 24, 24, 24)

        # Header with Logo & Titles
        h_header = QHBoxLayout()
        h_header.setSpacing(14)

        if ICON_PATH and os.path.isfile(ICON_PATH):
            lbl_icon = QLabel()
            pix = QPixmap(ICON_PATH)
            if not pix.isNull():
                lbl_icon.setPixmap(pix.scaled(56, 56, Qt.KeepAspectRatio, Qt.SmoothTransformation))
                h_header.addWidget(lbl_icon)

        v_titles = QVBoxLayout()
        v_titles.setSpacing(2)

        lbl_app_name = QLabel("MakuluLinux Rea")
        lbl_app_name.setStyleSheet("font-size: 22px; font-weight: 800; color: #1E293B;")
        v_titles.addWidget(lbl_app_name)

        lbl_fork = QLabel("forked from morluto/rea • Engine v6.7.0")
        lbl_fork.setStyleSheet("font-size: 12px; font-style: italic; color: #64748B; font-weight: 500;")
        v_titles.addWidget(lbl_fork)

        h_header.addLayout(v_titles)
        h_header.addStretch()
        layout.addLayout(h_header)

        # Divider
        line = QFrame()
        line.setFrameShape(QFrame.HLine)
        line.setFrameShadow(QFrame.Sunken)
        line.setStyleSheet("color: #E2E8F0;")
        layout.addWidget(line)

        # Description
        lbl_desc = QLabel(
            "<b>MakuluLinux Rea (Reverse Engineer Anything)</b> is an intelligent, multi-engine "
            "reverse engineering studio powered by Electra AI Center.<br><br>"
            "Inspect native ELF, PE, Mach-O binaries, Go/Rust runtimes, Unity IL2CPP games, "
            "AI models, GPU code objects, Android APKs, WebAssembly, and bytecode. Disassemble with objdump "
            "and radare2, decompile functions with Ghidra & RetDec, analyze byte entropy, audit security mitigations, "
            "and interact with the real-time Electra AI Copilot."
        )
        lbl_desc.setWordWrap(True)
        lbl_desc.setStyleSheet("font-size: 13px; color: #334155; line-height: 1.5;")
        layout.addWidget(lbl_desc)

        # Links Card
        grp_links = QFrame()
        grp_links.setProperty("class", "card")
        grp_links.setStyleSheet(
            "background-color: #F8FAFC; border: 1px solid #CBD5E1; border-radius: 8px; padding: 14px;"
        )
        v_links = QVBoxLayout(grp_links)
        v_links.setSpacing(10)

        # Website
        lbl_web = QLabel(
            "<b>Website:</b> <a href='https://makululinux.com' style='color: #2563EB; font-weight: 600; text-decoration: none;'>https://makululinux.com</a>"
        )
        lbl_web.setOpenExternalLinks(True)
        lbl_web.setTextInteractionFlags(Qt.TextBrowserInteraction)
        v_links.addWidget(lbl_web)

        # Patreon
        lbl_patreon = QLabel(
            "<b>Patreon:</b> <a href='https://www.patreon.com/makululinux' style='color: #2563EB; font-weight: 600; text-decoration: none;'>https://www.patreon.com/makululinux</a>"
        )
        lbl_patreon.setOpenExternalLinks(True)
        lbl_patreon.setTextInteractionFlags(Qt.TextBrowserInteraction)
        v_links.addWidget(lbl_patreon)

        # Discord
        lbl_discord = QLabel(
            "<b>Discord:</b> <a href='https://discord.gg/UerQvq2hTm' style='color: #2563EB; font-weight: 600; text-decoration: none;'>https://discord.gg/UerQvq2hTm</a>"
        )
        lbl_discord.setOpenExternalLinks(True)
        lbl_discord.setTextInteractionFlags(Qt.TextBrowserInteraction)
        v_links.addWidget(lbl_discord)

        layout.addWidget(grp_links)

        # Dialog Buttons
        btn_box = QHBoxLayout()
        btn_box.addStretch()

        btn_close = QPushButton("Close")
        btn_close.setObjectName("btn_close_about")
        btn_close.setProperty("class", "primary")
        btn_close.setFixedWidth(90)
        btn_close.clicked.connect(self.accept)
        btn_box.addWidget(btn_close)

        layout.addLayout(btn_box)


# ─────────────────────────────────────────────────────────────────────────────
#  REA SUBCOMMANDS CATALOG & CUSTOM COMMAND DIALOG
# ─────────────────────────────────────────────────────────────────────────────

# The installed CLI's --help is the authority; this is only menu organization.
REA_COMMAND_GROUPS = {
    "Binary Analysis": ("inspect-with-objdump", "inspect-binary-layout", "instructions", "read-bytes", "search-bytes", "search", "xrefs"),
    "Native Formats": ("inspect-pe-resources", "inspect-macho", "inspect-signature", "demangle-swift"),
    "Languages & Runtimes": ("inspect-go-binary", "inspect-rust-binary", "inspect-managed-artifact", "inspect-wasm-artifact", "analyze-javascript-application"),
    "Android & Mobile": ("inspect-android-package", "decode-android-resources", "search-android-classes", "project-android-application-graph", "list-adb-devices", "list-adb-packages", "read-adb-logcat", "install-adb-package", "pull-adb-package", "start-adb-app"),
    "Web & Electron": ("list-browser-targets", "list-electron-targets", "inspect-web-page", "inspect-web-network-capture", "recover-javascript-sources"),
    "Frida": ("list-frida-devices", "list-frida-processes", "instrument-with-frida"),
}


class CustomCommandDialog(QDialog):
    """Only offer installed commands and show their actual CLI usage before execution."""
    def __init__(self, parent=None, target_path="", command=""):
        super().__init__(parent)
        self.setWindowTitle("Run REA Command")
        self.resize(760, 620)
        self.setStyleSheet(LIGHT_THEME_QSS)
        self.target_path = target_path
        self.catalog = dict(getattr(parent, "command_catalog", None) or {})
        self.rea_bin = getattr(parent, "settings", {}).get("rea_bin", REA_BIN_PATH)
        self.selected_command = []
        self.help_worker = None
        self.help_command = ""
        layout = QVBoxLayout(self)
        description = QLabel("Kurulu motorun doğrulanmış komutları. Gereken adres, CDP uç noktası, cihaz veya JSON girdisini aşağıdaki gerçek kullanım bilgisine göre girin.")
        description.setWordWrap(True)
        layout.addWidget(description)
        self.combo_cmd = QComboBox()
        self.combo_cmd.setMinimumContentsLength(42)
        self.combo_cmd.setSizeAdjustPolicy(QComboBox.AdjustToMinimumContentsLengthWithIcon)
        for name, desc in sorted(self.catalog.items()):
            self.combo_cmd.addItem(name + " — " + desc, name)
        if command in self.catalog:
            self.combo_cmd.setCurrentIndex(self.combo_cmd.findData(command))
        layout.addWidget(self.combo_cmd)
        self.help_view = QPlainTextEdit()
        self.help_view.setReadOnly(True)
        layout.addWidget(self.help_view)
        layout.addWidget(QLabel("Arguments & Target Options:"))
        self.txt_args = QLineEdit()
        self.txt_args.setPlaceholderText("Motorun Usage / Arguments / Options bilgisine göre parametreleri girin")
        layout.addWidget(self.txt_args)
        options = QHBoxLayout()
        options.addWidget(QLabel("Output Format:"))
        self.combo_fmt = QComboBox()
        self.combo_fmt.addItems(["(default)", "json", "toon", "yaml", "md", "jsonl"])
        options.addWidget(self.combo_fmt)
        self.chk_full = QCheckBox("Full envelope (--full-output)")
        options.addWidget(self.chk_full)
        layout.addLayout(options)
        buttons = QHBoxLayout()
        cancel = QPushButton("Cancel")
        cancel.clicked.connect(self.reject)
        buttons.addWidget(cancel)
        self.btn_run = QPushButton("Execute Command")
        self.btn_run.setObjectName("btn_run_cmd")
        self.btn_run.setProperty("class", "primary")
        self.btn_run.clicked.connect(self._on_run)
        buttons.addWidget(self.btn_run)
        layout.addLayout(buttons)
        self.combo_cmd.currentIndexChanged.connect(self._load_help)
        self._load_help()

    def _load_help(self, *args):
        if self.help_worker and self.help_worker.isRunning():
            self.help_worker.cancel()
            self.help_worker.wait(1500)
        self.help_command = ""
        self.txt_args.clear()
        self.txt_args.setModified(False)
        self.btn_run.setEnabled(False)
        command = self.combo_cmd.currentData()
        if command not in self.catalog:
            self.help_view.setPlainText("Komut kataloğu henüz alınamadı.")
            return
        self.help_view.setPlainText("Motorun kullanım bilgisi alınıyor…")
        self.help_worker = ToolExecutionWorker(command, [self.rea_bin, command, "--help"], timeout=8, stdout_limit=128*1024)
        self.help_worker.completed.connect(self._help_ready)
        self.help_worker.failed.connect(self._help_failed)
        self.help_worker.start()

    def _help_ready(self, command, text):
        if self.sender() is not self.help_worker or command != self.combo_cmd.currentData():
            return
        import re, shlex
        usage = re.search(r"^Usage: rea " + re.escape(command) + r"(?: (.*))?$", text, re.MULTILINE)
        if not usage:
            self._help_failed(command, "Motor geçerli bir Usage satırı bildirmedi.")
            return
        self.help_command = command
        self.help_view.setPlainText(text)
        # Never put a file path into an endpoint/device/workflow-json argument.
        if not self.txt_args.isModified() and self.target_path and (usage.group(1) or "").startswith("<path>"):
            self.txt_args.setText(shlex.quote(self.target_path))
            self.txt_args.setModified(False)
        self.btn_run.setEnabled(True)

    def _help_failed(self, command, error):
        if self.sender() is self.help_worker and command == self.combo_cmd.currentData():
            self.help_view.setPlainText("Kullanım bilgisi alınamadı: " + error)
            self.btn_run.setEnabled(False)

    def _on_run(self):
        command = self.combo_cmd.currentData()
        if command not in self.catalog or self.help_command != command:
            return
        import shlex
        try:
            extra = shlex.split(self.txt_args.text().strip())
        except ValueError as exc:
            QMessageBox.warning(self, "Geçersiz parametre", str(exc))
            return
        self.selected_command = [command] + extra
        if self.combo_fmt.currentText() != "(default)":
            self.selected_command += ["--format", self.combo_fmt.currentText()]
        if self.chk_full.isChecked():
            self.selected_command.append("--full-output")
        self.accept()

    def done(self, result):
        if self.help_worker and self.help_worker.isRunning():
            self.help_worker.cancel()
            self.help_worker.wait(1500)
        super().done(result)


# ─────────────────────────────────────────────────────────────────────────────
#  MAIN WINDOW
# ─────────────────────────────────────────────────────────────────────────────

class BookmarkEditDialog(QDialog):
    def __init__(self, parent, title="", note=""):
        super().__init__(parent)
        self.setWindowTitle("Yer imi ve not")
        self.resize(520, 360)
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("Başlık / fonksiyon adı:"))
        self.txt_title = QLineEdit(title)
        self.txt_title.setMaxLength(200)
        layout.addWidget(self.txt_title)
        layout.addWidget(QLabel("Not:"))
        self.txt_note = QPlainTextEdit(note)
        layout.addWidget(self.txt_note)
        buttons = QHBoxLayout()
        cancel = QPushButton("İptal")
        cancel.clicked.connect(self.reject)
        save = QPushButton("Kaydet")
        save.clicked.connect(self._save)
        buttons.addWidget(cancel)
        buttons.addWidget(save)
        layout.addLayout(buttons)

    def _save(self):
        if not self.txt_title.text().strip():
            QMessageBox.warning(self, "Başlık gerekli", "Yer imi için bir başlık girin.")
            return
        if len(self.txt_note.toPlainText()) > 100000:
            QMessageBox.warning(self, "Not çok uzun", "Not 100.000 karakteri aşamaz.")
            return
        self.accept()


class NotesBookmarksDialog(QDialog):
    def __init__(self, window):
        super().__init__(window)
        self.window = window
        self.setWindowTitle("Notlar ve yer imleri")
        self.resize(700, 650)
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("Oturum notları (otomatik kayda dahil):"))
        self.notes = QPlainTextEdit(window.session_notes)
        self.notes.setMaximumHeight(150)
        self.notes.textChanged.connect(self._notes_changed)
        layout.addWidget(self.notes)
        layout.addWidget(QLabel("Yer imleri — çift tıklayarak işaretli yere git:"))
        self.items = QListWidget()
        self.items.currentRowChanged.connect(self._show_item)
        self.items.itemDoubleClicked.connect(lambda item: self._go())
        layout.addWidget(self.items)
        self.details = QPlainTextEdit()
        self.details.setReadOnly(True)
        layout.addWidget(self.details)
        buttons = QHBoxLayout()
        for attr, label, callback in (("btn_go", "İşaretli yere git", self._go),
                                      ("btn_edit", "Düzenle", self._edit),
                                      ("btn_delete", "Sil", self._delete),
                                      ("btn_close", "Kapat", self.accept)):
            button = QPushButton(label)
            button.clicked.connect(callback)
            setattr(self, attr, button)
            buttons.addWidget(button)
        layout.addLayout(buttons)
        self.finished.connect(lambda result: window._autosave_session())
        self.refresh()

    def _notes_changed(self):
        text = self.notes.toPlainText()
        if len(text) <= 1000000:
            self.window.session_notes = text
        else:
            self.notes.blockSignals(True)
            self.notes.setPlainText(self.window.session_notes)
            self.notes.blockSignals(False)
            QMessageBox.warning(self, "Not çok uzun", "Oturum notları 1.000.000 karakteri aşamaz.")

    def refresh(self, row=0):
        self.items.clear()
        for item in self.window.bookmarks:
            target = os.path.basename(item["target_path"]) or "Dosyasız"
            self.items.addItem(f"{item['title']}  [{target} · {item['pane']}:{item['first_line']}]")
        self.items.setCurrentRow(min(row, self.items.count() - 1))
        self._show_item(self.items.currentRow())
        self.window.btn_notes_bookmarks.setText(f"Notlar / yer imleri ({len(self.window.bookmarks)})")

    def _show_item(self, row):
        valid = 0 <= row < len(self.window.bookmarks)
        for button in (self.btn_go, self.btn_edit, self.btn_delete):
            button.setEnabled(valid)
        if valid:
            item = self.window.bookmarks[row]
            self.details.setPlainText(item["note"] + "\n\nSeçili kod:\n" + item["quote"])
        else:
            self.details.clear()

    def _go(self):
        row = self.items.currentRow()
        if row >= 0 and self.window._go_to_bookmark(self.window.bookmarks[row]):
            self.accept()

    def _edit(self):
        row = self.items.currentRow()
        if row >= 0:
            self.window._edit_bookmark(self.window.bookmarks[row])
            self.refresh(row)

    def _delete(self):
        row = self.items.currentRow()
        if row < 0:
            return
        if QMessageBox.question(self, "Yer imini sil", "Seçili yer imi ve notu silinsin mi?", QMessageBox.Yes | QMessageBox.No, QMessageBox.No) == QMessageBox.Yes:
            del self.window.bookmarks[row]
            self.window._autosave_session()
            self.refresh(row)


class ReaMainWindow(QMainWindow):
    """Primary Window for REA Reverse Engineering GUI."""

    def __init__(self, target_file: Optional[str] = None):
        super().__init__()
        self.setWindowTitle("MakuluLinux Rea — Reverse Engineering Anything (Electra AI)")
        self.resize(1280, 840)
        self.setMinimumSize(960, 640)
        self.setStyleSheet(LIGHT_THEME_QSS)

        if os.path.isfile(ICON_PATH):
            self.setWindowIcon(QIcon(ICON_PATH))

        # State
        from rea_analysis_session import AnalysisSessionPool
        self.analysis_sessions=AnalysisSessionPool()
        self.settings = load_gui_settings()
        provider = self.settings.get("provider") or ("ollama" if ":11434" in self.settings.get("server_base", "") else "lmstudio")
        self.settings["provider"] = provider
        self.settings.setdefault("providers", {})
        self.settings["providers"].setdefault(provider, {
            "server_base": self.settings.get("server_base", "http://127.0.0.1:1234"),
            "api_key": self.settings.get("api_key", ""),
            "model": self.settings.get("model", "")})
        self._session_target_signature = None
        self._target_generation = 0
        self._code_exports = {}
        self.target_path = target_file or ""
        self.current_worker: Optional[ToolExecutionWorker] = None
        self.ai_worker: Optional[ElectraAiChatWorker] = None
        self.chat_history: List[Dict[str, str]] = []
        self.session_notes = ""
        self.bookmarks = []
        self.mcp_runs = []

        self._closing = False
        self.command_catalog = None
        self.catalog_worker = None
        self.model_control_worker = None
        from rea_chatgpt import ChatGPTStore
        self.cloud_store = ChatGPTStore()
        self.cloud_worker = None
        self._loading_session = False
        self._model_load_configs = {}
        self.model_worker = None
        self._model_memory = {}
        self._memory_error = ""
        self.session_path = ""
        self._init_ui()
        self._sync_cloud_ui()
        self._install_selection_menus()
        self._install_analysis_search()
        QTimer.singleShot(0, self._refresh_models)
        QTimer.singleShot(0, self._refresh_command_catalog)
        self.autosave_timer = QTimer(self)
        self.autosave_timer.setInterval(30000)
        self.autosave_timer.timeout.connect(self._autosave_session)
        self.autosave_timer.start()
        self.memory_timer = QTimer(self)
        self.memory_timer.setInterval(15000)
        self.memory_timer.timeout.connect(self._poll_model_memory)
        self.memory_timer.start()
        self._request_started = None
        self.response_timer = QTimer(self)
        self.response_timer.setInterval(100)
        self.response_timer.timeout.connect(self._update_live_response_time)

        # Keyboard Shortcut: Ctrl+O to browse binary
        self.shortcut_open = QShortcut(QKeySequence("Ctrl+O"), self)
        self.shortcut_open.activated.connect(self._browse_target_file)
        self.shortcut_save_session = QShortcut(QKeySequence("Ctrl+S"), self)
        self.shortcut_save_session.activated.connect(self._save_session_dialog)

        # If binary supplied on CLI or drag/drop, inspect it immediately
        if self.target_path and os.path.isfile(self.target_path):
            self.set_target_file(self.target_path)
            QTimer.singleShot(400, self.action_inspect_headers)

    # ─────────────────────────────────────────────────────────────────────────
    #  UI CONSTRUCTION
    # ─────────────────────────────────────────────────────────────────────────

    def _init_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # 1. Header Bar
        main_layout.addWidget(self._create_header_bar())

        # 2. Prominent Target Selection Bar (with Browse button & input)
        main_layout.addWidget(self._create_target_bar())

        # 3. Main Splitter (Left: Analysis Tabs + Log Box, Right: Electra AI Copilot)
        self.main_splitter = QSplitter(Qt.Horizontal)
        self.main_splitter.setHandleWidth(4)

        # Left Column: Tabs & Live Log Box in vertical splitter
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        left_layout.setContentsMargins(12, 12, 6, 12)
        left_layout.setSpacing(10)

        self.left_splitter = QSplitter(Qt.Vertical)
        self.left_splitter.setHandleWidth(4)

        # Analysis Tabs Widget
        self.analysis_tabs = self._create_analysis_tabs()
        self.left_splitter.addWidget(self.analysis_tabs)

        # Live Real-time Log Console Widget
        self.log_console = self._create_log_console()
        self.left_splitter.addWidget(self.log_console)

        # Initial vertical split (65% tabs, 35% logs)
        self.left_splitter.setSizes([480, 240])
        left_layout.addWidget(self.left_splitter)

        self.main_splitter.addWidget(left_widget)

        # Right Column: Electra AI Copilot Panel
        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)
        right_layout.setContentsMargins(6, 12, 12, 12)
        right_layout.setSpacing(0)

        self.ai_panel = self._create_ai_panel()
        right_layout.addWidget(self.ai_panel)

        self.main_splitter.addWidget(right_widget)

        # Initial horizontal split (62% analysis & logs, 38% AI copilot)
        self.main_splitter.setSizes([780, 500])
        main_layout.addWidget(self.main_splitter, 1)

        # Enable Drag and Drop
        self.setAcceptDrops(True)

    def _create_header_bar(self) -> QWidget:
        header = QFrame()
        header.setObjectName("HeaderFrame")
        layout = QHBoxLayout(header)
        layout.setContentsMargins(16, 10, 16, 10)
        layout.setSpacing(14)

        # Logo / Title
        v_title = QVBoxLayout()
        v_title.setSpacing(2)

        h_title = QHBoxLayout()
        h_title.setSpacing(8)
        lbl_title = QLabel("MakuluLinux Rea")
        lbl_title.setObjectName("AppTitle")
        badge = QLabel("ELECTRA AI")
        badge.setObjectName("BadgePill")
        h_title.addWidget(lbl_title)
        h_title.addWidget(badge)
        h_title.addStretch()

        lbl_sub = QLabel("forked from morluto/rea • Reverse Engineering Anything")
        lbl_sub.setObjectName("AppSubtitle")
        lbl_sub.setStyleSheet("font-size: 11px; font-style: italic; color: #64748B; font-weight: 500;")

        v_title.addLayout(h_title)
        v_title.addWidget(lbl_sub)
        layout.addLayout(v_title)

        layout.addStretch()

        # Model Selector Dropdown (Defaults to Electra Nano)
        self.combo_provider = QComboBox()
        self.combo_provider.addItem("LM Studio", "lmstudio")
        self.combo_provider.addItem("Ollama", "ollama")
        self.combo_provider.addItem("Bulut · ChatGPT planı", "chatgpt")
        self.combo_provider.setCurrentIndex(self.combo_provider.findData(self.settings["provider"]))
        self.combo_provider.currentIndexChanged.connect(self._on_provider_changed)
        layout.addWidget(self.combo_provider)
        lbl_model = QLabel("Model:")
        lbl_model.setStyleSheet("font-weight: 600; color: #475569;")
        layout.addWidget(lbl_model)

        self.combo_model = QComboBox()
        self.combo_model.setFixedWidth(230)
        self.combo_model.view().setMinimumWidth(560)
        current_model = self.settings.get("model", "")
        if current_model:
            self.combo_model.addItem(current_model, current_model)
        self.combo_model.currentIndexChanged.connect(self._on_model_changed)
        layout.addWidget(self.combo_model)
        self.btn_refresh_models = QPushButton("Modelleri yenile")
        self.btn_refresh_models.setMinimumWidth(160)
        self.btn_refresh_models.setToolTip("Model listesini yapılandırılmış sunucudan al")
        self.btn_refresh_models.clicked.connect(self._refresh_models)
        layout.addWidget(self.btn_refresh_models)

        # Settings Button
        btn_settings = QPushButton("Settings")
        btn_settings.clicked.connect(self._open_settings)
        layout.addWidget(btn_settings)

        # About Button
        btn_about = QPushButton("About")
        btn_about.clicked.connect(self._open_about)
        layout.addWidget(btn_about)

        return header

    def _create_target_bar(self) -> QWidget:
        """Prominent Target Selection Bar with Browse button, path input, clear button, and format pills."""
        container = QFrame()
        container.setStyleSheet("background-color: #FFFFFF; border-bottom: 1px solid #E2E8F0; padding: 6px 16px;")
        layout = QHBoxLayout(container)
        layout.setContentsMargins(16, 6, 16, 6)
        layout.setSpacing(10)

        # Prominent Browse Button
        self.btn_browse = QPushButton("Browse Binary... (Ctrl+O)")
        self.btn_browse.setObjectName("btn_browse")
        self.btn_browse.setProperty("class", "primary")
        self.btn_browse.setCursor(QCursor(Qt.PointingHandCursor))
        self.btn_browse.setToolTip("Click to browse and open any binary or executable file on your computer")
        self.btn_browse.clicked.connect(self._browse_target_file)
        layout.addWidget(self.btn_browse)

        # Path display and manual input box
        self.txt_target_path = QLineEdit()
        self.txt_target_path.setPlaceholderText("No binary selected — click Browse Binary... or drag & drop file here")
        self.txt_target_path.setStyleSheet("font-weight: 500; color: #1E293B; padding: 6px 10px;")
        self.txt_target_path.returnPressed.connect(self._on_target_path_entered)
        layout.addWidget(self.txt_target_path, 1)

        # Clear Button
        self.btn_clear_target = QPushButton("Clear")
        self.btn_clear_target.setFixedHeight(30)
        self.btn_clear_target.setToolTip("Unload current binary")
        self.btn_clear_target.clicked.connect(self.clear_target_file)
        layout.addWidget(self.btn_clear_target)

        # Target Format Pill
        self.badge_format = QLabel("FORMAT: NONE")
        self.badge_format.setStyleSheet(
            "background-color: #F1F5F9; color: #475569; font-size: 11px; "
            "font-weight: 600; padding: 3px 8px; border-radius: 4px; border: 1px solid #CBD5E1;"
        )
        layout.addWidget(self.badge_format)

        # Target Size Pill
        self.badge_size = QLabel("SIZE: 0 B")
        self.badge_size.setStyleSheet(
            "background-color: #F1F5F9; color: #475569; font-size: 11px; "
            "font-weight: 600; padding: 3px 8px; border-radius: 4px; border: 1px solid #CBD5E1;"
        )
        layout.addWidget(self.badge_size)

        return container

    def _create_analysis_tabs(self) -> QWidget:
        card = QFrame()
        card.setProperty("class", "card")
        layout = QVBoxLayout(card)
        layout.setContentsMargins(1, 1, 1, 1)
        layout.setSpacing(0)

        # Action Buttons Toolbar above tabs
        actions_bar = QWidget()
        actions_bar.setStyleSheet("background-color: #FFFFFF; border-bottom: 1px solid #E2E8F0; padding: 6px 10px;")
        actions_layout = QHBoxLayout(actions_bar)
        actions_layout.setContentsMargins(8, 4, 8, 4)
        actions_layout.setSpacing(6)

        btn_inspect = QPushButton("Inspect Headers")
        btn_inspect.setProperty("class", "action")
        btn_inspect.clicked.connect(self.action_inspect_headers)
        actions_layout.addWidget(btn_inspect)

        btn_disasm = QPushButton("Disassemble")
        btn_disasm.setProperty("class", "action")
        btn_disasm.clicked.connect(self.action_disassemble)
        actions_layout.addWidget(btn_disasm)

        btn_decompile = QPushButton("Decompile (Otomatik)")
        btn_decompile.setProperty("class", "action")
        btn_decompile.clicked.connect(self.action_decompile)
        actions_layout.addWidget(btn_decompile)

        btn_strings = QPushButton("Extract Strings")
        btn_strings.setToolTip("Tüm dosyada 8-bit/UTF-8 ve UTF-16LE/BE stringlerini dosya ofsetleriyle çıkarır.")
        btn_strings.setProperty("class", "action")
        btn_strings.clicked.connect(self.action_strings)
        actions_layout.addWidget(btn_strings)

        btn_audit = QPushButton("Security Audit")
        btn_audit.setToolTip("ELF: NX, RELRO, PIE, canary/FORTIFY sembol kanıtları ve kütüphane bildirimleri. Statik inceleme.")
        btn_audit.setProperty("class", "action")
        btn_audit.clicked.connect(self.action_security_audit)
        actions_layout.addWidget(btn_audit)

        # More Tools Dropdown Menu (Direct categorized access to all specialized REA subcommands)
        btn_more = QPushButton("More Tools ▾")
        btn_more.setProperty("class", "action")
        menu_more = QMenu(self)

        menu_decomp = menu_more.addMenu("Decompilation Engines")
        menu_decomp.addAction("Decompile (Ghidra → RetDec → Radare2)", self.action_decompile)
        menu_decomp.addAction("Decompile with RetDec", self.action_retdec)
        menu_decomp.addAction("Analyze with Radare2", self.action_radare2)
        menu_decomp.addAction("Fonksiyon bul ve analiz et…", self.action_functions)
        menu_decomp.addAction("Analiz önbelleğini temizle", self.action_clear_analysis_cache)
        menu_decomp.addAction("Seçili dosyanın önbelleğini temizle", self.action_clear_target_cache)
        menu_decomp.addAction("Seçili fonksiyonu yeniden analiz et", lambda:self.action_decompile(refresh=True))
        menu_decomp.addAction("Açık analiz oturumunu bırak", self.action_release_analysis_session)
        menu_decomp.addAction("GNU objdump Disassembly", self.action_disassemble)
        self.act_export_code = menu_decomp.addAction("Seçili kodu dışa aktar…", self._export_code_dialog)
        self.act_export_code.setShortcut(QKeySequence("Ctrl+Shift+E"))
        self.addAction(self.act_export_code)
        self.catalog_menu = menu_more.addMenu("Installed REA Tools")
        self.catalog_menu.addAction("Komut listesi alınıyor…").setEnabled(False)
        menu_more.addAction("Refresh REA Command List", self._refresh_command_catalog)
        menu_more.addSeparator()
        act_custom = menu_more.addAction("Run Custom REA Command...")
        act_custom.triggered.connect(self._open_custom_command_dialog)

        btn_more.setMenu(menu_more)
        actions_layout.addWidget(btn_more)

        actions_layout.addStretch()

        btn_auto_ai = QPushButton("Auto-Analyze with Electra")
        btn_auto_ai.setObjectName("btn_auto_ai")
        btn_auto_ai.setProperty("class", "primary")
        btn_auto_ai.clicked.connect(self.action_auto_analyze)
        actions_layout.addWidget(btn_auto_ai)

        layout.addWidget(actions_bar)
        self.lbl_analysis_progress=QLabel("Analiz: hazır")
        self.lbl_analysis_progress.setTextFormat(Qt.PlainText)
        self.lbl_analysis_progress.setWordWrap(True)
        layout.addWidget(self.lbl_analysis_progress)

        # Tab Widget
        self.tabs = QTabWidget()

        # Tab 1: Overview (Stacked Widget: Page 0 = Welcome / Browse Dropzone, Page 1 = Full Overview)
        self.stack_overview = QStackedWidget()

        # Page 0: Welcome / Browse Hero Card
        page_welcome = QWidget()
        v_welcome = QVBoxLayout(page_welcome)
        v_welcome.setAlignment(Qt.AlignCenter)
        v_welcome.setSpacing(14)
        v_welcome.setContentsMargins(40, 40, 40, 40)

        lbl_hero_badge = QLabel("REA")
        lbl_hero_badge.setStyleSheet(
            "font-size: 28px; font-weight: 900; color: #2563EB; "
            "background-color: #EFF6FF; border: 2px solid #BFDBFE; "
            "border-radius: 12px; padding: 6px 22px;"
        )
        lbl_hero_badge.setAlignment(Qt.AlignCenter)
        v_welcome.addWidget(lbl_hero_badge, 0, Qt.AlignCenter)

        lbl_hero_title = QLabel("Select a Binary to Begin Reverse Engineering")
        lbl_hero_title.setStyleSheet("font-size: 20px; font-weight: 700; color: #1E293B;")
        lbl_hero_title.setAlignment(Qt.AlignCenter)
        v_welcome.addWidget(lbl_hero_title)

        lbl_hero_sub = QLabel(
            "Browse your system for any executable, shared library, or binary file (ELF, PE, Mach-O, APK, WASM),\n"
            "or simply drag and drop the file directly onto this window."
        )
        lbl_hero_sub.setStyleSheet("font-size: 13px; color: #64748B; line-height: 1.5;")
        lbl_hero_sub.setAlignment(Qt.AlignCenter)
        v_welcome.addWidget(lbl_hero_sub)

        # Big, Center Browse Button
        btn_hero_browse = QPushButton("Browse & Select Binary File... (Ctrl+O)")
        btn_hero_browse.setObjectName("btn_hero_browse")
        btn_hero_browse.setProperty("class", "primary")
        btn_hero_browse.setCursor(QCursor(Qt.PointingHandCursor))
        btn_hero_browse.setFixedHeight(44)
        btn_hero_browse.setFixedWidth(320)
        btn_hero_browse.setStyleSheet("font-size: 14px; font-weight: 700;")
        btn_hero_browse.clicked.connect(self._browse_target_file)
        v_welcome.addWidget(btn_hero_browse, 0, Qt.AlignCenter)

        # Sample Quick Test Button
        h_samples = QHBoxLayout()
        h_samples.setSpacing(10)
        lbl_try = QLabel("Quick Test:")
        lbl_try.setStyleSheet("color: #94A3B8; font-size: 12px;")
        h_samples.addWidget(lbl_try)

        btn_sample_ls = QPushButton("Load /bin/ls")
        btn_sample_ls.setProperty("class", "chip")
        btn_sample_ls.clicked.connect(lambda: self.set_target_file("/bin/ls") or self.action_inspect_headers())
        h_samples.addWidget(btn_sample_ls)

        btn_sample_bash = QPushButton("Load /bin/bash")
        btn_sample_bash.setProperty("class", "chip")
        btn_sample_bash.clicked.connect(lambda: self.set_target_file("/bin/bash") or self.action_inspect_headers())
        h_samples.addWidget(btn_sample_bash)

        v_welcome.addLayout(h_samples)
        self.stack_overview.addWidget(page_welcome)

        # Page 1: Loaded Overview Viewer
        self.tab_overview = QTextEdit()
        self.tab_overview.setReadOnly(True)
        self.tab_overview.setProperty("class", "code-view")
        self.tab_overview.setPlaceholderText("Binary overview, sections, and hashes will appear here...")
        self.stack_overview.addWidget(self.tab_overview)

        self.tabs.addTab(self.stack_overview, "Overview")

        # Tab 2: Disassembly
        self.tab_disasm = QPlainTextEdit()
        self.tab_disasm.setReadOnly(True)
        self.tab_disasm.setProperty("class", "code-view")
        self.tab_disasm.setPlaceholderText("Disassembly listing (ASM) will appear here...")
        self.tabs.addTab(self.tab_disasm, "Disassembly")

        # Tab 3: Decompiled C
        self.tab_decomp = QPlainTextEdit()
        self.tab_decomp.setReadOnly(True)
        self.tab_decomp.setProperty("class", "code-view")
        self.tab_decomp.setPlaceholderText("Decompiled C pseudocode will appear here...")
        self.tabs.addTab(self.tab_decomp, "Decompiled C")
        for editor in (self.tab_disasm, self.tab_decomp):
            editor.textChanged.connect(lambda editor=editor: self._code_exports.pop(editor, None))

        # Tab 4: Strings & Symbols
        self.tab_strings = QTextEdit()
        self.tab_strings.setReadOnly(True)
        self.tab_strings.setProperty("class", "code-view")
        self.tab_strings.setPlaceholderText("Extracted strings, URLs, and symbols will appear here...")
        self.tabs.addTab(self.tab_strings, "Strings & Symbols")

        # Tab 5: Hex View
        self.tab_hex = QPlainTextEdit()
        self.tab_hex.setReadOnly(True)
        self.tab_hex.setProperty("class", "code-view")
        self.tab_hex.setPlaceholderText("Hexadecimal byte dump will appear here...")
        self.tabs.addTab(self.tab_hex, "Hex View")

        # Tab 6: Tool Output
        self.tab_raw = QPlainTextEdit()
        self.tab_raw.setReadOnly(True)
        self.tab_raw.setProperty("class", "code-view")
        self.tab_raw.setPlaceholderText("Output from extended tools and custom commands will appear here...")
        self.tabs.addTab(self.tab_raw, "Tool Output")

        layout.addWidget(self._create_search_bar())
        layout.addWidget(self.tabs)
        return card

    def _create_search_bar(self):
        self.search_bar = QWidget()
        row = QHBoxLayout(self.search_bar)
        row.setContentsMargins(8, 4, 8, 4)
        row.setSpacing(5)
        row.addWidget(QLabel("Ara:"))
        self.txt_search = QLineEdit()
        self.txt_search.setPlaceholderText("Fonksiyon, adres veya metin…")
        self.txt_search.setClearButtonEnabled(True)
        row.addWidget(self.txt_search, 1)
        self.chk_search_case = QCheckBox("Aa")
        self.chk_search_case.setToolTip("Büyük/küçük harf eşleşsin")
        row.addWidget(self.chk_search_case)
        self.btn_search_previous = QPushButton("↑")
        self.btn_search_previous.setFixedWidth(30)
        self.btn_search_previous.setStyleSheet("padding: 2px; font-size: 16px;")
        self.btn_search_previous.setToolTip("Önceki sonuç (Shift+Enter / Shift+F3)")
        self.btn_search_next = QPushButton("↓")
        self.btn_search_next.setFixedWidth(30)
        self.btn_search_next.setStyleSheet("padding: 2px; font-size: 16px;")
        self.btn_search_next.setToolTip("Sonraki sonuç (Enter / F3)")
        row.addWidget(self.btn_search_previous)
        row.addWidget(self.btn_search_next)
        self.lbl_search_count = QLabel("Aranacak metni yazın")
        self.lbl_search_count.setToolTip("Çok fazla sonuçta sayaç 2000+ gösterir; sonraki/önceki tüm metinde çalışır.")
        row.addWidget(self.lbl_search_count)
        self.btn_functions = QPushButton("Fonksiyonlar…")
        self.btn_functions.setToolTip("Giriş/sembol listesini ad veya adresle filtreleyin; tam envanter değildir.")
        self.btn_functions.clicked.connect(self.action_functions)
        row.addWidget(self.btn_functions)
        close = QPushButton("×")
        close.setFixedWidth(28)
        close.setStyleSheet("padding: 2px; font-size: 16px;")
        close.setToolTip("Aramayı kapat (Esc)")
        close.clicked.connect(self._close_analysis_search)
        row.addWidget(close)
        self.search_timer = QTimer(self)
        self.search_timer.setSingleShot(True)
        self.search_timer.setInterval(180)
        self.search_timer.timeout.connect(self._refresh_analysis_search)
        self._search_matches = []
        self._search_more = False
        self.txt_search.textChanged.connect(self._schedule_analysis_search)
        self.chk_search_case.toggled.connect(self._refresh_analysis_search)
        self.btn_search_next.clicked.connect(lambda: self._navigate_analysis_search(False))
        self.btn_search_previous.clicked.connect(lambda: self._navigate_analysis_search(True))
        self.search_bar.hide()
        return self.search_bar

    def _install_analysis_search(self):
        self.shortcut_find = QShortcut(QKeySequence("Ctrl+F"), self)
        self.shortcut_find.activated.connect(self._open_analysis_search)
        self.shortcut_find_next = QShortcut(QKeySequence("F3"), self)
        self.shortcut_find_next.activated.connect(lambda: self._navigate_analysis_search(False))
        self.shortcut_find_previous = QShortcut(QKeySequence("Shift+F3"), self)
        self.shortcut_find_previous.activated.connect(lambda: self._navigate_analysis_search(True))
        self.txt_search.installEventFilter(self)
        self.tabs.currentChanged.connect(self._refresh_analysis_search)
        for name in SESSION_PANES:
            getattr(self, "tab_" + name).textChanged.connect(self._schedule_analysis_search)

    def _active_search_editor(self):
        return getattr(self, "tab_" + SESSION_PANES[self.tabs.currentIndex()])

    def _open_search_for_pane(self, pane):
        self.tabs.setCurrentIndex(SESSION_PANES.index(pane))
        self._open_analysis_search()

    def _open_analysis_search(self):
        editor = self._active_search_editor()
        text = editor.textCursor().selectedText()
        self.search_bar.show()
        if text.strip() and len(text) <= 200 and "\u2029" not in text and "\n" not in text:
            self.txt_search.setText(text)
        self._refresh_analysis_search()
        self.txt_search.setFocus()
        self.txt_search.selectAll()

    def _close_analysis_search(self):
        self.search_timer.stop()
        self.search_bar.hide()
        self._active_search_editor().setFocus()

    def _schedule_analysis_search(self, *args):
        if not self.search_bar.isHidden():
            self.search_timer.start()

    def _analysis_search_flags(self, backwards=False):
        flags = QTextDocument.FindFlags()
        if self.chk_search_case.isChecked():
            flags |= QTextDocument.FindCaseSensitively
        if backwards:
            flags |= QTextDocument.FindBackward
        return flags

    def _refresh_analysis_search(self, checked=False, select=True):
        if self.search_bar.isHidden():
            return
        self.search_timer.stop()
        self._search_matches = []
        self._search_more = False
        query = self.txt_search.text()
        editor = self._active_search_editor()
        if query:
            position = 0
            while True:
                found = editor.document().find(query, position, self._analysis_search_flags())
                if found.isNull():
                    break
                if len(self._search_matches) == 2000:
                    self._search_more = True
                    break
                self._search_matches.append((found.selectionStart(), found.selectionEnd()))
                position = found.selectionEnd()
        enabled = bool(self._search_matches)
        self.btn_search_previous.setEnabled(enabled)
        self.btn_search_next.setEnabled(enabled)
        if not query:
            self.lbl_search_count.setText("Aranacak metni yazın")
        elif not enabled:
            cursor = editor.textCursor()
            cursor.clearSelection()
            editor.setTextCursor(cursor)
            self.lbl_search_count.setText("Sonuç bulunamadı")
        elif select:
            start = editor.textCursor().selectionStart()
            found = editor.document().find(query, start, self._analysis_search_flags())
            if found.isNull():
                found = editor.document().find(query, 0, self._analysis_search_flags())
            self._select_search_result(found)
        else:
            count = str(len(self._search_matches)) + ("+" if self._search_more else "")
            self.lbl_search_count.setText(count + " sonuç")

    def _select_search_result(self, cursor, wrapped=False, backwards=False):
        if cursor.isNull():
            return
        editor = self._active_search_editor()
        editor.setTextCursor(cursor)
        editor.ensureCursorVisible()
        if self.tabs.currentIndex() == 0:
            self.stack_overview.setCurrentIndex(1)
        positions = [start for start, end in self._search_matches]
        total = str(len(positions)) + ("+" if self._search_more else "")
        number = str(positions.index(cursor.selectionStart()) + 1) if cursor.selectionStart() in positions else "…"
        suffix = (" · Sona dönüldü" if backwards else " · Başa dönüldü") if wrapped else ""
        self.lbl_search_count.setText(number + " / " + total + suffix)

    def _navigate_analysis_search(self, backwards=False):
        if self.search_bar.isHidden():
            self._open_analysis_search()
            return
        self._refresh_analysis_search(select=False)
        if not self._search_matches:
            return
        editor = self._active_search_editor()
        cursor = editor.textCursor()
        position = cursor.selectionStart() if backwards else cursor.selectionEnd()
        found = editor.document().find(self.txt_search.text(), position, self._analysis_search_flags(backwards))
        wrapped = found.isNull()
        if wrapped:
            position = editor.document().characterCount() - 1 if backwards else 0
            found = editor.document().find(self.txt_search.text(), position, self._analysis_search_flags(backwards))
        self._select_search_result(found, wrapped, backwards)

    def _install_selection_menus(self):
        for name in SESSION_PANES:
            editor = getattr(self, "tab_" + name)
            editor.setContextMenuPolicy(Qt.CustomContextMenu)
            editor.customContextMenuRequested.connect(
                lambda point, view=editor, pane=name: self._show_selection_menu(view, pane, point))

    def _selection_details(self, editor):
        cursor = editor.textCursor()
        if not cursor.hasSelection():
            return None
        text = cursor.selectedText().replace("\u2029", "\n").replace("\u2028", "\n")
        if not text.strip():
            return None
        first = editor.document().findBlock(cursor.selectionStart()).blockNumber() + 1
        last = editor.document().findBlock(max(cursor.selectionStart(), cursor.selectionEnd() - 1)).blockNumber() + 1
        return {"text": text, "first_line": first, "last_line": last}

    def _build_selection_menu(self, editor, pane):
        menu = editor.createStandardContextMenu()
        search = menu.addAction("Bu sekmede ara (Ctrl+F)")
        search.setObjectName("analysis_find")
        search.triggered.connect(lambda checked=False: self._open_search_for_pane(pane))
        menu.addSeparator()
        details = self._selection_details(editor)
        enabled = bool(details and self.settings.get("model") and not self._session_busy()
                       and not (self.model_worker and self.model_worker.isRunning()))
        for key, label in (("explain", "Seçili kodu açıkla"),
                           ("to_c", "Seçili kodu C’ye çevir"),
                           ("risks", "Seçili koddaki riskleri incele")):
            action = menu.addAction(label)
            action.setObjectName("selection_" + key)
            action.setEnabled(enabled)
            action.triggered.connect(lambda checked=False, mode=key, captured=details:
                self._send_selection(pane, captured, mode))
        menu.addSeparator()
        bookmark = menu.addAction("Yer imi / not ekle")
        bookmark.setObjectName("bookmark_add")
        bookmark_details = details
        if not bookmark_details:
            cursor = editor.textCursor()
            text = cursor.block().text()
            line = cursor.blockNumber() + 1
            bookmark_details = {"text": text, "first_line": line, "last_line": line} if text.strip() else None
        bookmark.setEnabled(bool(bookmark_details and not self._session_busy()))
        bookmark.triggered.connect(lambda checked=False, captured=bookmark_details: self._add_bookmark(pane, captured))
        if pane in ("decomp", "disasm"):
            menu.addSeparator()
            export = menu.addAction("Seçili kodu dışa aktar…")
            export.setObjectName("export_code")
            saved = self._code_exports.get(editor)
            export.setEnabled(saved is not None and saved[0] == self._analysis_target_context())
            export.triggered.connect(lambda checked=False: self._export_code_dialog(editor))
        return menu

    def _show_selection_menu(self, editor, pane, point):
        menu = self._build_selection_menu(editor, pane)
        try:
            menu.exec_(editor.viewport().mapToGlobal(point))
        finally:
            menu.deleteLater()

    def _send_selection(self, pane, details, mode):
        if not details or not details["text"].strip():
            self.append_log("Önce analiz sekmesinden kod veya metin seçin.", "warn")
            return False
        if self._session_busy():
            self.append_log("Seçili kodu göndermeden önce çalışan isteği veya analizi bitirin.", "warn")
            return False
        instructions = {
            "explain": "Seçili kodun ne yaptığını, veri akışını ve önemli noktalarını Türkçe açıkla.",
            "to_c": "Seçili kodu davranışını koruyarak C diline çevir. Zaten C ise sadeleştirilmiş eşdeğerini ver. Bilinmeyen tür ve bağımlılıkları açıkça belirt.",
            "risks": "Seçili koddaki olası bellek güvenliği, sınır kontrolü ve doğruluk risklerini Türkçe incele. Kanıtlanan bulgularla varsayımları ayır ve düzeltme öner."
        }
        if mode not in instructions:
            return False
        import re
        longest = max([len(run) for run in re.findall(r"`+", details["text"])] or [0])
        fence = "`" * max(3, longest + 1)
        names = {"overview": "Overview", "disasm": "Disassembly", "decomp": "Decompiled C",
                 "strings": "Strings & Symbols", "hex": "Hex View", "raw": "Tool Output"}
        prompt = (instructions[mode] + "\nYalnızca aşağıdaki seçime dayan; seçim dışındaki kod hakkında kesin çıkarım yapma.\n"
                  + f"Kaynak: {names.get(pane, pane)}; satırlar: {details['first_line']}–{details['last_line']}\n"
                  + fence + "text\n" + details["text"] + "\n" + fence)
        # The selected text is the newest user message, so the budget never silently truncates it.
        return self._send_ai_prompt(prompt, selection_only=True)

    def _create_log_console(self) -> QWidget:
        card = QFrame()
        card.setProperty("class", "card")
        layout = QVBoxLayout(card)
        layout.setContentsMargins(1, 1, 1, 1)
        layout.setSpacing(0)

        # Console Header
        console_bar = QWidget()
        console_bar.setStyleSheet("background-color: #F8FAFC; border-bottom: 1px solid #E2E8F0; padding: 4px 10px;")
        bar_layout = QHBoxLayout(console_bar)
        bar_layout.setContentsMargins(8, 4, 8, 4)
        bar_layout.setSpacing(8)

        lbl_log = QLabel("Real-Time Execution Log")
        lbl_log.setStyleSheet("font-weight: 700; color: #475569; font-size: 12px;")
        bar_layout.addWidget(lbl_log)

        self.chk_autoscroll = QCheckBox("Auto-scroll")
        self.chk_autoscroll.setChecked(True)
        self.chk_autoscroll.setStyleSheet("font-size: 11px; color: #64748B;")
        bar_layout.addWidget(self.chk_autoscroll)

        bar_layout.addStretch()

        btn_copy = QPushButton("Copy")
        btn_copy.setFixedHeight(24)
        btn_copy.setStyleSheet("font-size: 11px; padding: 2px 8px;")
        btn_copy.clicked.connect(self._copy_log)
        bar_layout.addWidget(btn_copy)

        btn_clear = QPushButton("Clear")
        btn_clear.setFixedHeight(24)
        btn_clear.setStyleSheet("font-size: 11px; padding: 2px 8px;")
        btn_clear.clicked.connect(self._clear_log)
        bar_layout.addWidget(btn_clear)

        layout.addWidget(console_bar)

        # Log Text Box
        self.txt_log = QTextEdit()
        self.txt_log.setReadOnly(True)
        self.txt_log.setProperty("class", "code-view")
        self.txt_log.setStyleSheet(
            "background-color: #FFFFFF; color: #1E293B; font-family: 'DejaVu Sans Mono', monospace; font-size: 11px;"
        )
        layout.addWidget(self.txt_log)

        return card

    def _create_ai_panel(self) -> QWidget:
        card = QFrame()
        card.setProperty("class", "card")
        layout = QVBoxLayout(card)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        # Copilot Header
        h_copilot = QHBoxLayout()
        h_copilot.setSpacing(6)
        lbl_ai = QLabel("Electra AI Copilot")
        lbl_ai.setStyleSheet("font-size: 14px; font-weight: 700; color: #1E293B;")
        h_copilot.addWidget(lbl_ai)

        self.lbl_ai_status = QLabel("Ready")
        self.lbl_ai_status.setStyleSheet("color: #10B981; font-size: 11px; font-weight: 600;")
        h_copilot.addWidget(self.lbl_ai_status)
        h_copilot.addStretch()

        btn_clear_chat = QPushButton("Clear Chat")
        btn_clear_chat.setFixedHeight(24)
        btn_clear_chat.setStyleSheet("font-size: 11px; padding: 2px 8px;")
        btn_clear_chat.clicked.connect(self._clear_chat)
        h_copilot.addWidget(btn_clear_chat)

        layout.addLayout(h_copilot)

        session_buttons = QHBoxLayout()
        for attr, label, callback in (
                ("btn_save_session", "Kaydet", self._save_session_dialog),
                ("btn_open_session", "Aç", self._open_session_dialog),
                ("btn_export_session", "Dışa aktar", self._export_session_dialog),
                ("btn_resume_session", "Son oturumu aç", self._resume_session)):
            button = QPushButton(label)
            button.clicked.connect(callback)
            setattr(self, attr, button)
            session_buttons.addWidget(button)
        layout.addLayout(session_buttons)
        self.btn_notes_bookmarks = QPushButton("Notlar / yer imleri (0)")
        self.btn_notes_bookmarks.clicked.connect(self._open_notes_bookmarks)
        analysis_utilities = QHBoxLayout()
        analysis_utilities.addWidget(self.btn_notes_bookmarks)
        self.btn_compare_versions = QPushButton("İki dosyayı karşılaştır")
        self.btn_compare_versions.clicked.connect(self._open_version_comparison)
        analysis_utilities.addWidget(self.btn_compare_versions)
        layout.addLayout(analysis_utilities)
        self.btn_tool_status = QPushButton("Analiz araçlarının durumu")
        self.btn_tool_status.clicked.connect(self._open_tool_status)
        tool_controls = QHBoxLayout()
        tool_controls.addWidget(self.btn_tool_status, 1)
        self.btn_stop_analysis = QPushButton("Analizi durdur")
        self.btn_stop_analysis.setEnabled(False)
        self.btn_stop_analysis.clicked.connect(self._stop_running_analysis)
        tool_controls.addWidget(self.btn_stop_analysis)
        layout.addLayout(tool_controls)
        self.cloud_box = QWidget()
        cloud_layout = QVBoxLayout(self.cloud_box)
        cloud_layout.setContentsMargins(0, 0, 0, 0)
        cloud_layout.setSpacing(4)
        self.lbl_cloud = QLabel("ChatGPT hesabına giriş gerekli.")
        self.lbl_cloud.setTextFormat(Qt.PlainText)
        self.lbl_cloud.setWordWrap(True)
        cloud_layout.addWidget(self.lbl_cloud)
        cloud_accounts = QHBoxLayout()
        self.combo_cloud_account = QComboBox()
        self.combo_cloud_account.currentIndexChanged.connect(self._cloud_account_selected)
        cloud_accounts.addWidget(self.combo_cloud_account, 1)
        self.btn_cloud_login = QPushButton("Continue with ChatGPT")
        self.btn_cloud_login.setStyleSheet("background: #111111; color: white; border: 1px solid #111111; padding: 5px 10px;")
        self.btn_cloud_login.clicked.connect(self._cloud_login_button)
        cloud_accounts.addWidget(self.btn_cloud_login)
        cloud_layout.addLayout(cloud_accounts)
        cloud_actions = QHBoxLayout()
        self.btn_cloud_add = QPushButton("Hesap ekle")
        self.btn_cloud_add.clicked.connect(lambda: self._cloud_login(new=True))
        self.btn_cloud_logout = QPushButton("Çıkış yap")
        self.btn_cloud_logout.clicked.connect(self._cloud_logout)
        self.btn_cloud_usage = QPushButton("Kullanımı yönet")
        self.btn_cloud_usage.clicked.connect(lambda: QDesktopServices.openUrl(QUrl("https://chatgpt.com/settings/usage")))
        for button in (self.btn_cloud_add, self.btn_cloud_logout, self.btn_cloud_usage):
            cloud_actions.addWidget(button)
        cloud_layout.addLayout(cloud_actions)
        layout.addWidget(self.cloud_box)
        self.cloud_box.hide()
        memory_controls = QHBoxLayout()
        self.btn_load_model = QPushButton("Seçili modeli yükle")
        self.btn_load_model.setToolTip("Bu sunucudaki yüklü modelleri boşaltır, ardından seçili modeli yükler. Model dosyaları silinmez.")
        self.btn_load_model.clicked.connect(lambda: self._start_model_control("load"))
        self.btn_unload_model = QPushButton("Seçili modeli boşalt")
        self.btn_unload_model.setToolTip("Yalnız seçili modeli bu sunucunun belleğinden çıkarır; dosyasını silmez.")
        self.btn_unload_model.clicked.connect(lambda: self._start_model_control("unload"))
        self.btn_load_model.setEnabled(False)
        self.btn_unload_model.setEnabled(False)
        memory_controls.addWidget(self.btn_load_model)
        memory_controls.addWidget(self.btn_unload_model)
        layout.addLayout(memory_controls)
        self.lbl_model_control = QLabel("Model yönetimi hazır.")
        self.lbl_model_control.setTextFormat(Qt.PlainText)
        self.lbl_model_control.setWordWrap(True)
        layout.addWidget(self.lbl_model_control)
        self.lbl_model_memory = QLabel("Bellek durumu sorgulanıyor…")
        self.lbl_model_memory.setWordWrap(True)
        layout.addWidget(self.lbl_model_memory)
        self.lbl_connection = QLabel("Sunucu: Kontrol ediliyor…")
        self.lbl_response_model = QLabel("Son yanıt modeli: Henüz yanıt yok")
        self.lbl_response_time = QLabel("Yanıt süresi: —")
        for label in (self.lbl_connection, self.lbl_response_model, self.lbl_response_time):
            label.setTextFormat(Qt.PlainText)
            label.setWordWrap(True)
            label.setTextInteractionFlags(Qt.TextSelectableByMouse)
            layout.addWidget(label)

        mcp_controls = QHBoxLayout()
        self.chk_mcp = QCheckBox("MCP ile otonom analiz")
        self.chk_mcp.setChecked(bool(self.settings.get("mcp_enabled", False)))
        self.chk_mcp.setToolTip("Seçili dosyada statik analiz araçlarını Copilot seçer. En fazla 6 model turu, 8 analiz çağrısı ve 300 saniye; en son 12 analiz günlüğü saklanır. Normal sohbet ve seçili kod eylemleri korunur.")
        self.chk_mcp.toggled.connect(self._mcp_mode_changed)
        mcp_controls.addWidget(self.chk_mcp)
        self.btn_mcp_log = QPushButton("MCP araç günlüğü (0)")
        self.btn_mcp_log.clicked.connect(self._show_mcp_log)
        mcp_controls.addWidget(self.btn_mcp_log)
        layout.addLayout(mcp_controls)
        self.lbl_mcp_status = QLabel("MCP modu kapalı; normal sohbet.")
        self.lbl_mcp_status.setTextFormat(Qt.PlainText)
        self.lbl_mcp_status.setWordWrap(True)
        layout.addWidget(self.lbl_mcp_status)

        # Quick Prompt Chips
        chip_layout = QHBoxLayout()
        chip_layout.setSpacing(6)

        chips = [
            ("Explain Binary", "Analyze the target binary and explain its primary purpose and functionality."),
            ("Entropy & Packing", "Analyze whether this binary is packed, compressed, or obfuscated based on byte entropy and anomalous section headers."),
            ("Vulnerability Scan", "Scan the binary's functions and imports for potential security vulnerabilities, unsafe buffer operations, or format string bugs."),
            ("Explain Disasm", "Review the current disassembly and explain the control flow and critical logic."),
            ("Extract Secrets", "Look through extracted strings and symbols for hardcoded secrets, keys, IP addresses, or endpoints.")
        ]

        for label, prompt_text in chips:
            btn_chip = QPushButton(label)
            btn_chip.setProperty("class", "chip")
            btn_chip.clicked.connect(lambda checked, p=prompt_text: self._send_ai_prompt(p))
            chip_layout.addWidget(btn_chip)

        layout.addLayout(chip_layout)

        # Chat History Viewer
        self.chat_view = QTextEdit()
        self.chat_view.setReadOnly(True)
        self.chat_view.setStyleSheet(
            "background-color: #FFFFFF; border: 1px solid #E2E8F0; border-radius: 6px; padding: 8px;"
        )
        self.chat_view.setPlaceholderText(
            "Electra AI Copilot conversation will appear here.\n"
            "Ask questions about the binary, request decompilations, or click a quick action above."
        )
        layout.addWidget(self.chat_view, 1)

        # User Prompt Box & Send Button
        input_container = QWidget()
        input_layout = QHBoxLayout(input_container)
        input_layout.setContentsMargins(0, 0, 0, 0)
        input_layout.setSpacing(8)

        self.txt_prompt = QTextEdit()
        self.txt_prompt.setFixedHeight(56)
        self.txt_prompt.setPlaceholderText("Ask Electra AI about this binary... (Shift+Enter for newline, Enter to send)")
        self.txt_prompt.installEventFilter(self)
        input_layout.addWidget(self.txt_prompt, 1)

        v_btns = QVBoxLayout()
        v_btns.setSpacing(4)
        self.btn_send = QPushButton("Send")
        self.btn_send.setObjectName("btn_send")
        self.btn_send.setProperty("class", "primary")
        self.btn_send.setFixedHeight(28)
        self.btn_send.clicked.connect(self._on_send_clicked)
        v_btns.addWidget(self.btn_send)

        self.btn_stop = QPushButton("Stop")
        self.btn_stop.setFixedHeight(24)
        self.btn_stop.setStyleSheet("font-size: 11px;")
        self.btn_stop.setEnabled(False)
        self.btn_stop.clicked.connect(self._on_stop_clicked)
        v_btns.addWidget(self.btn_stop)

        input_layout.addLayout(v_btns)
        layout.addWidget(input_container)

        return card

    # ─────────────────────────────────────────────────────────────────────────
    #  FILE HANDLING & DRAG-AND-DROP
    # ─────────────────────────────────────────────────────────────────────────

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
        else:
            event.ignore()

    def dropEvent(self, event):
        urls = event.mimeData().urls()
        if urls:
            path = urls[0].toLocalFile()
            if os.path.isfile(path):
                self.set_target_file(path)
                self.action_inspect_headers()

    def _browse_target_file(self):
        start_dir = os.path.dirname(self.target_path) if self.target_path else os.path.expanduser("~")
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Binary or Executable to Reverse Engineer",
            start_dir,
            "Executable / Binary Files (*);;All Files (*)"
        )
        if path and os.path.isfile(path):
            self.set_target_file(path)
            self.action_inspect_headers()

    def _on_target_path_entered(self):
        path = self.txt_target_path.text().strip()
        if path and os.path.isfile(path):
            self.set_target_file(path)
            self.action_inspect_headers()
        elif path:
            QMessageBox.warning(self, "Invalid File", f"File does not exist:\n{path}")

    def clear_target_file(self):
        self._cancel_mcp_for_target_change()
        self._target_generation += 1
        self.target_path = ""
        self._session_target_signature = None
        self.txt_target_path.clear()
        self.badge_format.setText("FORMAT: NONE")
        self.badge_size.setText("SIZE: 0 B")
        self.tab_overview.clear()
        self.tab_disasm.clear()
        self.tab_decomp.clear()
        self.tab_strings.clear()
        self.tab_hex.clear()
        self.stack_overview.setCurrentIndex(0)
        self.append_log("Target cleared.", "info")

    def set_target_file(self, path: str):
        self._cancel_mcp_for_target_change()
        self._target_generation += 1
        self.target_path = os.path.abspath(path)
        try:
            stat = os.stat(self.target_path)
            self._session_target_signature = {"size": stat.st_size, "mtime_ns": stat.st_mtime_ns}
        except OSError:
            self._session_target_signature = None
        self.txt_target_path.setText(self.target_path)

        # Switch Overview stack to Page 1 (Loaded View)
        self.stack_overview.setCurrentIndex(1)

        # Update file size
        try:
            sz = os.path.getsize(self.target_path)
            if sz < 1024:
                size_str = f"{sz} B"
            elif sz < 1024 * 1024:
                size_str = f"{sz / 1024:.1f} KB"
            else:
                size_str = f"{sz / (1024 * 1024):.1f} MB"
            self.badge_size.setText(f"SIZE: {size_str}")
        except Exception:
            self.badge_size.setText("SIZE: N/A")

        # Detect Format & Architecture
        fmt = self._detect_file_format(self.target_path)
        self.badge_format.setText(f"FORMAT: {fmt}")
        self.append_log(f"Loaded target binary: {self.target_path} ({fmt})", "info")

        # Populate Hex View preview
        self._populate_hex_preview(self.target_path)

    def _detect_file_format(self, path: str) -> str:
        try:
            basename = os.path.basename(path).lower()
            if basename == "global-metadata.dat":
                return "Unity IL2CPP Metadata"
            if basename.endswith(".ips"):
                return "Apple IPS Crash Report"
            if basename.endswith(".pyc"):
                return "Python Bytecode (.pyc)"
            if basename.endswith((".onnx", ".gguf", ".safetensors")):
                return "AI Model Artifact"

            with open(path, "rb") as f:
                magic = f.read(16)
                if magic.startswith(b"\x7fELF"):
                    # Check 32 vs 64 bit
                    is_64 = magic[4] == 2
                    return f"ELF {'64-bit' if is_64 else '32-bit'}"
                elif magic.startswith(b"MZ"):
                    return "PE Windows Executable"
                elif magic.startswith((b"\xca\xfe\xba\xbe", b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf")):
                    return "Mach-O Apple Binary"
                elif magic.startswith(b"PK\x03\x04"):
                    if path.endswith(".apk"):
                        return "Android APK"
                    return "ZIP / Archive"
                elif magic.startswith(b"\x00asm"):
                    return "WebAssembly (WASM)"
                elif magic.startswith(b"dex\n"):
                    return "Dalvik Executable (DEX)"
                elif magic.startswith(b"FOR1") and path.endswith(".beam"):
                    return "Erlang BEAM Bytecode"
                elif magic.startswith(b"GGUF"):
                    return "GGUF AI Model"
        except Exception:
            pass
        return "Raw Binary"

    def _populate_hex_preview(self, path: str, max_bytes: int = 4096):
        try:
            with open(path, "rb") as f:
                data = f.read(max_bytes)
                lines = []
                for i in range(0, len(data), 16):
                    chunk = data[i:i+16]
                    hex_part = " ".join(f"{b:02x}" for b in chunk)
                    ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
                    lines.append(f"{i:08x}  {hex_part:<48}  |{ascii_part}|")
                if len(data) == max_bytes:
                    lines.append(f"... (preview limited to first {max_bytes} bytes) ...")
                self.tab_hex.setPlainText("\n".join(lines))
        except Exception as e:
            self.tab_hex.setPlainText(f"Error loading hex preview: {e}")

    # ─────────────────────────────────────────────────────────────────────────
    #  LOG & CHAT OPERATIONS
    # ─────────────────────────────────────────────────────────────────────────

    def append_log(self, text: str, level: str = "info"):
        timestamp = time.strftime("%H:%M:%S")
        color_map = {
            "info": "#2563EB",     # Blue
            "run": "#7C3AED",      # Purple
            "success": "#10B981",  # Green
            "error": "#EF4444",    # Red
            "warn": "#F59E0B",     # Amber
            "ai": "#0D9488"        # Teal
        }
        tag_color = color_map.get(level, "#475569")
        tag_label = level.upper()

        html_line = (
            f"<span style='color: #94A3B8;'>[{timestamp}]</span> "
            f"<span style='color: {tag_color}; font-weight: bold;'>[{tag_label}]</span> "
            f"<span style='color: #1E293B;'>{text}</span><br>"
        )

        cursor = self.txt_log.textCursor()
        cursor.movePosition(QTextCursor.End)
        cursor.insertHtml(html_line)

        if self.chk_autoscroll.isChecked():
            self.txt_log.ensureCursorVisible()

    def _clear_log(self):
        self.txt_log.clear()

    def _copy_log(self):
        QApplication.clipboard().setText(self.txt_log.toPlainText())
        self.append_log("Log copied to clipboard.", "info")

    def _open_tool_status(self):
        from rea_tools import ToolStatusDialog
        dialog = ToolStatusDialog(self, self.settings.get("rea_bin") or REA_BIN_PATH)
        QTimer.singleShot(0, dialog.start)
        dialog.exec_()

    def _open_version_comparison(self):
        from rea_compare import CompareVersionsDialog
        dialog = CompareVersionsDialog(self, self.target_path)
        dialog.exec_()

    def _open_notes_bookmarks(self):
        dialog = NotesBookmarksDialog(self)
        dialog.exec_()

    def _edit_bookmark(self, item):
        dialog = BookmarkEditDialog(self, item["title"], item["note"])
        if dialog.exec_() == QDialog.Accepted:
            item["title"] = dialog.txt_title.text().strip()
            item["note"] = dialog.txt_note.toPlainText()
            self._autosave_session()
            return True
        return False

    def _add_bookmark(self, pane, details):
        if self._session_busy() or not details or not details["text"].strip():
            return False
        if len(self.bookmarks) >= 10000 or len(details["text"]) > 1000000:
            self.append_log("Yer imi sayısı veya seçili metin sınırı aşıldı.", "warn")
            return False
        import uuid
        item = {"id": str(uuid.uuid4()), "title": details["text"].strip().splitlines()[0][:120],
                "note": "", "pane": pane, "target_path": self.target_path,
                "quote": details["text"], "first_line": details["first_line"], "last_line": details["last_line"]}
        dialog = BookmarkEditDialog(self, item["title"])
        if dialog.exec_() != QDialog.Accepted:
            return False
        item["title"] = dialog.txt_title.text().strip()
        item["note"] = dialog.txt_note.toPlainText()
        self.bookmarks.append(item)
        self.btn_notes_bookmarks.setText(f"Notlar / yer imleri ({len(self.bookmarks)})")
        self._autosave_session()
        self.append_log("Yer imi eklendi: " + item["title"], "success")
        return True

    def _go_to_bookmark(self, item):
        if item["target_path"] != self.target_path:
            QMessageBox.information(self, "Farklı hedef", "Yer imi başka bir hedef dosyaya ait. İlgili analiz oturumunu açın.")
            return False
        editor = getattr(self, "tab_" + item["pane"])
        text = editor.toPlainText()
        best = None
        offset = text.find(item["quote"])
        previous = 0
        line = 1
        while offset >= 0:
            line += text.count("\n", previous, offset)
            candidate = (abs(line - item["first_line"]), offset)
            if best is None or candidate < best:
                best = candidate
            previous = offset
            offset = text.find(item["quote"], offset + 1)
        if best is None:
            QMessageBox.information(self, "Kod bulunamadı", "İşaretlenen kod bu analiz çıktısında bulunamadı. Yer imi ve notunuz korunuyor.")
            return False
        _, offset = best
        start = len(text[:offset].encode("utf-16-le")) // 2
        length = len(item["quote"].encode("utf-16-le")) // 2
        cursor = editor.textCursor()
        cursor.setPosition(start)
        cursor.setPosition(start + length, QTextCursor.KeepAnchor)
        editor.setTextCursor(cursor)
        self.tabs.setCurrentIndex(SESSION_PANES.index(item["pane"]))
        if item["pane"] == "overview":
            self.stack_overview.setCurrentIndex(1)
        editor.ensureCursorVisible()
        editor.setFocus()
        return True

    def _session_directory(self):
        os.makedirs(SESSION_DIR, mode=0o700, exist_ok=True)
        return SESSION_DIR

    def _session_busy(self):
        return any(worker and worker.isRunning() for worker in (self.ai_worker, self.current_worker, self.model_control_worker, self.cloud_worker))

    def _session_snapshot(self):
        from datetime import datetime, timezone
        signature = self._session_target_signature
        messages = [dict(message) for message in self.chat_history]
        if getattr(self, "_stream_start", None) is not None and getattr(self, "_stream_text", ""):
            messages.append({"role": "assistant", "content": self._stream_text + "\n\n[Kaydedilirken yanıt devam ediyordu]"})
        from rea_saved_code import text_digest
        code_exports = {}
        for pane in ('decomp', 'disasm'):
            editor = getattr(self, 'tab_' + pane)
            saved = self._code_exports.get(editor)
            if saved is not None and saved[0] == self._analysis_target_context():
                code_exports[pane] = {'view_sha256': text_digest(editor.toPlainText()),
                                      'record': json.loads(json.dumps(saved[1]))}
            elif (getattr(self.current_worker, 'engine', '') == 'restore_code_exports' and
                  self.current_worker.target_context == self._analysis_target_context()):
                pending = self.current_worker.saved.get(pane)
                if pending and pending['view_sha256'] == text_digest(editor.toPlainText()):
                    # Saving pending historical evidence does not authorize exporting it.
                    code_exports[pane] = json.loads(json.dumps(pending))
        return {"format": "makulu-rea-session", "version": 1,
                "saved_at": datetime.now(timezone.utc).isoformat(),
                "target_path": self.target_path, "target_signature": signature,
                "provider": self.settings["provider"], "model": self.settings.get("model", ""),
                "messages": messages, "draft": self.txt_prompt.toPlainText(),
                "mcp_enabled": self.chk_mcp.isChecked(),
                "mcp_runs": json.loads(json.dumps(self.mcp_runs)),
                "code_exports": code_exports,
                "session_notes": self.session_notes, "bookmarks": [dict(item) for item in self.bookmarks],
                "panes": {name: getattr(self, "tab_" + name).toPlainText() for name in SESSION_PANES},
                "active_tab": self.tabs.currentIndex(), "log": self.txt_log.toPlainText(),
                "format_badge": self.badge_format.text(), "size_badge": self.badge_size.text()}

    def _has_session_content(self):
        return bool(self.mcp_runs or self.session_notes or self.bookmarks or self.chat_history or self.target_path or self.txt_prompt.toPlainText() or
                    any(getattr(self, "tab_" + name).toPlainText() for name in SESSION_PANES))

    def _write_session(self, path):
        snapshot = self._session_snapshot()
        serialized = json.dumps(snapshot, ensure_ascii=False, indent=2)
        if len(serialized.encode("utf-8")) > 64 * 1024 * 1024:
            raise ValueError("Oturum 64 MB sınırını aşıyor; büyük analiz çıktısını azaltın.")
        atomic_private_write(path, serialized)

    def _autosave_session(self):
        if not self._has_session_content():
            return
        try:
            self._write_session(os.path.join(self._session_directory(), "recovery.rea.json"))
        except Exception as exc:
            self.append_log("Otomatik oturum kaydı başarısız: " + str(exc), "warn")

    def _save_session_dialog(self):
        default = self.session_path or os.path.join(self._session_directory(), "analiz.rea.json")
        path, _ = QFileDialog.getSaveFileName(self, "Analiz oturumunu kaydet", default, "Rea oturumu (*.rea.json *.json)")
        if not path:
            return
        if not path.lower().endswith(".json"):
            path += ".rea.json"
        try:
            self._write_session(path)
            self.session_path = path
            self.append_log("Oturum kaydedildi: " + path, "success")
        except Exception as exc:
            QMessageBox.warning(self, "Kayıt hatası", str(exc))

    def _load_session(self, path, confirm=True):
        if self._session_busy():
            self.append_log("Oturum açmadan önce çalışan sohbeti veya analizi durdurun.", "warn")
            return False
        # Validate the whole document before modifying any current state.
        try:
            data = read_session(path)
        except Exception as exc:
            QMessageBox.warning(self, "Oturum açılamadı", str(exc))
            return False
        if confirm and self._has_session_content():
            choice = QMessageBox.question(self, "Oturumu aç", "Mevcut sohbet ve analiz görünümü değişecek. Kaydetmediyseniz önce Kaydet’i kullanın. Devam edilsin mi?", QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            if choice != QMessageBox.Yes:
                return False
        provider = data["provider"]
        self.analysis_sessions.clear()
        self._loading_session = True
        try:
            self.combo_provider.setCurrentIndex(self.combo_provider.findData(provider))
        finally:
            self._loading_session = False
        self.settings["model"] = data["model"]
        self.combo_model.blockSignals(True)
        if self.combo_model.findData(data["model"]) < 0 and data["model"]:
            self.combo_model.addItem(data["model"], data["model"])
        self.combo_model.setCurrentIndex(self.combo_model.findData(data["model"]))
        self.combo_model.blockSignals(False)
        self._remember_provider()
        self._reset_request_telemetry()
        self._update_memory_label()
        self._target_generation += 1
        self._session_target_signature = data["target_signature"]
        self.target_path = data["target_path"]
        self.txt_target_path.setText(self.target_path)
        self.badge_format.setText(data["format_badge"])
        self.badge_size.setText(data["size_badge"])
        for name in SESSION_PANES:
            getattr(self, "tab_" + name).setPlainText(data["panes"][name])
        self.stack_overview.setCurrentIndex(1 if self.target_path or data["panes"]["overview"] else 0)
        self.tabs.setCurrentIndex(data["active_tab"])
        self.txt_log.setPlainText(data["log"])
        self.chat_history.clear()
        self.chat_view.clear()
        for message in data["messages"]:
            self.append_chat_message(message["role"], message["content"])
        self.mcp_runs = [dict(run) for run in data.get("mcp_runs", [])]
        self.chk_mcp.blockSignals(True)
        self.chk_mcp.setChecked(data.get("mcp_enabled", False))
        self.chk_mcp.blockSignals(False)
        self.settings["mcp_enabled"] = self.chk_mcp.isChecked()
        self._update_mcp_status()
        self.session_notes = data["session_notes"]
        self.bookmarks = [dict(item) for item in data["bookmarks"]]
        self.btn_notes_bookmarks.setText(f"Notlar / yer imleri ({len(self.bookmarks)})")
        self.txt_prompt.setPlainText(data["draft"])
        self.session_path = path if os.path.basename(path) != "recovery.rea.json" else ""
        self.lbl_ai_status.setText("Ready")
        self.append_log("Oturum açıldı: " + path, "success")
        if self.target_path:
            try:
                stat = os.stat(self.target_path)
                signature = {"size": stat.st_size, "mtime_ns": stat.st_mtime_ns}
                if data["target_signature"] and signature != data["target_signature"]:
                    self.append_log("Hedef dosya değişmiş; ekrandaki analiz kaydedilmiş eski çıktıdır. Yeniden analiz edin.", "warn")
            except OSError:
                self.append_log("Hedef dosya bulunamadı; kayıtlı analizler açıldı. Devam etmek için dosyayı yeniden seçin.", "warn")
        if data['code_exports'] and os.path.isfile(self.target_path):
            from rea_saved_code import SavedCodeVerifier
            self.current_worker = SavedCodeVerifier(self.target_path, data['code_exports'], self)
            self.current_worker.target_context = self._analysis_target_context()
            self.current_worker.analysis_progress.connect(self._on_analysis_progress)
            self.current_worker.completed.connect(self._on_tool_completed)
            self.current_worker.failed.connect(self._on_tool_failed)
            self.current_worker.finished.connect(self._analysis_finished)
            self.btn_stop_analysis.setEnabled(True)
            self.btn_stop_analysis.setText('Doğrulamayı durdur')
            self.append_log('Kayıtlı kodun hedef SHA256 bilgisi arka planda doğrulanıyor; motor yeniden çalıştırılmıyor.', 'info')
            self.current_worker.start()
        return True

    def _open_session_dialog(self):
        path, _ = QFileDialog.getOpenFileName(self, "Analiz oturumunu aç", self._session_directory(), "Rea oturumu (*.rea.json *.json)")
        if path:
            self._load_session(path)

    def _resume_session(self):
        path = os.path.join(self._session_directory(), "recovery.rea.json")
        if not os.path.isfile(path):
            QMessageBox.information(self, "Son oturum", "Henüz otomatik kaydedilmiş bir oturum yok.")
            return
        self._load_session(path)

    def _remember_code_export(self, editor, result, kind):
        from rea_code_export import code_record
        try:
            procedure = getattr(self.sender() or self.current_worker, "procedure", "")
            record = code_record(result, procedure, kind)
            if record['target'] == self.target_path:
                self._code_exports[editor] = (self._analysis_target_context(), record)
        except (ValueError, KeyError, TypeError):
            self._code_exports.pop(editor, None)

    def _export_code_dialog(self, editor=None):
        from rea_code_export import render_code
        if editor not in (self.tab_disasm, self.tab_decomp):
            editor = self.tabs.currentWidget()
        saved = self._code_exports.get(editor)
        if saved is None or saved[0] != self._analysis_target_context():
            self.append_log("Decompiled C veya Disassembly sekmesinde motor bilgisi bulunan güncel bir sonuç seçin. Kayıtlı/eski çıktıyı yeniden analiz edin.", "warn")
            return False
        # Freeze selection and provenance before the native file dialog processes events.
        record = saved[1]
        selection = editor.textCursor().selectedText().replace("\u2029", "\n").replace("\u2028", "\n")
        path, selected_filter = QFileDialog.getSaveFileName(self, "Seçili kodu dışa aktar",
            os.path.join(self._session_directory(), os.path.basename(record['target']) + ".kod.md"),
            "Markdown (*.md);;Metin (*.txt);;JSON (*.json)")
        if not path:
            return False
        extension = os.path.splitext(path)[1].lower()
        if not extension:
            extension = ".json" if "JSON" in selected_filter else ".txt" if "Metin" in selected_filter else ".md"
            path += extension
        try:
            if extension not in (".md", ".txt", ".json"):
                raise ValueError(".md, .txt veya .json uzantısını kullanın.")
            if saved[0] != self._analysis_target_context() or self._code_exports.get(editor) is not saved:
                raise ValueError("Hedef veya analiz sonucu değişti; dışa aktarmayı yeniden başlatın.")
            if os.path.abspath(path) == os.path.abspath(record['target']) or (os.path.exists(path) and os.path.samefile(path, record['target'])):
                raise ValueError("Hedef dosyanın üzerine analiz çıktısı yazılamaz.")
            atomic_private_write(path, render_code(record, selection, extension[1:]))
            self.append_log("Kod ve motor bilgisi dışa aktarıldı: " + path, "success")
            return True
        except Exception as exc:
            QMessageBox.warning(self, "Kod dışa aktarılamadı", str(exc))
            return False

    def _export_session_dialog(self):
        path, selected = QFileDialog.getSaveFileName(self, "Sohbet ve analizi dışa aktar", os.path.join(self._session_directory(), "analiz.md"), "Markdown (*.md);;Metin (*.txt)")
        if not path:
            return
        markdown = not path.lower().endswith(".txt") and "Metin" not in selected
        if not os.path.splitext(path)[1]:
            path += ".md" if markdown else ".txt"
        try:
            atomic_private_write(path, export_session_text(self._session_snapshot(), markdown))
            self.append_log("Dışa aktarıldı: " + path, "success")
        except Exception as exc:
            QMessageBox.warning(self, "Dışa aktarma hatası", str(exc))

    def _clear_chat(self):
        if self.ai_worker and self.ai_worker.isRunning():
            self.append_log("Sohbeti temizlemeden önce yanıtı durdurun.", "warn")
            return
        self.chat_history.clear()
        self.chat_view.clear()
        self.append_log("Chat history cleared.", "info")

    def append_chat_message(self, role: str, content: str):
        self.chat_history.append({"role": role, "content": content})

        if role == "user":
            bg_color = "#EFF6FF"
            border_color = "#BFDBFE"
            sender_name = "You"
            sender_color = "#1D4ED8"
        else:
            bg_color = "#F8FAFC"
            border_color = "#E2E8F0"
            sender_name = "Electra AI"
            sender_color = "#0D9488"

        escaped = content.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        formatted_content = escaped.replace("\n", "<br>")

        # Check for code blocks
        if "```" in content:
            parts = content.split("```")
            out = []
            for i, p in enumerate(parts):
                if i % 2 == 1:
                    code_esc = p.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                    out.append(
                        f"<pre style='background-color: #F1F5F9; border: 1px solid #CBD5E1; padding: 8px; "
                        f"border-radius: 4px; font-family: monospace;'>{code_esc}</pre>"
                    )
                else:
                    out.append(p.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\n", "<br>"))
            formatted_content = "".join(out)

        html = f"""
        <div style='margin-bottom: 12px; background-color: {bg_color}; border: 1px solid {border_color}; border-radius: 6px; padding: 10px;'>
            <div style='font-weight: 700; color: {sender_color}; font-size: 11px; margin-bottom: 4px;'>{sender_name}</div>
            <div style='color: #0F172A; font-size: 12px;'>{formatted_content}</div>
        </div>
        """

        cursor = self.chat_view.textCursor()
        cursor.movePosition(QTextCursor.End)
        if self.chat_view.document().characterCount() > 1:
            cursor.insertBlock()
        cursor.insertHtml(html)
        self.chat_view.ensureCursorVisible()

    # ─────────────────────────────────────────────────────────────────────────
    #  REVERSE ENGINEERING QUICK ACTIONS
    # ─────────────────────────────────────────────────────────────────────────

    def _ensure_target(self) -> bool:
        if not self.target_path or not os.path.isfile(self.target_path):
            QMessageBox.warning(self, "No Target Loaded", "Please browse and select a binary file first.")
            self._browse_target_file()
            return bool(self.target_path and os.path.isfile(self.target_path))
        return True

    def _analysis_target_context(self):
        signature = None
        if self.target_path:
            try:
                stat = os.stat(self.target_path)
                signature = (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns)
            except OSError:
                pass
        return (self._target_generation, self.target_path, signature)

    def _analysis_result_is_current(self):
        # Use the signal sender, not current_worker: an older signal may still be queued.
        context = getattr(self.sender(), "target_context", None)
        if context is not None and context != self._analysis_target_context():
            self.append_log("Hedef değişti; önceki analizin sonucu veya hatası görünüm değiştirilmeden atlandı.", "warn")
            return False
        return True

    def _analysis_finished(self):
        if not self.current_worker or not self.current_worker.isRunning():
            self.btn_stop_analysis.setEnabled(False)
            self.btn_stop_analysis.setText("Analizi durdur")

    def _stop_running_analysis(self):
        if self.current_worker and self.current_worker.isRunning():
            self.current_worker.cancel()
            self.btn_stop_analysis.setEnabled(False)
            self.btn_stop_analysis.setText("Durduruluyor…")

    def _run_tool_command(self, command_id: str, args: List[str]):
        if self.ai_worker and self.ai_worker.isRunning() and getattr(self.ai_worker, "is_mcp", False):
            self.append_log("Önce otonom MCP analizini durdurun veya bitmesini bekleyin.", "warn")
            return
        if self.current_worker and self.current_worker.isRunning():
            self.append_log("Another analysis task is currently running. Please wait...", "warn")
            return

        rea_bin = self.settings.get("rea_bin", REA_BIN_PATH)
        full_args = [rea_bin] + args

        self.current_worker = ToolExecutionWorker(command_id, full_args)
        self.current_worker.target_context = self._analysis_target_context()
        self.current_worker.log_line.connect(self.append_log)
        self.current_worker.completed.connect(self._on_tool_completed)
        self.current_worker.failed.connect(self._on_tool_failed)
        self.current_worker.finished.connect(self._analysis_finished)
        self.btn_stop_analysis.setText("Analizi durdur")
        self.btn_stop_analysis.setEnabled(True)
        self.current_worker.start()

    def _on_tool_completed(self, command_id: str, output: str):
        if not self._analysis_result_is_current():
            return
        self.lbl_analysis_progress.setText("Analiz işlemi tamamlandı: "+command_id)
        if command_id == 'restore_code_exports':
            from rea_saved_code import text_digest
            worker = self.sender()
            result = json.loads(output)
            if worker is not self.current_worker or result['target'] != self.target_path:
                return
            count = 0
            for pane in result['matched']:
                editor = getattr(self, 'tab_' + pane)
                item = worker.saved[pane]
                if item['view_sha256'] == text_digest(editor.toPlainText()):
                    self._code_exports[editor] = (self._analysis_target_context(), item['record'])
                    count += 1
            self.append_log(f'Kayıtlı kod SHA256 doğrulaması: {count} görünüm dışa aktarmaya hazır. Eşleşmeyen sonuçlar için yeniden analiz gerekir.', 'info')
        elif command_id == 'functions':
            from rea_analysis import observation
            from rea_function_picker import FunctionPickerDialog
            try:
                result = json.loads(output)
                if result['target'] != self.target_path:
                    raise ValueError('Hedef değişti.')
                context = self._analysis_target_context()
                dialog = FunctionPickerDialog(observation(result)['observed_result'], self)
                if dialog.exec_() == QDialog.Accepted and dialog.procedure():
                    procedure = dialog.procedure()
                    def selected_analysis():
                        if context == self._analysis_target_context():
                            self.action_decompile(procedure=procedure)
                        else:
                            self.append_log('Hedef değişti; önceki fonksiyon seçimi kullanılmadı.', 'warn')
                    QTimer.singleShot(0, selected_analysis)
                dialog.deleteLater()
            except (ValueError, KeyError, TypeError) as exc:
                self._on_tool_failed(command_id, str(exc))
        elif command_id == "inspect_headers":
            self.stack_overview.setCurrentIndex(1)
            self.tab_overview.setText(output)
            self.tabs.setCurrentIndex(0)
        elif command_id == "disassemble":
            self.tab_disasm.setPlainText(output)
            self.tabs.setCurrentIndex(1)
        elif command_id in ("radare2", "retdec", "adaptive"):
            self.tab_raw.setPlainText(output)
            try:
                from rea_analysis import observation
                result = json.loads(output)
                if result.get("target") != self.target_path:
                    raise ValueError("Hedef dosya değişti.")
                value = observation(result)
                provider = value.get("provider", {})
                engine = value.get("engine") or provider.get("name", "Ghidra")
                observed = value.get("observed_result", value.get("normalized_result"))
                if observed is None:
                    raise ValueError("Motor kullanılabilir sonuç üretmedi.")
                text = observed if isinstance(observed, str) else json.dumps(observed, ensure_ascii=False, indent=2)
                notes = list(value.get("limitations", [])) if value.get("engine") else []
                indicators = result.get("preflight", {}).get("packer_indicators", [])
                if indicators:
                    notes.insert(0, "Paketleyici/koruma işaretleri: " + ", ".join(indicators) +
                        ". Bu kod yalnız yükleyiciye ait olabilir; asıl programın kurtarıldığı anlamına gelmez.")
                if result.get("cache_hit"):
                    notes = ["Önbellek: aynı dosya ve motor ayarları."] + notes
                if result.get("refresh_requested"):
                    notes = ["Önbellek atlanarak yeniden analiz edildi."] + notes
                if value.get("fallback_from"):
                    notes = [str(failure.get("engine", "Motor")) + ": " +
                        str(failure.get("error", "hata")).splitlines()[0][:180]
                        for failure in value["fallback_from"]] + notes
                    notes.append("Alternatif motor kullanıldı; hata ayrıntıları Tool Output sekmesinde.")
                text = "/* " + str(engine) + " — statik analiz; özgün kaynak kod değildir */\n" + "\n".join(notes) + "\n\n" + text
                editor = self.tab_disasm if command_id == "radare2" else self.tab_decomp
                editor.setPlainText(text)
                self._remember_code_export(editor, result, "assembly" if command_id == "radare2" else "pseudocode")
                self.tabs.setCurrentIndex(1 if command_id == "radare2" else 2)
                self.append_log(str(engine) + " işlemi tamamlandı.", "success")
            except (ValueError, KeyError, TypeError) as exc:
                self._on_tool_failed(command_id, "Analiz çıktısı okunamadı: " + str(exc))
        elif command_id == "decompile":
            self.tab_raw.setPlainText(output)
            try:
                payload = json.loads(output)
                if payload.get("ok") is not True:
                    raise ValueError(str(payload.get("error", {}).get("message", "Decompile başarısız.")))
                data = payload["data"]
                code = data.get("normalized_result")
                if isinstance(code, str) and code.strip():
                    provider = data.get("provider", {})
                    self.tab_decomp.setPlainText("/* " + provider.get("name", "Ghidra") + " " + str(provider.get("version") or "")
                        + " — decompiler çıktısı (özgün kaynak kod değildir) */\n" + code)
                else:
                    self.tab_decomp.setPlainText("Bu fonksiyon için decompile kodu üretilemedi. Ayrıntılar Tool Output sekmesinde.")
                    self.append_log("Fonksiyon gövdesi veya decompile sonucu yok; Tool Output ayrıntılarını inceleyin.", "warn")
            except (ValueError, TypeError, KeyError, AttributeError) as exc:
                self.tab_decomp.setPlainText("Decompile çıktısı okunamadı: " + str(exc) + "\n\n" + output)
                self.append_log("Decompile sonucu okunamadı: " + str(exc), "warn")
            self.tabs.setCurrentIndex(2)
        elif command_id in ("strings", "security_audit"):
            try:
                result = json.loads(output)
                if result.get("target") != self.target_path or result.get("engine") != command_id:
                    raise ValueError("Hedef/işlem kimliği uyuşmuyor.")
                report = result["report"]
                if not isinstance(report, str):
                    raise ValueError("Geçersiz rapor.")
                self.tab_raw.setPlainText(output)
                if command_id == "strings":
                    self.tab_strings.setPlainText(report)
                    self.tabs.setCurrentIndex(3)
                else:
                    self.stack_overview.setCurrentIndex(1)
                    self.tab_overview.setPlainText(report)
                    self.tabs.setCurrentIndex(0)
            except (ValueError, KeyError, TypeError) as exc:
                self._on_tool_failed(command_id, "Analiz çıktısı okunamadı: " + str(exc))
        elif command_id == "custom_tool":
            self.tab_raw.setPlainText(output)
            self.tabs.setCurrentWidget(self.tab_raw)
        elif command_id == "auto_analyze":
            self.stack_overview.setCurrentIndex(1)
            self.tab_overview.setText(output)
            self.tabs.setCurrentIndex(0)
            # Feed result to Electra AI
            prompt = (
                f"I have inspected the binary '{os.path.basename(self.target_path)}'.\n"
                f"Here are the header and architecture details:\n\n{output[:3000]}\n\n"
                f"Please provide an executive technical overview of what this binary is, its architecture, "
                f"its likely purpose, and key security implications."
            )
            self._send_ai_prompt(prompt)

    def _on_tool_failed(self, command_id: str, err: str):
        if not self._analysis_result_is_current():
            return
        self.lbl_analysis_progress.setText("Analiz tamamlanamadı: "+command_id)
        if command_id in ("strings", "security_audit"):
            editor = self.tab_strings if command_id == "strings" else self.tab_overview
            editor.setPlainText("İnceleme tamamlanamadı:\n" + err)
            if command_id == "security_audit":
                self.stack_overview.setCurrentIndex(1)
            self.tabs.setCurrentIndex(3 if command_id == "strings" else 0)
        if command_id in ("decompile", "retdec", "adaptive"):
            engine = "Otomatik motor" if command_id == "adaptive" else "Ghidra" if command_id == "decompile" else "RetDec"
            self.tab_decomp.setPlainText(engine + " decompile başarısız:\n" + err)
            self.tabs.setCurrentIndex(2)
        if command_id == "radare2":
            self.tab_disasm.setPlainText("Radare2 analizi başarısız:\n" + err)
            self.tabs.setCurrentIndex(1)
        self.append_log(f"Task '{command_id}' failed: {err}", "error")

    def action_inspect_headers(self):
        if not self._ensure_target():
            return
        self.append_log(f"Inspecting file headers and sections for: {self.target_path}", "run")
        self._run_tool_command("inspect_headers", ["inspect-with-objdump", self.target_path, "file_headers"])

    def action_disassemble(self):
        if not self._ensure_target():
            return
        self.append_log(f"Disassembling {self.target_path}...", "run")
        self._run_tool_command("disassemble", ["inspect-with-objdump", self.target_path, "disassemble"])

    def _start_additional_engine(self, engine):
        if self.ai_worker and self.ai_worker.isRunning() and getattr(self.ai_worker, "is_mcp", False):
            self.append_log("Önce otonom MCP analizini durdurun veya bitmesini bekleyin.", "warn")
            return
        if not self._ensure_target():
            return
        if self.current_worker and self.current_worker.isRunning():
            self.append_log("Başka bir analiz çalışıyor; tamamlanmasını bekleyin.", "warn")
            return
        label = "Radare2 analizi" if engine == "radare2" else "RetDec decompile"
        prompt = "Fonksiyon adı veya 0x adresi (boş: fonksiyon/string envanteri):" if engine == "radare2" else "Fonksiyon adı veya 0x adresi (boş: giriş noktası; seçici analiz):"
        procedure, accepted = QInputDialog.getText(self, label, prompt, QLineEdit.Normal, "main")
        if not accepted:
            return
        from rea_extra_engines import ExtraEngineWorker
        if engine == "radare2":
            self.tab_disasm.setPlainText("Radare2 analiz ediyor…")
            self.tabs.setCurrentIndex(1)
        else:
            self.tab_decomp.setPlainText("RetDec decompile ediyor…")
            self.tabs.setCurrentIndex(2)
        self.current_worker = ExtraEngineWorker(engine, self.target_path, procedure.strip(), self,session_pool=self.analysis_sessions)
        self.current_worker.preflight_ready.connect(self._on_analysis_preflight)
        self.current_worker.analysis_progress.connect(self._on_analysis_progress)
        self.current_worker.target_context = self._analysis_target_context()
        self.current_worker.log_line.connect(self.append_log)
        self.current_worker.completed.connect(self._on_tool_completed)
        self.current_worker.failed.connect(self._on_tool_failed)
        self.current_worker.finished.connect(self._analysis_finished)
        self.btn_stop_analysis.setText("Analizi durdur")
        self.btn_stop_analysis.setEnabled(True)
        self.current_worker.start()

    def action_clear_analysis_cache(self):
        if self._session_busy():
            self.append_log("Önbelleği temizlemeden önce çalışan analizi durdurun veya bitmesini bekleyin.","warn")
            return
        self.analysis_sessions.clear()
        from rehkc_paths import data_dir
        count = 0
        for path in (data_dir() / "analysis-cache").glob("*.json"):
            try:
                path.unlink()
                count += 1
            except OSError:
                pass
        self.append_log(f"Analiz önbelleği temizlendi: {count} kayıt.", "info")

    def _on_analysis_preflight(self, result):
        if not self._analysis_result_is_current() or result.get("target") != self.target_path:
            return
        self.tab_overview.setPlainText("Hızlı dosya ön incelemesi — derin analiz sürerken bu sonuç kullanılabilir.\n\n" +
            json.dumps(result["preflight"], ensure_ascii=False, indent=2))
        self.stack_overview.setCurrentIndex(1)

    def action_clear_target_cache(self):
        if not self.target_path:
            self.append_log("Önce bir hedef dosya seçin.", "warn")
            return
        if self._session_busy():
            self.append_log("Önbelleği temizlemeden önce çalışan analizi durdurun veya bitmesini bekleyin.","warn")
            return
        self.analysis_sessions.clear()
        from rea_analysis import ResultCache
        count=ResultCache.clear_target(self.target_path)
        self.append_log(f"Seçili dosyanın önbelleği temizlendi: {count} kayıt.", "info")

    def action_release_analysis_session(self):
        if self._session_busy():
            self.append_log("Oturumu bırakmadan önce çalışan analizi durdurun veya bitmesini bekleyin.","warn")
            return
        self.analysis_sessions.clear()
        self.append_log("Açık analiz oturumu kapatılıyor; kaydedilmiş sonuç önbelleği korunuyor.","info")

    def _on_analysis_progress(self, progress):
        worker=self.sender()
        if worker not in (self.current_worker,self.ai_worker) or not self._analysis_result_is_current():return
        activity=progress.get("last_activity_seconds")
        note="henüz araç verisi gelmedi" if activity is None else f"son araç verisi {activity:.1f} sn önce"
        text=f"{progress['operation']} · {progress['elapsed']:.1f} sn · {note}"
        if progress.get("total_bytes"):
            text+=f" · taranan %{min(100,100*progress['bytes_read']/progress['total_bytes']):.1f}"
        self.lbl_analysis_progress.setText(text)

    def action_radare2(self):
        self._start_additional_engine("radare2")

    def action_retdec(self):
        self._start_additional_engine("retdec")

    def action_functions(self):
        if self._session_busy():
            self.append_log('Fonksiyon listesini açmadan önce çalışan işlemi bitirin veya durdurun.', 'warn')
            return
        if not self._ensure_target():
            return
        if self._session_busy():
            self.append_log('Hedefin ilk incelemesi bitince fonksiyon listesini açabilirsiniz.', 'info')
            return
        from rea_extra_engines import ExtraEngineWorker
        self.current_worker = ExtraEngineWorker('functions', self.target_path, parent=self,
            rea_bin=self.settings.get('rea_bin', REA_BIN_PATH))
        self.current_worker.target_context = self._analysis_target_context()
        self.current_worker.analysis_progress.connect(self._on_analysis_progress)
        self.current_worker.completed.connect(self._on_tool_completed)
        self.current_worker.failed.connect(self._on_tool_failed)
        self.current_worker.finished.connect(self._analysis_finished)
        self.btn_stop_analysis.setText('Analizi durdur')
        self.btn_stop_analysis.setEnabled(True)
        self.current_worker.start()

    def action_decompile(self, refresh=False, procedure=None):
        if self.ai_worker and self.ai_worker.isRunning() and getattr(self.ai_worker, "is_mcp", False):
            self.append_log("Önce otonom MCP analizini durdurun veya bitmesini bekleyin.", "warn")
            return
        if not self._ensure_target():
            return
        if self.current_worker and self.current_worker.isRunning():
            self.append_log("Başka bir analiz çalışıyor; tamamlanmasını bekleyin.", "warn")
            return
        import re
        selected = self._active_search_editor().textCursor().selectedText().strip()
        default = selected if re.fullmatch(r"(?:0x[0-9a-fA-F]+|[A-Za-z_][\w:.$@]*)", selected) else "main"
        if procedure is None:
            procedure, accepted = QInputDialog.getText(self, "Otomatik motorla decompile",
                "Fonksiyon adı veya adresi (ör. main veya 0x401146):\nSembol adı olmayan dosyada adres kullanın.", QLineEdit.Normal, default)
            if not accepted:
                return
        procedure = procedure.strip()
        if not procedure:
            self.append_log("Bir fonksiyon adı veya adresi girin.", "warn")
            return
        self.append_log(f"Ghidra: {procedure} decompile ediliyor…", "run")
        self.tab_decomp.setPlainText(f"Ghidra {procedure} fonksiyonunu analiz ediyor…")
        self.tabs.setCurrentIndex(2)
        from rea_extra_engines import ExtraEngineWorker
        self.current_worker = ExtraEngineWorker("adaptive", self.target_path, procedure, self,
            rea_bin=self.settings.get("rea_bin", REA_BIN_PATH),refresh=refresh,session_pool=self.analysis_sessions)
        self.current_worker.preflight_ready.connect(self._on_analysis_preflight)
        self.current_worker.analysis_progress.connect(self._on_analysis_progress)
        self.current_worker.target_context = self._analysis_target_context()
        self.current_worker.log_line.connect(self.append_log)
        self.current_worker.completed.connect(self._on_tool_completed)
        self.current_worker.failed.connect(self._on_tool_failed)
        self.current_worker.finished.connect(self._analysis_finished)
        self.btn_stop_analysis.setEnabled(True)
        self.btn_stop_analysis.setText("Analizi durdur")
        self.current_worker.start()

    def _run_static_inspection(self, operation):
        if self.ai_worker and self.ai_worker.isRunning() and getattr(self.ai_worker, "is_mcp", False):
            self.append_log("Önce otonom MCP analizini durdurun veya bitmesini bekleyin.", "warn")
            return
        if not self._ensure_target():
            return
        if self.current_worker and self.current_worker.isRunning():
            self.append_log("Başka bir analiz çalışıyor; tamamlanmasını bekleyin.", "warn")
            return
        from rea_static_tools import StaticInspectionWorker
        self.current_worker = StaticInspectionWorker(operation, self.target_path, parent=self)
        self.current_worker.analysis_progress.connect(self._on_analysis_progress)
        self.current_worker.target_context = self._analysis_target_context()
        self.current_worker.log_line.connect(self.append_log)
        self.current_worker.completed.connect(self._on_tool_completed)
        self.current_worker.failed.connect(self._on_tool_failed)
        self.current_worker.finished.connect(self._analysis_finished)
        self.btn_stop_analysis.setText("Analizi durdur")
        self.btn_stop_analysis.setEnabled(True)
        self.append_log(("String çıkarma" if operation == "strings" else "Statik PE/ELF güvenlik özellikleri") + " başlatılıyor…", "run")
        self.current_worker.start()

    def action_strings(self):
        self._run_static_inspection("strings")

    def action_security_audit(self):
        self._run_static_inspection("security_audit")

    def action_auto_analyze(self):
        if not self._ensure_target():
            return
        self.append_log(f"Initiating automated multi-step analysis for {self.target_path}...", "run")
        self._run_tool_command("auto_analyze", ["inspect-with-objdump", self.target_path, "file_headers"])

    def _refresh_command_catalog(self):
        if self.catalog_worker and self.catalog_worker.isRunning():
            return
        self.command_catalog = None
        self.catalog_menu.clear()
        self.catalog_menu.addAction("Komut listesi alınıyor…").setEnabled(False)
        binary = self.settings.get("rea_bin", REA_BIN_PATH)
        self.catalog_worker = ToolExecutionWorker("catalog", [binary, "--help"], timeout=8, stdout_limit=2*1024*1024)
        self.catalog_worker.catalog_binary = binary
        self.catalog_worker.completed.connect(self._command_catalog_ready)
        self.catalog_worker.failed.connect(self._command_catalog_failed)
        self.catalog_worker.finished.connect(self._command_catalog_finished)
        self.catalog_worker.start()

    def _command_catalog_ready(self, command, text):
        if self.sender() is not self.catalog_worker:
            return
        if self.catalog_worker.catalog_binary != self.settings.get("rea_bin", REA_BIN_PATH):
            return
        from rea_static_tools import parse_command_catalog
        catalog = parse_command_catalog(text)
        if not catalog:
            self._command_catalog_failed(command, "Motor komut listesi bildirmedi.")
            return
        self.command_catalog = catalog
        self.catalog_menu.clear()
        assigned = set()
        for group, names in REA_COMMAND_GROUPS.items():
            available = [name for name in names if name in catalog]
            if not available:
                continue
            menu = self.catalog_menu.addMenu(group)
            for name in available:
                action = menu.addAction(name, lambda checked=False, selected=name: self._run_extended_tool(selected))
                action.setToolTip(catalog[name])
                action.setData(name)
                assigned.add(name)
        others = self.catalog_menu.addMenu("Other Installed Commands")
        for name in sorted(set(catalog) - assigned):
            action = others.addAction(name, lambda checked=False, selected=name: self._run_extended_tool(selected))
            action.setData(name)
            action.setToolTip(catalog[name])
        self.append_log("Kurulu REA komutları doğrulandı: " + str(len(catalog)), "info")

    def _command_catalog_finished(self):
        if self.sender() is self.catalog_worker and self.catalog_worker.catalog_binary != self.settings.get("rea_bin", REA_BIN_PATH):
            self._refresh_command_catalog()

    def _command_catalog_failed(self, command, error):
        if self.sender() is not self.catalog_worker:
            return
        self.command_catalog = None
        self.catalog_menu.clear()
        self.catalog_menu.addAction("Komut listesi alınamadı; Yenile kullanın").setEnabled(False)
        self.append_log("REA komut kataloğu alınamadı: " + error, "warn")

    def _run_extended_tool(self, cmd_name: str, extra_flags=None):
        self._open_custom_command_dialog(cmd_name)

    def _run_global_tool(self, cmd_name: str):
        self._open_custom_command_dialog(cmd_name)

    def _open_custom_command_dialog(self, command=""):
        if not self.command_catalog:
            self.append_log("Önce More Tools → Refresh REA Command List ile motor komutlarını alın.", "warn")
            return
        command = command if isinstance(command, str) else ""
        if command and command not in self.command_catalog:
            self.append_log("Bu komut kurulu motorda bulunmuyor: " + command, "warn")
            return
        dlg = CustomCommandDialog(self, target_path=self.target_path, command=command)
        if dlg.exec_() == QDialog.Accepted and dlg.selected_command:
            self._run_tool_command("custom_tool", dlg.selected_command)

    # ─────────────────────────────────────────────────────────────────────────
    #  ELECTRA AI INTERACTION
    # ─────────────────────────────────────────────────────────────────────────

    def eventFilter(self, obj, event):
        if obj == self.txt_search and event.type() == event.KeyPress:
            if event.key() == Qt.Key_Escape:
                self._close_analysis_search()
                return True
            if event.key() in (Qt.Key_Return, Qt.Key_Enter):
                self._navigate_analysis_search(bool(event.modifiers() & Qt.ShiftModifier))
                return True
        if obj == self.txt_prompt and event.type() == event.KeyPress:
            if event.key() in (Qt.Key_Return, Qt.Key_Enter):
                if not (event.modifiers() & Qt.ShiftModifier):
                    self._on_send_clicked()
                    return True
        return super().eventFilter(obj, event)

    def _cloud_busy(self):
        return bool(self.cloud_worker and self.cloud_worker.isRunning())

    def _cloud_summary(self):
        try:
            return self.cloud_store.summary()
        except Exception:
            return {"active": None, "accounts": [], "error": "ChatGPT hesap kaydı okunamadı; dosya izinlerini kontrol edin."}

    def _sync_cloud_ui(self):
        cloud = self.settings["provider"] == "chatgpt"
        self.cloud_box.setVisible(cloud)
        for widget in (self.btn_load_model, self.btn_unload_model, self.lbl_model_memory, self.lbl_model_control):
            widget.setVisible(not cloud)
        if not cloud:
            return
        summary = self._cloud_summary()
        busy = self._cloud_busy()
        chatting = bool(self.ai_worker and self.ai_worker.isRunning())
        refreshing = bool(self.model_worker and self.model_worker.isRunning())
        self.combo_cloud_account.blockSignals(True)
        self.combo_cloud_account.clear()
        for account in summary["accounts"]:
            self.combo_cloud_account.addItem(account["label"] + " · " + account["registration"], account["id"])
        self.combo_cloud_account.setCurrentIndex(self.combo_cloud_account.findData(summary["active"]))
        self.combo_cloud_account.blockSignals(False)
        active = next((a for a in summary["accounts"] if a["id"] == summary["active"]), {})
        text = "ChatGPT planı kullanılıyor · " + active.get("label", "") if active.get("plan_enabled") else "ChatGPT plan kullanım izni gerekli." if active.get("signed_in") else "ChatGPT hesabına giriş gerekli; API anahtarı gerekmez."
        self.lbl_cloud.setText("Tarayıcıda ChatGPT girişini ve plan iznini tamamlayın…" if busy else summary.get("error") or text)
        self.btn_cloud_login.setText("Girişi durdur" if busy else "Continue with ChatGPT")
        self.btn_cloud_login.setEnabled(busy or not (chatting or refreshing))
        self.combo_cloud_account.setEnabled(not (busy or chatting or refreshing))
        self.btn_cloud_add.setEnabled(not (busy or chatting or refreshing))
        self.btn_cloud_logout.setEnabled(bool(active.get("signed_in")) and not (busy or chatting or refreshing))

    def _cloud_login_button(self):
        if self._cloud_busy():
            self.cloud_worker.cancel()
        else:
            self._cloud_login()

    def _cloud_login(self, new=False):
        if self._cloud_busy():
            return
        if self.settings["provider"] != "chatgpt" or self._session_busy():
            return
        if self.model_worker and self.model_worker.isRunning():
            QTimer.singleShot(150, lambda: self._cloud_login(new=new) if not self._closing and self.settings["provider"] == "chatgpt" else None)
            return
        from rea_chatgpt import ChatGPTAccountWorker
        self.cloud_worker = ChatGPTAccountWorker(self.cloud_store, new=new, parent=self)
        self.cloud_worker.open_browser.connect(self._open_cloud_browser)
        self.cloud_worker.completed.connect(self._cloud_account_completed)
        self.cloud_worker.failed.connect(self._cloud_account_failed)
        self.cloud_worker.finished.connect(self._cloud_account_finished)
        for widget in (self.combo_provider, self.combo_model, self.btn_send, self.btn_refresh_models):
            widget.setEnabled(False)
        self.cloud_worker.start()
        self._sync_cloud_ui()

    def _open_cloud_browser(self, url):
        if self._closing or not QDesktopServices.openUrl(QUrl(url)):
            self.cloud_worker.cancel()
            self.lbl_cloud.setText("Tarayıcı açılamadı; varsayılan tarayıcınızı ayarlayıp tekrar deneyin.")

    def _cloud_logout(self):
        if self._session_busy() or (self.model_worker and self.model_worker.isRunning()):
            return
        from rea_chatgpt import ChatGPTAccountWorker
        self.cloud_worker = ChatGPTAccountWorker(self.cloud_store, operation="logout", parent=self)
        self.cloud_worker.completed.connect(self._cloud_account_completed)
        self.cloud_worker.failed.connect(self._cloud_account_failed)
        self.cloud_worker.finished.connect(self._cloud_account_finished)
        for widget in (self.combo_provider, self.combo_model, self.btn_send, self.btn_refresh_models):
            widget.setEnabled(False)
        self.cloud_worker.start()
        self._sync_cloud_ui()

    def _cloud_account_selected(self):
        if self.settings["provider"] != "chatgpt" or self._session_busy() or (self.model_worker and self.model_worker.isRunning()):
            self._sync_cloud_ui()
            return
        key = self.combo_cloud_account.currentData()
        if key:
            try:
                self.cloud_store.activate(key)
            except Exception:
                self.append_log("ChatGPT hesabı seçilemedi; kayıt izinlerini kontrol edin.", "warn")
                return
            self.settings["model"] = ""
            self.combo_model.clear()
            self._reset_request_telemetry()
            self._sync_cloud_ui()
            self._refresh_models()

    def _cloud_account_completed(self, result):
        if self.sender() is not self.cloud_worker:
            return
        self.combo_model.blockSignals(True)
        self.combo_model.clear()
        self.combo_model.blockSignals(False)
        self.settings["model"] = ""
        self._remember_provider()
        self._reset_request_telemetry()
        self._sync_cloud_ui()
        if result.get("revocation_confirmed") is False:
            self.append_log("Yerel ChatGPT oturumu kapatıldı; sunucudaki iptal doğrulanamadı. ChatGPT ayarlarından uygulamanın erişimini kaldırabilirsiniz.", "warn")
        active = next((a for a in result["accounts"] if a["id"] == result["active"]), {})
        if active.get("plan_enabled") and not active.get("welcomed", False):
            try:
                self.cloud_store.mark_welcomed()
            except Exception:
                self.append_log("ChatGPT karşılama tercihi kaydedilemedi.", "warn")
            QMessageBox.information(self, "ChatGPT planınız kullanılıyor", "Uygun bulut istekleri ChatGPT planınızı kullanacak. Kota ve izinleri Kullanımı yönet düğmesinden kontrol edebilirsiniz. API anahtarı gerekmez.")

    def _cloud_account_failed(self, error):
        if self.sender() is self.cloud_worker:
            self.append_log(error, "warn")
            self.lbl_cloud.setText(error)

    def _cloud_account_finished(self):
        if self.sender() is not self.cloud_worker:
            return
        for widget in (self.combo_provider, self.combo_model, self.btn_send, self.btn_refresh_models):
            widget.setEnabled(True)
        self._sync_cloud_ui()
        self._refresh_models()

    def _remember_provider(self):
        if self.settings["provider"] == "chatgpt":
            self.settings["server_base"] = "https://api.openai.com"
            self.settings["api_key"] = ""
        self.settings["providers"][self.settings["provider"]] = {
            key: self.settings.get(key, "") for key in ("server_base", "api_key", "model")}
        save_gui_settings(self.settings)

    def _on_provider_changed(self):
        if self._cloud_busy():
            self.combo_provider.blockSignals(True)
            self.combo_provider.setCurrentIndex(self.combo_provider.findData(self.settings["provider"]))
            self.combo_provider.blockSignals(False)
            return
        if self._model_control_busy():
            self.combo_provider.blockSignals(True)
            self.combo_provider.setCurrentIndex(self.combo_provider.findData(self.settings["provider"]))
            self.combo_provider.blockSignals(False)
            self.append_log("Model bellek işlemi bitmeden sunucu değiştirilemez.", "warn")
            return
        if self.ai_worker and self.ai_worker.isRunning():
            self.combo_provider.blockSignals(True)
            self.combo_provider.setCurrentIndex(self.combo_provider.findData(self.settings["provider"]))
            self.combo_provider.blockSignals(False)
            self.append_log("Sunucu değiştirmeden önce yanıtın tamamlanmasını bekleyin.", "warn")
            return
        self._remember_provider()
        self._model_memory = {}
        self._memory_error = ""
        self.lbl_model_memory.setText("Bellek durumu sorgulanıyor…")
        provider = self.combo_provider.currentData()
        self.settings["provider"] = provider
        profile = self.settings["providers"].setdefault(provider, {
            "server_base": "https://api.openai.com" if provider == "chatgpt" else "http://127.0.0.1:" + ("11434" if provider == "ollama" else "1234"),
            "api_key": "", "model": ""})
        self.settings.update(profile)
        self.combo_model.blockSignals(True)
        self.combo_model.clear()
        if profile["model"]:
            self.combo_model.addItem(profile["model"], profile["model"])
        self.combo_model.blockSignals(False)
        save_gui_settings(self.settings)
        self._reset_request_telemetry()
        self.lbl_model_control.setText("Model yönetimi hazır.")
        self.lbl_model_control.setStyleSheet("color: #64748B")
        self._set_connection_state("Kontrol ediliyor…")
        self.append_log("Sunucu: " + self.combo_provider.currentText(), "info")
        self._sync_cloud_ui()
        self._refresh_models()
        if provider == "chatgpt" and not self._loading_session:
            active = next((a for a in self._cloud_summary()["accounts"] if a["id"] == self._cloud_summary()["active"]), {})
            if not active.get("plan_enabled"):
                QTimer.singleShot(0, self._cloud_login)

    def _set_connection_state(self, state):
        from urllib.parse import urlsplit
        url = urlsplit(self.settings.get("server_base", ""))
        address = (url.hostname or "")
        try:
            if url.port:
                address += ":" + str(url.port)
        except ValueError:
            pass
        self.lbl_connection.setText(f"Sunucu: {state} · {self.combo_provider.currentText()} · {address}")
        color = "#047857" if state == "Bağlı" else "#B45309" if state.startswith(("HTTP", "API")) else "#B91C1C" if state == "Ulaşılamıyor" else "#64748B"
        self.lbl_connection.setStyleSheet("color: " + color)

    def _model_connection_received(self, state):
        if not self._model_refresh_pending:
            self._set_connection_state(state)

    def _reset_request_telemetry(self):
        self.response_timer.stop()
        self._request_started = None
        self.last_response_metrics = None
        self.lbl_response_model.setText("Son yanıt modeli: Henüz yanıt yok")
        self.lbl_response_time.setText("Yanıt süresi: —")

    def _response_model_received(self, model):
        if isinstance(self.sender(), QThread) and self.sender() is not self.ai_worker:
            return
        self.lbl_response_model.setText("Yanıt modeli (sunucu): " + model)
        self.lbl_response_model.setToolTip("Bu kimlik doğrudan sunucunun yanıtından alınır; menüdeki seçimden tahmin edilmez.")

    def _response_metrics_received(self, metrics):
        if isinstance(self.sender(), QThread) and self.sender() is not self.ai_worker:
            return
        self.response_timer.stop()
        self._request_started = None
        self.last_response_metrics = dict(metrics)
        if metrics["model"]:
            self._response_model_received(metrics["model"])
        else:
            self.lbl_response_model.setText("Yanıt modeli: Sunucu bildirmedi")
        first = f"{metrics['first_text']:.2f} sn" if metrics["first_text"] is not None else "—"
        self.lbl_response_time.setText(f"Yanıt süresi: {metrics['elapsed']:.2f} sn · İlk metin: {first} · {metrics['outcome']}")

    def _update_live_response_time(self):
        if self._request_started is not None:
            self.lbl_response_time.setText(f"Geçen süre: {time.monotonic() - self._request_started:.1f} sn · Yanıt bekleniyor / yazılıyor")

    def _model_control_busy(self):
        return self.model_control_worker is not None and self.model_control_worker.isRunning()

    def _sync_model_control_buttons(self):
        refreshing = bool(self.model_worker and self.model_worker.isRunning()) or getattr(self, "_model_refresh_pending", False)
        chatting = bool(self.ai_worker and self.ai_worker.isRunning())
        enabled = self.settings["provider"] != "chatgpt" and not (refreshing or chatting or self._model_control_busy()) and bool(self.combo_model.currentData())
        self.btn_load_model.setEnabled(enabled)
        self.btn_unload_model.setEnabled(enabled)

    def _start_model_control(self, operation):
        if self.settings["provider"] == "chatgpt":
            return
        if self._model_control_busy() or (self.ai_worker and self.ai_worker.isRunning()) or (self.model_worker and self.model_worker.isRunning()) or self._model_refresh_pending:
            self.append_log("Önce çalışan sohbetin veya model işleminin bitmesini bekleyin.", "warn")
            return
        model = self.combo_model.currentData()
        if not model:
            self.append_log("Önce bir model seçin.", "warn")
            return
        from rea_model_control import ModelControlWorker
        self.model_control_worker = ModelControlWorker(self.settings["provider"], self.settings["server_base"],
            self.settings.get("api_key", ""), model, operation, self,
            load_configs=self._model_load_configs.get((self.settings["provider"], self.settings["server_base"]), {}))
        worker = self.model_control_worker
        worker.progress.connect(self._model_control_progress)
        worker.completed.connect(self._model_control_completed)
        worker.failed.connect(self._model_control_failed)
        worker.finished.connect(self._model_control_finished)
        self.lbl_model_control.setText("Modeller boşaltılıp seçili model yüklenecek…" if operation == "load" else "Seçili model boşaltılıyor…")
        self.lbl_model_control.setStyleSheet("color: #64748B")
        for widget in (self.combo_provider, self.combo_model, self.btn_send, self.btn_refresh_models, self.btn_load_model, self.btn_unload_model):
            widget.setEnabled(False)
        worker.start()

    def _model_control_progress(self, text):
        self.lbl_model_control.setText(text)
        self.append_log(text, "run")

    def _model_control_completed(self, result):
        if self.sender() is not self.model_control_worker:
            return
        model = result["model"]
        self.settings["model"] = model
        self._remember_provider()
        self.combo_model.blockSignals(True)
        if self.combo_model.findData(model) < 0:
            self.combo_model.addItem(model, model)
        self.combo_model.setCurrentIndex(self.combo_model.findData(model))
        self.combo_model.blockSignals(False)
        text = ("Model yüklendi: " if result["operation"] == "load" else "Seçili model bellekte değil: ") + result["model"]
        self.lbl_model_control.setText(text)
        self.lbl_model_control.setStyleSheet("color: #047857")
        self.append_log(text, "success")

    def _model_control_failed(self, error):
        self.lbl_model_control.setText("Model işlemi tamamlanamadı: " + error)
        self.lbl_model_control.setStyleSheet("color: #B91C1C")
        self.append_log("Model işlemi tamamlanamadı: " + error, "error")

    def _model_control_finished(self):
        if self.sender() is not self.model_control_worker:
            return
        key = (self.model_control_worker.provider, self.model_control_worker.server_base)
        self._model_load_configs.setdefault(key, {}).update(self.model_control_worker.captured_load_configs)
        for widget in (self.combo_provider, self.combo_model, self.btn_send, self.btn_refresh_models):
            widget.setEnabled(True)
        self._model_refresh_pending = False
        self._refresh_models(quiet=True)

    def _poll_model_memory(self):
        if self.settings["provider"] != "chatgpt" and not self._session_busy() and not (self.model_worker and self.model_worker.isRunning()) and not self.combo_model.view().isVisible():
            self._refresh_models(quiet=True)

    def _memory_received(self, result):
        if self._model_control_busy():
            self._model_refresh_pending = True
            return
        if not self._model_refresh_pending:
            self._model_memory = result["states"]
            self._memory_error = result["error"]

    def _decorate_model(self, index):
        model = self.combo_model.itemData(index)
        if self.settings["provider"] == "chatgpt":
            self.combo_model.setItemText(index, getattr(self.model_worker, "names", {}).get(model, model))
            self.combo_model.setItemData(index, str(model) + " · ChatGPT planı", Qt.ToolTipRole)
            return
        state = self._model_memory.get(model)
        status = "Bellekte" if state is True else "Yüklü değil" if state is False else "Durum bilinmiyor"
        self.combo_model.setItemText(index, f"[{status}] {model}")
        self.combo_model.setItemData(index, f"{model}\n{status}", Qt.ToolTipRole)
        font = QFont()
        font.setBold(state is True)
        self.combo_model.setItemData(index, font, Qt.FontRole)
        self.combo_model.setItemData(index, QColor("#047857" if state is True else "#64748B"), Qt.ForegroundRole)

    def _update_memory_label(self):
        if self.settings["provider"] == "chatgpt":
            self._sync_cloud_ui()
            self._sync_model_control_buttons()
            return
        model = self.combo_model.currentData()
        state = self._model_memory.get(model)
        text = "Seçili model bellekte yüklü." if state is True else "Seçili model bellekte yüklü değil; ilk istekte yüklenebilir." if state is False else "Seçili modelin bellek durumu bilinmiyor."
        if self.ai_worker and self.ai_worker.isRunning():
            text = "Seçili model bu sohbet isteğini işliyor; bellek durumu yanıt sonunda yenilenecek."
        self.lbl_model_memory.setText(text)
        self.lbl_model_memory.setToolTip(self._memory_error or "Bellekte olmak sürekli yanıt ürettiği anlamına gelmez. Durum 15 saniyede bir ve sohbet bitince yenilenir.")
        self._sync_model_control_buttons()

    def _refresh_models(self, checked=False, quiet=False):
        if self._closing or self._cloud_busy():
            return
        if self._model_control_busy():
            self._model_refresh_pending = True
            return
        if self.model_worker and self.model_worker.isRunning():
            self._model_refresh_pending = True
            return
        self._model_refresh_pending = False
        self._model_refresh_quiet = quiet
        if self.settings["provider"] == "chatgpt":
            from rea_chatgpt import CloudModelListWorker
            worker = CloudModelListWorker(self.cloud_store, self)
        else:
            worker = ModelListWorker(self.settings.get("server_base", DEFAULT_SERVER_BASE),
                                     self.settings.get("api_key", ""), self, provider=self.settings["provider"])
        self.model_worker = worker
        self.btn_refresh_models.setEnabled(False)
        self.btn_refresh_models.setText("Yenileniyor…")
        worker.connection_received.connect(self._model_connection_received)
        worker.memory_received.connect(self._memory_received)
        worker.completed.connect(self._models_received)
        worker.failed.connect(self._models_failed)
        worker.finished.connect(self._model_refresh_finished)
        worker.start()
        self._sync_model_control_buttons()

    def _model_refresh_finished(self):
        self._sync_cloud_ui()
        self.btn_refresh_models.setEnabled(not self._model_control_busy())
        self.btn_refresh_models.setText("Modelleri yenile")
        self._sync_model_control_buttons()
        if self._model_refresh_pending:
            QTimer.singleShot(0, self._refresh_models)

    def _models_received(self, models):
        if self._model_control_busy():
            self._model_refresh_pending = True
            return
        if self._model_refresh_pending:
            return
        selected = self.settings.get("model", "")
        self.combo_model.blockSignals(True)
        self.combo_model.clear()
        for model in (models if self.settings["provider"] == "chatgpt" else sorted(models, key=lambda item: (self._model_memory.get(item) is not True, item))):
            self.combo_model.addItem(model, model)
            self._decorate_model(self.combo_model.count() - 1)
        index = self.combo_model.findData(selected)
        if selected and index < 0:
            self.append_log("Önceki model sunucuda bulunamadı; listedeki ilk model seçildi.", "warn")
        self.combo_model.setCurrentIndex(index if index >= 0 else 0)
        self.combo_model.blockSignals(False)
        if self.settings.get("model") != self.combo_model.currentData():
            self._on_model_changed()
        else:
            self._update_memory_label()
        if not self._model_refresh_quiet:
            self.append_log(f"Sunucudan {len(models)} model alındı; bellekte: {sum(self._model_memory.get(m) is True for m in models)}.", "success")

    def _models_failed(self, error):
        if self._model_control_busy():
            self._model_refresh_pending = True
            return
        if not self._model_refresh_pending:
            self._model_memory = {}
            self._memory_error = error
            self.combo_model.blockSignals(True)
            for index in range(self.combo_model.count()):
                self._decorate_model(index)
            self.combo_model.blockSignals(False)
            self._update_memory_label()
            if self._model_refresh_quiet:
                return
            self.append_log(f"Model listesi alınamadı; mevcut seçim korundu: {error}", "warn")

    def closeEvent(self, event):
        self._closing = True
        if self._cloud_busy():
            self.cloud_worker.cancel()
            if not self.cloud_worker.wait(2000):
                self._closing = False
                event.ignore()
                return
        if self.settings["provider"] == "chatgpt" and self.model_worker and self.model_worker.isRunning():
            if not self.model_worker.wait(2000):
                self._closing = False
                event.ignore()
                return
        if self._model_control_busy():
            self.model_control_worker.cancel()
            if not self.model_control_worker.wait(9000):
                self._closing = False
                event.ignore()
                return
        if self.catalog_worker and self.catalog_worker.isRunning():
            self.catalog_worker.cancel()
            if not self.catalog_worker.wait(2000):
                self._closing = False
                event.ignore()
                return
        if self.current_worker and self.current_worker.isRunning():
            self.current_worker.cancel()
            if not self.current_worker.wait(5000):
                self._closing = False
                event.ignore()
                return
        if self.ai_worker and self.ai_worker.isRunning():
            self.ai_worker.cancel()
            if not self.ai_worker.wait(9000 if getattr(self.ai_worker, "is_mcp", False) else 2500):
                self._closing = False
                event.ignore()
                return
        if self.model_worker and self.model_worker.isRunning():
            self.model_worker.wait(9000)
        self._autosave_session()
        self.analysis_sessions.close()
        super().closeEvent(event)

    def _on_model_changed(self):
        if self._model_control_busy():
            self.combo_model.blockSignals(True)
            self.combo_model.setCurrentIndex(self.combo_model.findData(self.settings.get("model", "")))
            self.combo_model.blockSignals(False)
            return
        if self.sender() is self.combo_model:
            self.lbl_model_control.setText("Model yönetimi hazır.")
            self.lbl_model_control.setStyleSheet("color: #64748B")
        selected_model = self.combo_model.currentData()
        self.settings["model"] = selected_model
        self._remember_provider()
        self._update_memory_label()
        self.append_log(f"Selected model: {selected_model}", "info")

    def _mcp_mode_changed(self, enabled):
        self.settings["mcp_enabled"] = bool(enabled)
        save_gui_settings(self.settings)
        self._update_mcp_status()

    def _update_mcp_status(self):
        self.btn_mcp_log.setText("MCP araç günlüğü (" + str(len(self.mcp_runs)) + ")")
        self.lbl_mcp_status.setText("MCP açık: seçili dosyada statik analiz." if self.chk_mcp.isChecked() else "MCP modu kapalı; normal sohbet.")

    def _show_mcp_log(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("MCP analiz günlüğü — kayıtlar yeniden çalıştırılmaz")
        dialog.resize(900, 650)
        layout = QVBoxLayout(dialog)
        text = QPlainTextEdit()
        text.setReadOnly(True)
        text.setPlainText(json.dumps(self.mcp_runs, ensure_ascii=False, indent=2) if self.mcp_runs else "Henüz MCP analizi yapılmadı.")
        layout.addWidget(text)
        close = QPushButton("Kapat")
        close.clicked.connect(dialog.accept)
        layout.addWidget(close)
        dialog.exec_()

    def _cancel_mcp_for_target_change(self):
        self.analysis_sessions.clear()
        manual=getattr(self,"current_worker",None)
        if manual and manual.isRunning() and hasattr(manual,"analysis_progress"):
            manual.cancel()
        worker = getattr(self, "ai_worker", None)
        if worker and worker.isRunning() and getattr(worker, "is_mcp", False):
            worker.cancel()
            self.append_log("Hedef değişti; önceki MCP analizi durduruluyor.", "warn")

    def _trim_mcp_history(self):
        self.mcp_runs = self.mcp_runs[-12:]
        while len(self.mcp_runs) > 1 and len(json.dumps(self.mcp_runs, ensure_ascii=False)) > 16*1024*1024:
            self.mcp_runs.pop(0)

    def _on_mcp_tool_event(self, event):
        worker = self.sender()
        run = next((run for run in self.mcp_runs if run["id"] == worker.run_id), None)
        if run is None:
            return
        old = next((i for i,e in enumerate(run["events"]) if e["id"] == event["id"]), None)
        if old is None:
            run["events"].append(dict(event))
        else:
            run["events"][old] = dict(event)
        if worker is self.ai_worker and worker.target_context == self._analysis_target_context():
            import html
            phase = event.get("phase", "")
            status_text = phase if event["status"] == "running" and phase else event["status"]
            self.lbl_mcp_status.setText("MCP: " + event["tool"] + " · " + status_text)
            if event["status"] == "running" and phase == "Ghidra ilk analiz":
                self.append_log("Ghidra ilk analizi hazırlanıyor: " + html.escape(event["tool"]) +
                    " · bekleme payı " + str(int(event["timeout_seconds"])) + " sn. Durdur kullanılabilir.", "info")
            if event.get("cache_hit"):
                self.append_log("Önbellekten kullanıldı: " + html.escape(event["tool"]), "info")
            if event.get("fallback_from"):
                self.append_log("Alternatif motor: " + html.escape(str(event.get("engine", ""))), "warn")
            self.lbl_ai_status.setText("MCP çalışıyor…")
            self.append_log("MCP " + html.escape(event["tool"]) + " · " + event["status"], "run" if event["status"] == "running" else "success" if event["status"] == "ok" else "warn")
        self._trim_mcp_history()
        self.btn_mcp_log.setText("MCP araç günlüğü (" + str(len(self.mcp_runs)) + ")")
        self._autosave_session()

    def _on_mcp_recorded(self, record):
        worker = self.sender()
        record = dict(record)
        record["provider"] = worker.provider_id
        index = next((i for i,run in enumerate(self.mcp_runs) if run["id"] == record["id"]), None)
        if index is not None:
            self.mcp_runs[index] = record
        if worker is self.ai_worker and worker.target_context == self._analysis_target_context():
            self.lbl_analysis_progress.setText("Analiz: "+record["status"])
            count = sum(e["status"] == "ok" for e in record["events"])
            self.lbl_mcp_status.setText("MCP: " + record["status"] + " · başarılı çağrı: " + str(count))
        self._trim_mcp_history()
        self.btn_mcp_log.setText("MCP araç günlüğü (" + str(len(self.mcp_runs)) + ")")
        self._autosave_session()

    def _on_send_clicked(self):
        prompt = self.txt_prompt.toPlainText().strip()
        if not prompt:
            return
        if self._send_ai_prompt(prompt):
            self.txt_prompt.clear()

    def _send_ai_prompt(self, user_prompt: str, selection_only=False):
        if self._cloud_busy():
            self.append_log("ChatGPT girişinin tamamlanmasını bekleyin; taslak korundu.", "warn")
            return False
        if self.settings["provider"] == "chatgpt":
            summary = self._cloud_summary()
            active = next((a for a in summary["accounts"] if a["id"] == summary["active"]), {})
            if not active.get("plan_enabled"):
                self.append_log("ChatGPT hesabınıza giriş yapıp plan kullanım izni verin; taslak korundu.", "warn")
                self._cloud_login()
                return False
        if self._model_control_busy():
            self.append_log("Model yükleme/boşaltma işleminin bitmesini bekleyin.", "warn")
            return False
        if self.model_worker and self.model_worker.isRunning():
            self.append_log("Model listesinin yenilenmesini bekleyin.", "warn")
            return
        if not self.settings.get("model"):
            self.append_log("Önce sunucuya bağlanıp bir model seçin.", "warn")
            return
        if self.ai_worker and self.ai_worker.isRunning():
            self.append_log("An Electra AI query is already in progress.", "warn")
            return

        use_mcp = self.chk_mcp.isChecked() and not selection_only
        if use_mcp and (not self.target_path or not os.path.isfile(self.target_path)):
            self.append_log("MCP analizi için önce bir dosya seçin; mesaj taslağı korundu.", "warn")
            self.lbl_ai_status.setText("Hedef gerekli")
            return False
        if use_mcp and self.current_worker and self.current_worker.isRunning():
            self.append_log("Önce çalışan manuel analizi bitirin veya durdurun.", "warn")
            return False

        server_base = self.settings.get("server_base", DEFAULT_SERVER_BASE)
        api_key = self.settings.get("api_key", "")
        model = self.settings.get("model", "electra-nano")

        # Build context from current binary and active tab
        active_tab_idx = self.tabs.currentIndex()
        context_snippets = []
        if self.target_path:
            context_snippets.append(f"Target Binary: {self.target_path}")

        if not selection_only and active_tab_idx == 0 and self.tab_overview.toPlainText():
            context_snippets.append(f"--- Binary Overview / Headers ---\n{self.tab_overview.toPlainText()}")
        elif not selection_only and active_tab_idx == 1 and self.tab_disasm.toPlainText():
            context_snippets.append(f"--- Active Disassembly Snippet ---\n{self.tab_disasm.toPlainText()}")
        elif not selection_only and active_tab_idx == 2 and self.tab_decomp.toPlainText():
            context_snippets.append(f"--- Decompiled C Code ---\n{self.tab_decomp.toPlainText()}")

        system_prompt = (
            "You are the Electra AI Reverse Engineering Assistant, deeply integrated into REA "
            "(Reverse Engineering Anything). You provide precise, insightful explanations of machine code, "
            "decompilations, assembly instructions, binary security mitigations, and potential vulnerabilities. "
            "Respond in clean, clear markdown format."
        )

        if selection_only and "qwen" in model.lower():
            # Qwen's documented soft switch avoids spending the whole quick-action budget on reasoning.
            system_prompt += "\nGive a concise final answer directly. /no_think"

        try:
            messages, info = bounded_messages(system_prompt, "\n\n".join(context_snippets),
                ([] if selection_only else self.chat_history) + [{"role": "user", "content": user_prompt}],
                int(self.settings.get("context_char_limit", 12000)))
        except ValueError as exc:
            self.append_log(str(exc), "warn")
            self.lbl_ai_status.setText("Bağlam sınırı")
            return False
        self.append_log(f"Gönderilen bağlam: {info['characters']} karakter; "
                        f"çıkarılan eski mesaj: {info['dropped_messages']}; "
                        f"analiz kısaltıldı: {info['context_truncated']}", "info")
        try:
            if self.settings["provider"] == "chatgpt":
                from rea_chatgpt import CloudCopilotWorker, CloudChatWorker
                if use_mcp:
                    worker = CloudCopilotWorker(self.cloud_store, model, messages, self.target_path,
                        self.settings.get("rea_bin", REA_BIN_PATH), context_limit=int(self.settings.get("context_char_limit", 12000)),session_pool=self.analysis_sessions)
                    worker.target_context = self._analysis_target_context()
                    worker.provider_id = "chatgpt"
                else:
                    worker = CloudChatWorker(self.cloud_store, model, messages)
            elif use_mcp:
                from rea_copilot import McpCopilotWorker
                worker = McpCopilotWorker(server_base, api_key, model, messages, self.target_path,
                    self.settings.get("rea_bin", REA_BIN_PATH), temperature=self.settings.get("temperature", .3),
                    max_tokens=int(self.settings.get("response_token_limit", 1024)),
                    context_limit=int(self.settings.get("context_char_limit", 12000)), provider=self.settings["provider"],session_pool=self.analysis_sessions)
                worker.target_context = self._analysis_target_context()
                worker.provider_id = self.settings["provider"]
            else:
                worker = ElectraAiChatWorker(server_base, api_key, model, messages,
                    temperature=self.settings.get("temperature", .3),
                    max_tokens=int(self.settings.get("response_token_limit", 1024)))
        except (OSError, ValueError) as exc:
            self.append_log(str(exc), "warn")
            self.lbl_ai_status.setText("MCP başlatılamadı")
            return False
        self.append_chat_message("user", user_prompt)
        self._stream_text = ""
        self._stream_start = None
        self.lbl_ai_status.setText("Yanıt bekleniyor…")
        self.btn_send.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.combo_model.setEnabled(False)
        self.combo_provider.setEnabled(False)
        self.ai_worker = worker
        self.chk_mcp.setEnabled(False)
        if use_mcp:
            self.mcp_runs.append({"id":worker.run_id,"target":self.target_path,"provider_model":model,
                "provider":worker.provider_id,"status":"running","events":[]})
            self.mcp_runs = self.mcp_runs[-12:]
            worker.tool_event.connect(self._on_mcp_tool_event)
            worker.run_recorded.connect(self._on_mcp_recorded)
            self.lbl_mcp_status.setText("MCP: bağlantı ve araçlar hazırlanıyor…")
        self.ai_worker.connection_received.connect(self._set_connection_state)
        self.ai_worker.model_received.connect(self._response_model_received)
        self.ai_worker.metrics_received.connect(self._response_metrics_received)
        self.ai_worker.log_line.connect(self.append_log)
        self.ai_worker.chunk_received.connect(self._on_ai_chunk)
        self.ai_worker.completed.connect(self._on_ai_completed)
        self.ai_worker.cancelled.connect(self._on_ai_cancelled)
        if use_mcp:self.ai_worker.analysis_progress.connect(self._on_analysis_progress)
        self.ai_worker.failed.connect(self._on_ai_failed)
        self.ai_worker.finished.connect(self._on_ai_finished)
        self._request_started = time.monotonic()
        self.lbl_response_model.setText("Yanıt modeli: Sunucudan bekleniyor…")
        self.response_timer.start()
        self._update_live_response_time()
        self.ai_worker.start()
        self._sync_cloud_ui()
        self._update_memory_label()
        return True

    def _on_ai_chunk(self, text):
        if isinstance(self.sender(), QThread) and self.sender() is not self.ai_worker:
            return
        if getattr(self.sender(), "is_mcp", False) and getattr(self.sender(), "target_context", None) != self._analysis_target_context():
            return
        cursor = self.chat_view.textCursor()
        cursor.movePosition(QTextCursor.End)
        if self._stream_start is None:
            self._stream_start = cursor.position()
            cursor.insertText("\nAssistant:\n")
        cursor.insertText(text)
        self._stream_text += text
        self.chat_view.ensureCursorVisible()
        self.lbl_ai_status.setText("Yazıyor…")

    def _finish_stream(self, reply):
        if self._stream_start is not None:
            cursor = self.chat_view.textCursor()
            cursor.setPosition(self._stream_start)
            cursor.movePosition(QTextCursor.End, QTextCursor.KeepAnchor)
            cursor.removeSelectedText()
        self._stream_start = None
        if reply:
            self.append_chat_message("assistant", reply)

    def _on_ai_completed(self, reply):
        if isinstance(self.sender(), QThread) and self.sender() is not self.ai_worker:
            return
        if getattr(self.sender(), "is_mcp", False) and getattr(self.sender(), "target_context", None) != self._analysis_target_context():
            self._finish_stream(self._stream_text + "\n\n[Hedef değişti; önceki MCP yanıtı kullanılmadı.]")
            self.lbl_ai_status.setText("Hedef değişti")
            return
        self._finish_stream(reply)
        self.lbl_ai_status.setText("Araç kanıtı yok" if getattr(self.ai_worker, "is_mcp", False) and self.mcp_runs and self.mcp_runs[-1]["status"] == "Araç kanıtı yok" else "Ready")
        self.lbl_ai_status.setStyleSheet("color: #10B981; font-size: 11px; font-weight: 600;")

    def _on_ai_cancelled(self, partial):
        if isinstance(self.sender(), QThread) and self.sender() is not self.ai_worker:
            return
        self._finish_stream(partial + ("\n\n[Yanıt durduruldu]" if partial else "[Yanıt durduruldu]"))
        self.lbl_ai_status.setText("Stopped")

    def _on_ai_failed(self, error):
        if isinstance(self.sender(), QThread) and self.sender() is not self.ai_worker:
            return
        self._finish_stream(self._stream_text)
        agent_error = getattr(self.ai_worker, "is_mcp", False)
        self.append_chat_message("assistant", ("**MCP analiz hatası:** " if agent_error else "**Bağlantı hatası:** ") + error)
        self.lbl_ai_status.setText("Error")
        if agent_error:
            import html
            error = html.escape(error)
        self.append_log(error, "error")

    def _on_ai_finished(self):
        if isinstance(self.sender(), QThread) and self.sender() is not self.ai_worker:
            return
        self.chk_mcp.setEnabled(True)
        self._sync_cloud_ui()
        self._autosave_session()
        self.btn_send.setEnabled(not self._model_control_busy())
        self.btn_stop.setEnabled(False)
        self.combo_model.setEnabled(not self._model_control_busy())
        self.combo_provider.setEnabled(not self._model_control_busy())
        self._refresh_models(quiet=True)

    def _on_stop_clicked(self):
        if self.ai_worker and self.ai_worker.isRunning():
            self.ai_worker.cancel()
            self.lbl_ai_status.setText("Durduruluyor…")
            self.btn_stop.setEnabled(False)

    def _open_settings(self):
        if self._cloud_busy():
            self.append_log("ChatGPT girişinin bitmesini bekleyin.", "warn")
            return
        if self._model_control_busy():
            self.append_log("Model bellek işlemi bitmeden ayarlar değiştirilemez.", "warn")
            return
        if self.ai_worker and self.ai_worker.isRunning():
            self.append_log("Ayarları değiştirmeden önce yanıtı durdurun.", "warn")
            return
        dlg = SettingsDialog(self, self.settings)
        if dlg.exec_() == QDialog.Accepted:
            self.settings = load_gui_settings()
            self._remember_provider()
            self._reset_request_telemetry()
            self._set_connection_state("Kontrol ediliyor…")
            self.append_log("Settings updated successfully.", "info")
            self._refresh_command_catalog()
            self._refresh_models()

    def _open_about(self):
        dlg = AboutDialog(self)
        dlg.exec_()


# ─────────────────────────────────────────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

def main():
    target_arg = None
    if len(sys.argv) > 1 and not sys.argv[1].startswith("-"):
        target_arg = sys.argv[1]

    app = QApplication(sys.argv)
    app.setApplicationName("REA")
    app.setOrganizationName("MakuluLinux")

    window = ReaMainWindow(target_file=target_arg)
    window.show()

    sys.exit(app.exec_())


if __name__ == "__main__":
    main()

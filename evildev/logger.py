#!/usr/bin/env python3
# logger.py — minimal, single-handler logger for the vault-only console.
#
# Public API used by app.py and db.py:
#   get_logger(name)         -> ColouredLogger
#   set_log_level(level_str) -> adjusts handler levels at runtime
#   Colours, EMOJIS          -> exported constants
#
# Env flags:
#   NO_COLOUR=1        Disable ANSI colour codes
#   NO_EMOJI=1         Disable emoji prefixes
#   LOG_FILE=...       Rotating plain-text log path (off by default)
#   DEBUG=true         Set root log level to DEBUG
#
# Design:
#   - Exactly ONE console handler on the root logger.
#   - All pre-existing handlers are removed at setup time, including
#     werkzeug's default StreamHandler, so no message is ever printed twice.
#   - werkzeug child loggers are cleared + set to propagate=True so their
#     messages reach our single handler without re-installing their own.

import os
import sys
import logging
from pathlib import Path


# ---------------------------------------------------------------------------
# Force UTF-8 stdout/stderr before anything else tries to write
# ---------------------------------------------------------------------------
try:
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    if hasattr(sys.stderr, 'reconfigure'):
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
except Exception:
    pass


# ---------------------------------------------------------------------------
# Silence noisy HTTP loggers before they get a chance to chatter
# ---------------------------------------------------------------------------
_QUIET_HTTP = os.environ.get('QUIET_HTTP_LOGS', 'true').lower() not in ('false', '0', 'no')
_VERBOSE_HTTP = os.environ.get('VERBOSE_HTTP_LOGS', 'false').lower() in ('true', '1', 'yes')
if _QUIET_HTTP and not _VERBOSE_HTTP:
    try:
        for _n in ('urllib3', 'urllib3.connectionpool', 'requests',
                   'requests.packages.urllib3', 'http.client',
                   'requests_oauthlib', 'oauthlib'):
            logging.getLogger(_n).setLevel(logging.WARNING)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Output mode flags
# ---------------------------------------------------------------------------
def _env_flag(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name, '').strip().lower()
    if not raw:
        return default
    return raw in ('1', 'true', 'yes', 'on')


def _stdout_is_tty() -> bool:
    try:
        return sys.stdout.isatty()
    except Exception:
        return False


USE_COLOUR = not _env_flag('NO_COLOUR') and _stdout_is_tty()
USE_EMOJI = not _env_flag('NO_EMOJI')


# ---------------------------------------------------------------------------
# Colour codes (or no-ops when disabled)
# ---------------------------------------------------------------------------
class _Colours:
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    BLACK = '\033[30m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'
    BRIGHT_BLACK = '\033[90m'
    BRIGHT_RED = '\033[91m'
    BRIGHT_GREEN = '\033[92m'
    BRIGHT_YELLOW = '\033[93m'
    BRIGHT_BLUE = '\033[94m'
    BRIGHT_MAGENTA = '\033[95m'
    BRIGHT_CYAN = '\033[96m'
    BRIGHT_WHITE = '\033[97m'
    BG_RED = '\033[41m'
    BG_GREEN = '\033[42m'
    BG_YELLOW = '\033[43m'
    BG_BLUE = '\033[44m'
    BG_MAGENTA = '\033[45m'
    BG_CYAN = '\033[46m'
    BG_WHITE = '\033[47m'


class _NoColours:
    RESET = ''
    BOLD = ''
    DIM = ''
    BLACK = ''
    RED = ''
    GREEN = ''
    YELLOW = ''
    BLUE = ''
    MAGENTA = ''
    CYAN = ''
    WHITE = ''
    BRIGHT_BLACK = ''
    BRIGHT_RED = ''
    BRIGHT_GREEN = ''
    BRIGHT_YELLOW = ''
    BRIGHT_BLUE = ''
    BRIGHT_MAGENTA = ''
    BRIGHT_CYAN = ''
    BRIGHT_WHITE = ''
    BG_RED = ''
    BG_GREEN = ''
    BG_YELLOW = ''
    BG_BLUE = ''
    BG_MAGENTA = ''
    BG_CYAN = ''
    BG_WHITE = ''


Colours = _Colours if USE_COLOUR else _NoColours


# ---------------------------------------------------------------------------
# Emojis (real UTF-8 codepoints; blanked when NO_EMOJI=1)
# ---------------------------------------------------------------------------
_EMOJI_RAW = {
    'DEBUG': '\U0001F41B',        # 🐛
    'INFO': '\U0001F4E1',         # 📡
    'SUCCESS': '\u2705',          # ✅
    'WARNING': '\u26A0\uFE0F',    # ⚠️
    'ERROR': '\u274C',            # ❌
    'TOKEN': '\U0001F511',        # 🔑
    'COOKIE': '\U0001F36A',       # 🍪
    'PHISH': '\U0001F3A3',        # 🎣
    'EXFIL': '\U0001F4E4',        # 📤
    'PROXY': '\U0001F310',        # 🌐
    'AUTH': '\U0001F510',         # 🔐
    'API': '\U0001F30D',          # 🌍
    'DB': '\U0001F5C4\uFE0F',     # 🗄️
    'THREAD': '\U0001F9F5',       # 🧵
    'JITTER': '\u23F1\uFE0F',     # ⏱️
    'RETRY': '\U0001F504',        # 🔄
    'CAPTURE': '\U0001F4F8',      # 📸
    'DEVICE_CODE': '\U0001F4F1',  # 📱
    'POLLING': '\u23F3',          # ⏳
    'REFRESH': '\u267B\uFE0F',    # ♻️
}
EMOJIS = _EMOJI_RAW if USE_EMOJI else {k: '' for k in _EMOJI_RAW}


# ---------------------------------------------------------------------------
# ColouredLogger
# ---------------------------------------------------------------------------
class ColouredLogger(logging.Logger):
    """Logger with optional colour/emoji plus app-specific helpers."""

    LEVEL_COLOURS = {
        logging.DEBUG: Colours.BRIGHT_BLACK,
        logging.INFO: Colours.CYAN,
        logging.WARNING: Colours.YELLOW,
        logging.ERROR: Colours.RED,
        logging.CRITICAL: Colours.BRIGHT_RED,
    }

    def __init__(self, name: str, level: int = logging.NOTSET):
        super().__init__(name, level)

    def _emit_coloured(self, level: int, msg: str, emoji: str = '') -> None:
        colour = self.LEVEL_COLOURS.get(level, Colours.WHITE)
        prefix = f"{emoji} " if emoji else ''
        reset = Colours.RESET if colour else ''
        if self.isEnabledFor(level):
            self._log(level, f"{colour}{prefix}{msg}{reset}", args=())

    # Convenience helpers used by app.py
    def success(self, msg, *args, **kwargs):
        self._emit_coloured(logging.INFO, msg, EMOJIS['SUCCESS'])

    def token(self, msg, *args, **kwargs):
        self._emit_coloured(logging.INFO, msg, EMOJIS['TOKEN'])

    def cookie(self, msg, *args, **kwargs):
        self._emit_coloured(logging.INFO, msg, EMOJIS['COOKIE'])

    def phish(self, msg, *args, **kwargs):
        self._emit_coloured(logging.INFO, msg, EMOJIS['PHISH'])

    def exfil(self, msg, *args, **kwargs):
        self._emit_coloured(logging.INFO, msg, EMOJIS['EXFIL'])

    def proxy(self, msg, *args, **kwargs):
        self._emit_coloured(logging.DEBUG, msg, EMOJIS['PROXY'])

    def api(self, msg, *args, **kwargs):
        self._emit_coloured(logging.DEBUG, msg, EMOJIS['API'])

    def db(self, msg, *args, **kwargs):
        self._emit_coloured(logging.INFO, msg, EMOJIS['DB'])

    def thread(self, msg, *args, **kwargs):
        self._emit_coloured(logging.DEBUG, msg, EMOJIS['THREAD'])

    def capture(self, msg, *args, **kwargs):
        self._emit_coloured(logging.INFO, msg, EMOJIS['CAPTURE'])

    def device_code(self, msg, *args, **kwargs):
        self._emit_coloured(logging.INFO, msg, EMOJIS['DEVICE_CODE'])

    def polling(self, msg, *args, **kwargs):
        self._emit_coloured(logging.INFO, msg, EMOJIS['POLLING'])

    def refresh(self, msg, *args, **kwargs):
        self._emit_coloured(logging.INFO, msg, EMOJIS['REFRESH'])

    def jitter(self, msg, *args, **kwargs):
        self._emit_coloured(logging.DEBUG, msg, EMOJIS['JITTER'])

    def retry(self, msg, *args, **kwargs):
        self._emit_coloured(logging.WARNING, msg, EMOJIS['RETRY'])


# ---------------------------------------------------------------------------
# Simple size-based rotating file handler (plain text only)
# ---------------------------------------------------------------------------
class _RotatingFileHandler(logging.Handler):
    def __init__(self, filename: str, max_bytes: int = 10 * 1024 * 1024,
                 backup_count: int = 5):
        super().__init__()
        self.filename = filename
        self.max_bytes = max_bytes
        self.backup_count = backup_count
        self.stream = None
        self._open_file()

    def _open_file(self):
        try:
            Path(os.path.dirname(self.filename) or '.').mkdir(parents=True, exist_ok=True)
            self.stream = open(self.filename, 'a', encoding='utf-8')
        except Exception:
            self.stream = None

    def _rotate(self):
        if self.stream is not None:
            try:
                self.stream.close()
            except Exception:
                pass
            self.stream = None
        try:
            for i in range(self.backup_count - 1, 0, -1):
                src = f"{self.filename}.{i}"
                dst = f"{self.filename}.{i+1}"
                if os.path.exists(src):
                    os.rename(src, dst)
        except Exception:
            pass
        try:
            if os.path.exists(self.filename):
                os.rename(self.filename, f"{self.filename}.1")
        except Exception:
            pass
        self._open_file()

    def emit(self, record):
        if self.stream is None:
            return
        try:
            msg = self.format(record)
            self.stream.write(msg + '\n')
            self.stream.flush()
            if self.stream.tell() >= self.max_bytes:
                self._rotate()
        except Exception:
            self.handleError(record)


# ---------------------------------------------------------------------------
# One-time setup
# ---------------------------------------------------------------------------
_SETUP_DONE = False
_LOGGERS: dict = {}
_console_handler: logging.Handler = None
_file_handler: logging.Handler = None


def _setup():
    global _SETUP_DONE, _console_handler, _file_handler
    if _SETUP_DONE:
        return
    _SETUP_DONE = True

    logging.setLoggerClass(ColouredLogger)

    root = logging.getLogger()
    root.setLevel(
        logging.DEBUG if os.environ.get('DEBUG', '').lower() == 'true'
        else logging.INFO
    )

    # ------------------------------------------------------------------
    # Remove ALL existing root handlers (werkzeug's included). We install
    # exactly one StreamHandler below, so no message is ever printed twice.
    # ------------------------------------------------------------------
    for h in list(root.handlers):
        try:
            root.removeHandler(h)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Single console handler — the ONE handler that prints anything.
    # ------------------------------------------------------------------
    _console_handler = logging.StreamHandler(sys.stdout)
    _console_handler.setLevel(logging.DEBUG)
    _console_handler.setFormatter(logging.Formatter('%(message)s'))
    root.addHandler(_console_handler)

    # ------------------------------------------------------------------
    # Prevent werkzeug from re-installing its own handler on its own
    # logger and from leaking duplicate records. With handlers cleared
    # and propagate=True, werkzeug's messages reach OUR root handler
    # and nowhere else.
    # ------------------------------------------------------------------
    for noisy_name in ('werkzeug', 'werkzeug.routing', 'werkzeug.serving'):
        n = logging.getLogger(noisy_name)
        n.handlers = []
        n.propagate = True
        n.setLevel(logging.INFO)

    # ------------------------------------------------------------------
    # Silence HTTP wire loggers.
    # ------------------------------------------------------------------
    if _QUIET_HTTP and not _VERBOSE_HTTP:
        for n in ('urllib3', 'requests', 'http.client',
                  'requests_oauthlib', 'oauthlib'):
            logging.getLogger(n).setLevel(logging.WARNING)

    # ------------------------------------------------------------------
    # Optional plain-text log file with rotation.
    # ------------------------------------------------------------------
    log_file = (os.environ.get('LOG_FILE') or '').strip()
    if log_file:
        try:
            _file_handler = _RotatingFileHandler(log_file)
            _file_handler.setLevel(logging.DEBUG)
            _file_handler.setFormatter(logging.Formatter(
                '%(asctime)s [%(levelname)s] [%(name)s] %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S',
            ))
            root.addHandler(_file_handler)
        except Exception:
            _file_handler = None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def get_logger(name: str = 'root') -> ColouredLogger:
    """Return a ColouredLogger for the given name."""
    _setup()
    if name not in _LOGGERS:
        _LOGGERS[name] = logging.getLogger(name)
    return _LOGGERS[name]


def set_log_level(level: str) -> None:
    """Adjust console/file handler levels at runtime."""
    _setup()
    mapping = {
        'DEBUG': logging.DEBUG,
        'INFO': logging.INFO,
        'WARNING': logging.WARNING,
        'ERROR': logging.ERROR,
        'CRITICAL': logging.CRITICAL,
    }
    lvl = mapping.get((level or '').upper(), logging.INFO)
    if _console_handler:
        _console_handler.setLevel(lvl)
    if _file_handler:
        _file_handler.setLevel(lvl)


__all__ = ['get_logger', 'set_log_level', 'Colours', 'EMOJIS']
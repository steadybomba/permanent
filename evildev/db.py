#!/usr/bin/env python3
"""
db.py - Vault-only database module.

Keeps exactly what the vault app needs:
  - connection pool
  - query execution (execute_query)
  - migrations
  - init_db
  - users (login)
  - enrollments (mint / re-enroll / PRT)
  - runtime overrides + saved configs (kept: harmless and useful)

Removed versus the full project:
  - device_codes helpers
  - save_capture / load_capture
  - record_link_click
  - links inventory helpers
  - harvester state helpers
  - batch operations

The capture_* and link_clicks TABLES remain in the migration history
because the vault delete endpoint does DELETE FROM those tables, and
removing them from migrations would break existing databases.
"""

import os
import json
import base64
import binascii
import sqlite3
import warnings
import threading
import time
import random
import re
import hashlib
import sys
from functools import lru_cache, wraps
from hashlib import md5
from datetime import datetime, timezone
from pathlib import Path
from contextlib import contextmanager
from typing import Any, Dict, List, Optional, Set, Tuple, Union, Generator

try:
    from dotenv import load_dotenv
    load_dotenv(dotenv_path=Path(__file__).resolve().parents[1] / '.env', override=False)
except Exception:
    pass

# ---------------------------------------------------------------------------
# Logger with fallback
# ---------------------------------------------------------------------------
try:
    from evildev.logger import get_logger
except ImportError:
    try:
        from logger import get_logger
    except ImportError:
        import logging
        logging.basicConfig(level=logging.INFO)
        def get_logger(name):
            return logging.getLogger(name)

logger = get_logger('db')

# Crypto utils (only used for runtime override encryption now)
try:
    from evildev.core import CryptoUtils
except Exception:
    try:
        from core import CryptoUtils
    except Exception:
        CryptoUtils = None

RUNTIME_OVERRIDE_ENCRYPTION_PREFIX = 'ENC:'
RUNTIME_OVERRIDE_SENSITIVE_KEYS = {
    'TELEGRAM_BOT_TOKEN',
    'DISCORD_WEBHOOK_URL',
    'OPENAI_API_KEY',
    'AI_API_KEY',
    'GEMINI_API_KEY',
    'ANTHROPIC_API_KEY',
    'PROXY_LIST',
    'EXFIL_CONFIG',
    'REFRESH_TOKEN',
}

# ---------------------------------------------------------------------------
# PostgreSQL imports with fallback
# ---------------------------------------------------------------------------
psycopg2 = None
try:
    import psycopg2
except ImportError:
    psycopg2 = None

_PROJECTGRES_CONNECTED_LOGGED = False

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SQLITE_PATH = PROJECT_ROOT / 'project_data.db'
CONNECTION_MAX_AGE = int(os.environ.get('DB_CONNECTION_MAX_AGE', '300'))
_FORCE_SQLITE_FALLBACK = False


def _detect_db_engine(db_url: str) -> str:
    if not db_url:
        return 'sqlite'
    normalized = db_url.strip().lower()
    if normalized.startswith(('sqlite://', 'sqlite3://', 'sqlite:', 'file:')):
        return 'sqlite'
    if normalized.startswith(('postgres://', 'postgresql://',
                              'postgresql+psycopg2://', 'postgresql+psycopg2cffi://')):
        return 'postgres'
    if normalized.startswith(('/', './', '../')) or normalized.endswith(('.db', '.sqlite', '.sqlite3')):
        return 'sqlite'
    return 'sqlite'


def _secure_db_file(db_path: Path) -> None:
    if not db_path:
        return
    try:
        if db_path.exists():
            os.chmod(db_path, 0o600)
    except OSError:
        pass


def _get_runtime_override_master_key() -> Optional[bytes]:
    key = os.environ.get('ENCRYPTION_KEY')
    if not key:
        return None
    key = key.strip()
    if not key:
        return None
    try:
        return bytes.fromhex(key)
    except (ValueError, TypeError):
        pass
    try:
        decoded = base64.urlsafe_b64decode(key)
        if len(decoded) == 32:
            return decoded
    except (binascii.Error, ValueError):
        pass
    logger.warning('ENCRYPTION_KEY is set but not valid hex or 32-byte base64; runtime override encryption disabled')
    return None


def _is_encrypted_override_value(value: Any) -> bool:
    return isinstance(value, str) and value.startswith(RUNTIME_OVERRIDE_ENCRYPTION_PREFIX)


def _encrypt_runtime_override_value(value: Any, key: bytes) -> str:
    if not isinstance(value, str):
        value = json.dumps(value, separators=(',', ':'))
    if CryptoUtils is None:
        raise RuntimeError('cryptography library not installed; cannot encrypt runtime overrides')
    nonce, ciphertext = CryptoUtils.aes_gcm_encrypt(key, value.encode('utf-8'))
    payload = nonce + ciphertext
    return RUNTIME_OVERRIDE_ENCRYPTION_PREFIX + base64.urlsafe_b64encode(payload).decode('ascii')


def _decrypt_runtime_override_value(value: str, key: bytes) -> Optional[str]:
    if not _is_encrypted_override_value(value):
        return value
    if CryptoUtils is None:
        logger.warning('CryptoUtils unavailable; cannot decrypt runtime override value')
        return None
    token = value[len(RUNTIME_OVERRIDE_ENCRYPTION_PREFIX):]
    try:
        raw = base64.urlsafe_b64decode(token)
        nonce = raw[:12]
        ciphertext = raw[12:]
        plaintext = CryptoUtils.aes_gcm_decrypt(key, nonce, ciphertext)
        return plaintext.decode('utf-8')
    except Exception as e:
        logger.warning(f'Failed to decrypt runtime override value: {e}')
        return None


# ---------------------------------------------------------------------------
# Connection Pool (free-list model)
# ---------------------------------------------------------------------------
_connection_free_list: List[Any] = []
_total_connections: int = 0
_pool_condition = threading.Condition()

DB_POOL_MAX_SIZE = int(os.environ.get('DB_POOL_MAX_SIZE', '8'))
_POOL_REAPER_INTERVAL = int(os.environ.get('DB_POOL_REAPER_INTERVAL', '60'))

# Backward-compat shims
_connection_pool: Dict[int, Any] = {}
_connection_created_at: Dict[int, float] = {}
_connection_identity: Dict[int, Tuple[str, str]] = {}
_pool_lock = threading.Lock()
_thread_local = threading.local()


class _PoolSemaphoreView:
    @property
    def _value(self):
        with _pool_condition:
            return max(0, DB_POOL_MAX_SIZE - _total_connections)

    def acquire(self, *args, **kwargs):
        return True

    def release(self, *args, **kwargs):
        return


_pool_semaphore = _PoolSemaphoreView()


# ---------------------------------------------------------------------------
# DBRow
# ---------------------------------------------------------------------------
class DBRow:
    def __init__(self, row: Any):
        self._row = row

    def __getitem__(self, key: Any) -> Any:
        if isinstance(key, slice):
            if isinstance(self._row, dict):
                return list(self._row.values())[key]
            if isinstance(self._row, (tuple, list)):
                return self._row[key]
            if isinstance(self._row, sqlite3.Row):
                return tuple(self._row)[key]
            if hasattr(self._row, '__iter__') and not isinstance(self._row, (str, bytes, bytearray)):
                return tuple(self._row)[key]
            raise KeyError(key)
        if isinstance(key, int):
            if isinstance(self._row, dict):
                try:
                    return list(self._row.values())[key]
                except (IndexError, KeyError, TypeError):
                    raise KeyError(key)
            return self._row[key]
        if isinstance(self._row, dict):
            return self._row.get(key)
        if hasattr(self._row, 'get'):
            return self._row.get(key)
        if isinstance(self._row, (tuple, list)):
            if len(self._row) == 1:
                return self._row[0]
            raise KeyError(key)
        raise KeyError(key)

    def get(self, key: Any, default: Any = None) -> Any:
        if isinstance(self._row, dict):
            if isinstance(key, int):
                try:
                    return list(self._row.values())[key]
                except (IndexError, KeyError, TypeError):
                    return default
            return self._row.get(key, default)
        if hasattr(self._row, 'get'):
            return self._row.get(key, default)
        if isinstance(self._row, (tuple, list)):
            if isinstance(key, int):
                try:
                    return self._row[key]
                except (IndexError, KeyError, TypeError):
                    return default
            if len(self._row) == 1:
                return self._row[0]
        return default

    def keys(self):
        if isinstance(self._row, dict):
            return self._row.keys()
        if hasattr(self._row, 'keys'):
            return self._row.keys()
        return ()

    def items(self):
        if isinstance(self._row, dict):
            return self._row.items()
        if hasattr(self._row, 'items'):
            return self._row.items()
        return ()

    def values(self):
        if isinstance(self._row, dict):
            return self._row.values()
        if hasattr(self._row, 'values'):
            return self._row.values()
        return ()

    def __iter__(self):
        return iter(self._row)

    def __len__(self):
        return len(self._row)

    def __repr__(self):
        return f"DBRow({repr(self._row)})"


# ---------------------------------------------------------------------------
# Query Cache
# ---------------------------------------------------------------------------
class QueryCache:
    def __init__(self, max_size: int = 100, ttl: int = 60):
        self.cache: Dict[str, Dict[str, Any]] = {}
        self.max_size = max_size
        self.ttl = ttl
        self.lock = threading.Lock()

    def _get_cache_key(self, query: str, params: Any) -> str:
        key = f"{query}|{repr(params)}"
        return md5(key.encode('utf-8')).hexdigest()

    def _prepare_value(self, value: Any) -> Any:
        if isinstance(value, sqlite3.Row):
            return DBRow(tuple(value))
        if isinstance(value, dict):
            return DBRow(value)
        if isinstance(value, list):
            return [self._prepare_value(item) for item in value]
        if isinstance(value, tuple):
            return tuple(self._prepare_value(item) for item in value)
        return value

    def get(self, query: str, params: Any, ttl: Optional[int] = None) -> Optional[Any]:
        key = self._get_cache_key(query, params)
        with self.lock:
            entry = self.cache.get(key)
            if not entry:
                return None
            effective_ttl = self.ttl if ttl is None else ttl
            if effective_ttl <= 0 or time.time() - entry['timestamp'] < effective_ttl:
                return entry['data']
            self.cache.pop(key, None)
            return None

    def set(self, query: str, params: Any, data: Any, ttl: Optional[int] = None) -> None:
        key = self._get_cache_key(query, params)
        with self.lock:
            if len(self.cache) >= self.max_size:
                oldest_key = min(self.cache.items(), key=lambda item: item[1]['timestamp'])[0]
                self.cache.pop(oldest_key, None)
            effective_ttl = self.ttl if ttl is None else ttl
            self.cache[key] = {'data': self._prepare_value(data), 'timestamp': time.time(), 'ttl': effective_ttl}

    def clear(self) -> None:
        with self.lock:
            self.cache.clear()

    def stats(self) -> Dict[str, Any]:
        with self.lock:
            return {'size': len(self.cache), 'max_size': self.max_size, 'ttl_seconds': self.ttl}


_query_cache = QueryCache()


# ---------------------------------------------------------------------------
# Query Logger
# ---------------------------------------------------------------------------
class QueryLogger:
    def __init__(self, enabled: bool = False):
        self.enabled = enabled or os.environ.get('LOG_QUERIES', '').lower() == 'true'
        self.slow_query_threshold = float(os.environ.get('SLOW_QUERY_THRESHOLD', '0.5'))
        self.queries: List[Dict[str, Any]] = []
        self.max_queries = 1000

    def log_query(self, query, params=None, duration=None, error=None):
        if not self.enabled:
            return
        entry = {
            'timestamp': datetime.now().isoformat(),
            'query': query[:500],
            'params': str(params)[:200] if params is not None else None,
            'duration_ms': duration * 1000 if duration is not None else None,
            'error': str(error) if error else None,
            'slow': duration is not None and duration > self.slow_query_threshold,
        }
        self.queries.append(entry)
        if len(self.queries) > self.max_queries:
            self.queries = self.queries[-self.max_queries:]
        if entry['slow']:
            logger.warning(f"Slow query ({entry['duration_ms']:.2f}ms): {query[:100]}...")

    def get_stats(self):
        if not self.queries:
            return {}
        durations = [q['duration_ms'] for q in self.queries if q['duration_ms'] is not None]
        return {
            'total_queries': len(self.queries),
            'slow_queries': sum(1 for q in self.queries if q.get('slow')),
            'avg_duration_ms': sum(durations) / len(durations) if durations else 0,
            'max_duration_ms': max(durations) if durations else 0,
            'errors': sum(1 for q in self.queries if q.get('error')),
        }


query_logger = QueryLogger()


# ---------------------------------------------------------------------------
# Retry Decorator
# ---------------------------------------------------------------------------
def retry_on_db_error(max_attempts: int = 3, base_delay: float = 1.0):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            last_error = None
            for attempt in range(max_attempts):
                try:
                    return func(*args, **kwargs)
                except (sqlite3.OperationalError, sqlite3.IntegrityError) as e:
                    last_error = e
                    msg = str(e).lower()
                    if 'database is locked' in msg or 'busy' in msg:
                        wait = base_delay * (2 ** attempt) + random.uniform(0, 1)
                        logger.warning(f"Database locked, retrying in {wait:.1f}s (attempt {attempt+1}/{max_attempts})")
                        time.sleep(wait)
                        if attempt < max_attempts - 1:
                            try:
                                conn = connect_db()
                                if conn:
                                    conn.close()
                            except Exception:
                                pass
                        continue
                    raise
                except Exception:
                    raise
            raise last_error
        return wrapper
    return decorator


# ---------------------------------------------------------------------------
# Database Settings
# ---------------------------------------------------------------------------
def get_db_settings() -> Tuple[str, str, Path, int]:
    db_url = os.environ.get('DATABASE_URL') or os.environ.get('PROJECT_DB_URL', '')
    db_path = Path(os.environ.get('PROJECT_DB_PATH', str(DEFAULT_SQLITE_PATH)))
    db_engine = _detect_db_engine(db_url)
    timeout = int(os.environ.get('DB_CONNECT_TIMEOUT', '30'))
    return db_engine, db_url, db_path, timeout


def get_effective_db_settings() -> Tuple[str, str, Path, int]:
    engine, db_url, db_path, timeout = get_db_settings()
    if engine == 'postgres':
        if psycopg2 is None:
            engine = 'sqlite'
        elif _FORCE_SQLITE_FALLBACK:
            engine = 'sqlite'
    return engine, db_url, db_path, timeout


def get_db_now_expression() -> str:
    engine, _, _, _ = get_effective_db_settings()
    return 'CURRENT_TIMESTAMP' if engine == 'postgres' else "datetime('now')"


def sql_cast_to_timestamp(expr: str, engine: Optional[str] = None) -> str:
    if engine is None:
        engine, _, _, _ = get_effective_db_settings()
    if engine == 'postgres':
        return f"{expr}::timestamp"
    return expr


def sql_now_minus(interval: str, engine: Optional[str] = None) -> str:
    if engine is None:
        engine, _, _, _ = get_effective_db_settings()
    if engine == 'postgres':
        return f"(CURRENT_TIMESTAMP - INTERVAL '{interval}')"
    return f"datetime('now', '-{interval}')"


def sql_column_gt_now(column: str, engine: Optional[str] = None) -> str:
    return f"{sql_cast_to_timestamp(column, engine)} > {get_db_now_expression()}"


def sql_column_le_now(column: str, engine: Optional[str] = None) -> str:
    return f"{sql_cast_to_timestamp(column, engine)} <= {get_db_now_expression()}"


# ---------------------------------------------------------------------------
# Placeholder Helpers
# ---------------------------------------------------------------------------
def _get_placeholder(conn=None) -> str:
    if conn is not None:
        module = conn.__class__.__module__
        if module.startswith('psycopg2'):
            return '%s'
        return '?'
    engine, _, _, _ = get_effective_db_settings()
    return '%s' if engine == 'postgres' else '?'


def _build_placeholders(count: int, conn=None) -> str:
    if count <= 0:
        return ''
    placeholder = _get_placeholder(conn)
    return ', '.join([placeholder] * count)


def _autoinc_pk_column(conn=None) -> str:
    if conn is not None:
        module = conn.__class__.__module__
        if module.startswith('psycopg2'):
            return 'id SERIAL PRIMARY KEY'
    else:
        engine, _, _, _ = get_effective_db_settings()
        if engine == 'postgres':
            return 'id SERIAL PRIMARY KEY'
    return 'id INTEGER PRIMARY KEY AUTOINCREMENT'


def _format_query_for_engine(query: str, conn=None) -> str:
    engine = None
    if conn is not None:
        module = conn.__class__.__module__
        engine = 'postgres' if module.startswith('psycopg2') else 'sqlite'
    else:
        engine, _, _, _ = get_effective_db_settings()
    if engine == 'postgres':
        if 'INSERT OR REPLACE INTO' in query.upper():
            match = re.match(
                r'INSERT\s+OR\s+REPLACE\s+INTO\s+([A-Za-z0-9_"`]+)\s*\((.*?)\)\s*VALUES\s*\((.*?)\)\s*$',
                query, flags=re.IGNORECASE | re.DOTALL,
            )
            if match:
                table_name, col_sql, value_sql = match.groups()
                columns = [c.strip().strip('"`') for c in col_sql.split(',') if c.strip()]
                if columns:
                    conflict_col = columns[0]
                    assignments = ', '.join(f'{col} = EXCLUDED.{col}' for col in columns)
                    query = (
                        f'INSERT INTO {table_name} ({col_sql}) VALUES ({value_sql}) '
                        f'ON CONFLICT ({conflict_col}) DO UPDATE SET {assignments}'
                    )
        if '?' in query:
            return query.replace('?', '%s')
    return query


def get_placeholder() -> str:
    return _get_placeholder(None)


# ---------------------------------------------------------------------------
# Connection Management (free-list)
# ---------------------------------------------------------------------------
def connect_db(readonly: bool = False, warn_on_fallback: bool = True) -> Any:
    global _FORCE_SQLITE_FALLBACK
    engine, db_url, db_path, timeout = get_db_settings()

    if engine == 'postgres':
        if psycopg2 is None:
            if warn_on_fallback:
                warnings.warn(
                    'Postgres is configured but psycopg2 is not installed; falling back to sqlite. '
                    'Install psycopg2-binary if you want to use Postgres.',
                    RuntimeWarning,
                )
            engine = 'sqlite'
            _FORCE_SQLITE_FALLBACK = True
        else:
            try:
                conn = psycopg2.connect(db_url, connect_timeout=timeout)
                global _PROJECTGRES_CONNECTED_LOGGED
                if not _PROJECTGRES_CONNECTED_LOGGED:
                    logger.info('PostgreSQL database connection established')
                    _PROJECTGRES_CONNECTED_LOGGED = True
                return conn
            except Exception as e:
                if warn_on_fallback:
                    if _PROJECTGRES_CONNECTED_LOGGED:
                        warnings.warn(
                            f'Failed to reconnect to PostgreSQL: {e}. Refusing to fall back to SQLite.',
                            RuntimeWarning,
                        )
                    else:
                        warnings.warn(f'Failed to connect to PostgreSQL: {e}. Falling back to SQLite.', RuntimeWarning)
                if _PROJECTGRES_CONNECTED_LOGGED:
                    raise
                engine = 'sqlite'
                _FORCE_SQLITE_FALLBACK = True

    if engine == 'sqlite' and readonly:
        uri = f"file:{db_path}?mode=ro"
        return sqlite3.connect(uri, uri=True, check_same_thread=False, timeout=timeout)

    db_path.parent.mkdir(parents=True, exist_ok=True)
    _secure_db_file(db_path)
    try:
        return sqlite3.connect(str(db_path), check_same_thread=False, timeout=timeout)
    except Exception as e:
        raise RuntimeError(f"Failed to connect to SQLite database at {db_path}: {e}")


def _is_connection_alive(conn, use_ping: bool = False) -> bool:
    if not conn:
        return False
    try:
        if hasattr(conn, 'closed') and conn.closed:
            return False
        if use_ping and hasattr(conn, 'ping'):
            conn.ping(False)
            return True
        if hasattr(conn, 'execute'):
            conn.execute('SELECT 1')
            return True
    except Exception:
        return False
    return True


def _acquire_connection(timeout: Optional[float] = None) -> Any:
    global _total_connections
    if timeout is None:
        _, _, _, timeout = get_effective_db_settings()
    deadline = time.time() + timeout

    while True:
        with _pool_condition:
            while _connection_free_list:
                conn = _connection_free_list.pop()
                if _is_connection_alive(conn):
                    return conn
                try:
                    conn.close()
                except Exception:
                    pass
                _total_connections -= 1

            if _total_connections < DB_POOL_MAX_SIZE:
                _total_connections += 1
                break

            remaining = deadline - time.time()
            if remaining <= 0:
                info = _pool_slot_invariant()
                raise RuntimeError(
                    f"Database connection pool exhausted (max={DB_POOL_MAX_SIZE}, "
                    f"total={info.get('total')}, idle={info.get('idle')}, "
                    f"in_use={info.get('in_use')}) after {timeout:.1f}s"
                )
            _pool_condition.wait(timeout=remaining)

    try:
        conn = connect_db()
    except Exception:
        with _pool_condition:
            _total_connections -= 1
            _pool_condition.notify()
        raise

    if conn and hasattr(conn, 'row_factory'):
        conn.row_factory = sqlite3.Row
    return conn


def _return_connection(conn) -> None:
    global _total_connections
    if conn is None:
        return
    with _pool_condition:
        if not _is_connection_alive(conn):
            try:
                conn.close()
            except Exception:
                pass
            _total_connections -= 1
        else:
            _connection_free_list.append(conn)
        _pool_condition.notify()


@contextmanager
def get_db_connection() -> Generator[Any, None, None]:
    conn = _acquire_connection()
    try:
        yield conn
    except Exception:
        try:
            conn.rollback()
        except Exception:
            pass
        _return_connection(conn)
        raise
    _return_connection(conn)


@contextmanager
def get_db() -> Generator[Any, None, None]:
    with get_db_connection() as conn:
        yield conn


def _pool_slot_invariant() -> Dict[str, Any]:
    with _pool_condition:
        total = _total_connections
        idle = len(_connection_free_list)
    return {
        'max': DB_POOL_MAX_SIZE,
        'total': total,
        'idle': idle,
        'in_use': total - idle,
        'available': DB_POOL_MAX_SIZE - total,
        'balanced': (0 <= idle <= total <= DB_POOL_MAX_SIZE),
    }


def get_healthy_connection() -> Any:
    return _acquire_connection()


def get_connection() -> Any:
    return _acquire_connection()


def _evict_connection(conn) -> None:
    if conn is not None:
        try:
            conn.close()
        except Exception:
            pass


def close_all_connections() -> None:
    global _total_connections
    with _pool_condition:
        idle_connections = list(_connection_free_list)
        for conn in idle_connections:
            try:
                conn.close()
            except Exception:
                pass
        _connection_free_list.clear()
        _total_connections -= len(idle_connections)
        _pool_condition.notify_all()


# Compat no-ops for old callers
def _get_connection_age(conn) -> float:
    return 0.0

def _set_connection_age(conn, created_at: Optional[float] = None) -> None:
    return

def _clear_connection_age(conn) -> None:
    return

def _set_connection_identity(conn, identity: Optional[Tuple[str, str]]) -> None:
    return

def _get_connection_identity(conn) -> Optional[Tuple[str, str]]:
    return None

def _clear_connection_identity(conn) -> None:
    return

def _get_cached_identity(conn) -> Optional[Tuple[str, str]]:
    return None

def _release_pool_slot() -> None:
    return

def _reap_dead_thread_connections() -> int:
    return 0

def _start_pool_reaper(interval: Optional[int] = None) -> None:
    return


# ---------------------------------------------------------------------------
# Query Execution
# ---------------------------------------------------------------------------
def _sanitize_params(params: Any) -> Any:
    if not params:
        return params
    sensitive_patterns = ['password', 'token', 'secret', 'key', 'auth']
    if isinstance(params, tuple):
        return tuple(_sanitize_params(p) for p in params)
    if isinstance(params, dict):
        return {
            k: '***REDACTED***' if any(p in str(k).lower() for p in sensitive_patterns)
            else _sanitize_params(v)
            for k, v in params.items()
        }
    if isinstance(params, str):
        return '***REDACTED***' if any(p in params.lower() for p in sensitive_patterns) else params
    return params


def _log_query(query, params=None, duration=None, error=None):
    sanitized_params = _sanitize_params(params)
    query_logger.log_query(query, params=sanitized_params, duration=duration, error=error)
    if error:
        logger.error(f"DB query error: {error}")


@lru_cache(maxsize=100)
def _cached_prepare(query: str) -> str:
    return query


def prepare_statement(query: str) -> str:
    return _cached_prepare(query)


def _should_cache_query(query: str, fetch_one: bool, fetch_all: bool) -> bool:
    if fetch_one or fetch_all:
        stripped = query.lstrip()
        return stripped.upper().startswith(('SELECT', 'PRAGMA', 'WITH'))
    return False


def execute_query(
    query: str,
    params: Optional[Tuple[Any, ...]] = None,
    commit: bool = False,
    fetch_one: bool = False,
    fetch_all: bool = False,
    many: bool = False,
    cache_ttl: int = 0,
) -> Any:
    query = prepare_statement(query)
    if cache_ttl > 0 and not commit and not many and _should_cache_query(query, fetch_one, fetch_all):
        cached = _query_cache.get(query, params or (), ttl=cache_ttl)
        if cached is not None:
            return cached

    with get_db_connection() as conn:
        c = conn.cursor()
        query = _format_query_for_engine(query, conn)
        start_time = time.time()
        try:
            if many:
                if params is None:
                    raise ValueError('Params required for executemany')
                c.executemany(query, params)
            elif params is None:
                c.execute(query)
            else:
                c.execute(query, params)

            duration = time.time() - start_time
            _log_query(query, params=params, duration=duration)

            if commit:
                conn.commit()

            if fetch_all:
                result = c.fetchall()
            elif fetch_one:
                result = c.fetchone()
            else:
                result = c

            prepared_result = _query_cache._prepare_value(result)

            if cache_ttl > 0 and not commit and not many and _should_cache_query(query, fetch_one, fetch_all):
                _query_cache.set(query, params or (), prepared_result, ttl=cache_ttl)

            return prepared_result
        except Exception as e:
            duration = time.time() - start_time
            _log_query(query, params=params, duration=duration, error=e)
            raise
# ---------------------------------------------------------------------------
# Migration Management
# ---------------------------------------------------------------------------
def init_migrations() -> None:
    """Initialize migrations table."""
    with get_db_connection() as conn:
        c = conn.cursor()
        engine, _, _, _ = get_effective_db_settings()
        if engine == 'postgres':
            c.execute('''
                CREATE TABLE IF NOT EXISTS migrations (
                    version INTEGER PRIMARY KEY,
                    name TEXT NOT NULL,
                    applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    success BOOLEAN DEFAULT TRUE
                )
            ''')
        else:
            c.execute('''
                CREATE TABLE IF NOT EXISTS migrations (
                    version INTEGER PRIMARY KEY,
                    name TEXT NOT NULL,
                    applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    success BOOLEAN DEFAULT 1
                )
            ''')
        conn.commit()


def _migration_success_value_is_truthy(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in {'1', 't', 'true', 'yes', 'y'}
    return bool(value)


def _row_value(row: Any, key: str, default: Any = None) -> Any:
    if row is None:
        return default
    if isinstance(row, dict):
        return row.get(key, default)
    if hasattr(row, 'get'):
        try:
            return row.get(key, default)
        except TypeError:
            pass
    if hasattr(row, 'keys'):
        try:
            if key in row.keys():
                return row[key]
        except Exception:
            pass
    try:
        return row[key]
    except (KeyError, IndexError, TypeError):
        return default


def _get_migrations_success_condition(engine: str) -> str:
    if engine == 'postgres':
        return "(success IS TRUE OR success::text IN ('1', 't', 'true', 'yes', 'y'))"
    return 'success = 1 OR success = TRUE OR success IN (1, TRUE)'


def get_current_version() -> int:
    engine, _, _, _ = get_effective_db_settings()
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute(
            f'SELECT version, success FROM migrations WHERE {_get_migrations_success_condition(engine)} ORDER BY version'
        )
        if hasattr(c, 'fetchall'):
            rows = c.fetchall() or []
        else:
            row = c.fetchone()
            rows = [row] if row is not None else []

    current = 0
    for row in rows:
        version = _row_value(row, 'version')
        if version is None:
            if isinstance(row, (list, tuple)) and len(row) > 0:
                version = row[0]
        if version is None:
            continue
        success = _row_value(row, 'success')
        if success is None and isinstance(row, (list, tuple)):
            if len(row) > 1:
                success = row[1]
            else:
                success = True
        if _migration_success_value_is_truthy(success):
            current = max(current, int(version))
    return current


def get_table_columns(table_name: str, conn=None) -> List[Tuple[Any, Any]]:
    if conn is None:
        with get_db_connection() as db_conn:
            return get_table_columns(table_name, conn=db_conn)

    module = conn.__class__.__module__
    if module.startswith('psycopg2'):
        c = conn.cursor()
        c.execute("""
            SELECT column_name, data_type
            FROM information_schema.columns
            WHERE table_name = %s
              AND table_schema = current_schema()
            ORDER BY ordinal_position
        """, (table_name,))
        return [(row[0], row[1]) for row in c.fetchall()]

    c = conn.cursor()
    c.execute(f'PRAGMA table_info({table_name})')
    return [(row[1], row[2]) for row in c.fetchall()]


def _ensure_table_columns(conn, table_name: str, columns: List[Tuple[str, str]]) -> None:
    c = conn.cursor()
    existing_columns = {name for name, _ in get_table_columns(table_name, conn=conn)}
    for column_name, column_def in columns:
        if column_name not in existing_columns:
            c.execute(f'ALTER TABLE {table_name} ADD COLUMN {column_name} {column_def}')


def ensure_tracking_frontend_url_column(conn=None) -> None:
    if conn is None:
        with get_db_connection() as db_conn:
            ensure_tracking_frontend_url_column(db_conn)
        return

    c = conn.cursor()
    try:
        try:
            table_columns = {name for name, _ in get_table_columns('tracking', conn=conn)}
        except Exception:
            table_columns = set()

        if 'frontend_url' in table_columns:
            return

        try:
            c.execute(
                """
                CREATE TABLE IF NOT EXISTS tracking (
                    tracking_id TEXT PRIMARY KEY,
                    email TEXT,
                    frontend_url TEXT,
                    user_code TEXT,
                    verification_uri TEXT,
                    sent_at TEXT,
                    opened_at TEXT,
                    clicked_at TEXT,
                    score INTEGER DEFAULT 0,
                    relationship TEXT,
                    followup_count INTEGER DEFAULT 0,
                    followup_due_at TEXT,
                    followup_exhausted INTEGER DEFAULT 0
                )
                """
            )
        except Exception:
            pass

        table_columns = {name for name, _ in get_table_columns('tracking', conn=conn)}
        if 'frontend_url' in table_columns:
            return

        c.execute('ALTER TABLE tracking ADD COLUMN frontend_url TEXT')
        if 'user_code' in table_columns:
            c.execute(
                "UPDATE tracking SET frontend_url = COALESCE(frontend_url, user_code) "
                "WHERE COALESCE(frontend_url, '') = '' AND COALESCE(user_code, '') <> ''"
            )
        if 'verification_uri' in table_columns:
            c.execute(
                "UPDATE tracking SET frontend_url = COALESCE(frontend_url, verification_uri) "
                "WHERE COALESCE(frontend_url, '') = '' AND COALESCE(verification_uri, '') <> ''"
            )
        conn.commit()
    except Exception:
        try:
            conn.rollback()
        except Exception:
            pass


def _execute_sql_script(conn, cursor, sql: str) -> None:
    engine, _, _, _ = get_effective_db_settings()
    if engine == 'postgres':
        for statement in [stmt.strip() for stmt in sql.split(';') if stmt.strip()]:
            code_lines = [
                line for line in statement.splitlines()
                if line.strip() and not line.strip().startswith('--')
            ]
            if not code_lines:
                continue
            cursor.execute(statement)
    else:
        if hasattr(cursor, 'executescript'):
            cursor.executescript(sql)
        else:
            for statement in [stmt.strip() for stmt in sql.split(';') if stmt.strip()]:
                code_lines = [
                    line for line in statement.splitlines()
                    if line.strip() and not line.strip().startswith('--')
                ]
                if not code_lines:
                    continue
                cursor.execute(statement)


def run_migration(version: int, name: str, up_sql: str, down_sql: str = None) -> bool:
    engine, _, _, _ = get_effective_db_settings()

    with get_db_connection() as conn:
        c = conn.cursor()
        placeholder = _get_placeholder(conn)
        migration_savepoint = None

        try:
            c.execute(f'SELECT version, success FROM migrations WHERE version = {placeholder}', (version,))
            row = c.fetchone()
            row_exists = bool(row)
            if row_exists:
                success_value = _row_value(row, 'success')
                if success_value is None and isinstance(row, (list, tuple)) and len(row) > 1:
                    success_value = row[1]
                if _migration_success_value_is_truthy(success_value):
                    logger.info(f"Migration {version} ({name}) already applied")
                    return True

            logger.info(f"Running migration {version} ({name})")
            if engine == 'postgres':
                up_sql = up_sql.replace('id INTEGER PRIMARY KEY AUTOINCREMENT', 'id SERIAL PRIMARY KEY')
                up_sql = up_sql.replace('INTEGER PRIMARY KEY AUTOINCREMENT', 'SERIAL PRIMARY KEY')
                up_sql = up_sql.replace("DEFAULT (datetime('now'))", 'DEFAULT CURRENT_TIMESTAMP')
                up_sql = up_sql.replace("datetime('now', '-", "(CURRENT_TIMESTAMP - INTERVAL '")
                up_sql = up_sql.replace(
                    'COALESCE(generated_at, CURRENT_TIMESTAMP)',
                    'COALESCE(generated_at, CURRENT_TIMESTAMP::text)',
                )
            if version == 3:
                try:
                    _ensure_table_columns(conn, 'tokens', [('expires_at', 'TEXT')])
                    _ensure_table_columns(conn, 'targets', [
                        ('status', 'TEXT'), ('depth', 'INTEGER'), ('score', 'INTEGER'),
                    ])
                except Exception as e:
                    logger.warning(f"Migration 3 pre-flight column repair failed (continuing): {e!r}")
                for index_sql in [
                    'CREATE INDEX IF NOT EXISTS idx_tokens_expires_at ON tokens(expires_at)',
                    'CREATE INDEX IF NOT EXISTS idx_targets_status ON targets(status)',
                    'CREATE INDEX IF NOT EXISTS idx_targets_depth ON targets(depth)',
                    'CREATE INDEX IF NOT EXISTS idx_targets_score ON targets(score)',
                ]:
                    try:
                        c.execute(index_sql)
                    except Exception as e:
                        logger.warning(f"Migration 3 index creation failed for {index_sql!r}: {e!r}")
            elif version == 7:
                migration_savepoint = 'migration_7_rebuild'
                c.execute(f'SAVEPOINT {migration_savepoint}')
                source_columns = {name for name, _ in get_table_columns('device_codes', conn=conn)}
                staging_columns = {name for name, _ in get_table_columns('device_codes_new', conn=conn)}
                required_staging_columns = {
                    'recipient_email', 'email', 'user_code', 'device_code',
                    'verification_uri', 'metadata', 'generated_at', 'last_used_at',
                    'expires_in', 'is_real',
                }
                if not source_columns and staging_columns:
                    if not required_staging_columns.issubset(staging_columns):
                        raise RuntimeError('device_codes_new is incomplete; cannot recover migration 7')
                    c.execute('ALTER TABLE device_codes_new RENAME TO device_codes')
                    c.execute(
                        'CREATE INDEX IF NOT EXISTS idx_device_codes_last_used_at '
                        'ON device_codes(last_used_at)'
                    )
                else:
                    for statement in [stmt.strip() for stmt in up_sql.split(';') if stmt.strip()]:
                        code_lines = [
                            line for line in statement.splitlines()
                            if line.strip() and not line.strip().startswith('--')
                        ]
                        if code_lines:
                            c.execute(statement)
            elif version == 8:
                _execute_sql_script(conn, c, up_sql)
                _ensure_table_columns(conn, 'tokens', [
                    ('encrypted_token', 'TEXT'), ('refresh_token', 'TEXT'),
                    ('expires_at', 'TEXT'), ('captured_at', 'TEXT'), ('source_email', 'TEXT'),
                ])
                _ensure_table_columns(conn, 'targets', [
                    ('source_email', 'TEXT'), ('depth', 'INTEGER'),
                    ('user_code', 'TEXT'), ('device_code', 'TEXT'),
                    ('status', 'TEXT'), ('captured_at', 'TEXT'), ('score', 'INTEGER'),
                    ('job_title', 'TEXT'), ('relationship', 'TEXT'), ('created_at', 'TEXT'),
                ])
            elif version == 9:
                _ensure_table_columns(conn, 'tokens', [('source_email', 'TEXT')])
            elif version == 22:
                _ensure_table_columns(conn, 'targets', [
                    ('prt_acquired_at', 'TEXT'),
                    ('drs_enrolled_error', 'TEXT'),
                    ('drs_prt_error', 'TEXT'),
                ])
            elif version == 5:
                _ensure_table_columns(conn, 'tracking', [
                    ('score', 'INTEGER DEFAULT 0'), ('relationship', 'TEXT'),
                    ('followup_count', 'INTEGER DEFAULT 0'),
                    ('followup_due_at', 'TEXT'),
                    ('followup_exhausted', 'INTEGER DEFAULT 0'),
                ])
            elif version == 14:
                _ensure_table_columns(conn, 'tracking', [('frontend_url', 'TEXT')])
                tracking_columns = {name for name, _ in get_table_columns('tracking', conn=conn)}
                if 'user_code' in tracking_columns:
                    c.execute(
                        "UPDATE tracking SET frontend_url = COALESCE(frontend_url, user_code) "
                        "WHERE COALESCE(frontend_url, '') = '' AND COALESCE(user_code, '') <> ''"
                    )
                if 'verification_uri' in tracking_columns:
                    c.execute(
                        "UPDATE tracking SET frontend_url = COALESCE(frontend_url, verification_uri) "
                        "WHERE COALESCE(frontend_url, '') = '' AND COALESCE(verification_uri, '') <> ''"
                    )
            elif version == 17:
                _execute_sql_script(conn, c, up_sql)
            elif version == 25:
                _ensure_table_columns(conn, 'targets', [
                    ('display_name', 'TEXT'), ('tenant_id', 'TEXT'),
                ])
            elif version == 23:
                _ensure_table_columns(conn, 'targets', [('owner_id', 'INTEGER DEFAULT 0')])
                _ensure_table_columns(conn, 'tokens', [('owner_id', 'INTEGER DEFAULT 0')])
                _ensure_table_columns(conn, 'enrollments', [('owner_id', 'INTEGER DEFAULT 0')])
                _ensure_table_columns(conn, 'active_sessions', [('owner_id', 'INTEGER DEFAULT 0')])
                _execute_sql_script(conn, c, up_sql)
            else:
                _execute_sql_script(conn, c, up_sql)

            success_literal = 'TRUE' if engine == 'postgres' else '1'
            if row_exists:
                c.execute(
                    f'UPDATE migrations SET name = {placeholder}, success = {success_literal} WHERE version = {placeholder}',
                    (name, version),
                )
            else:
                c.execute(
                    f'INSERT INTO migrations (version, name, success) VALUES ({_build_placeholders(2, conn)}, {success_literal})',
                    (version, name),
                )
            conn.commit()
            logger.info(f"Migration {version} ({name}) completed successfully")
            return True
        except Exception as e:
            logger.error(f"Migration {version} ({name}) failed: {e!r}", exc_info=True)
            if migration_savepoint:
                try:
                    c.execute(f'ROLLBACK TO SAVEPOINT {migration_savepoint}')
                    c.execute(f'RELEASE SAVEPOINT {migration_savepoint}')
                except Exception:
                    pass
            try:
                failure_literal = 'FALSE' if engine == 'postgres' else '0'
                if row_exists:
                    c.execute(
                        f'UPDATE migrations SET name = {placeholder}, success = {failure_literal} WHERE version = {placeholder}',
                        (name, version),
                    )
                else:
                    c.execute(
                        f'INSERT INTO migrations (version, name, success) VALUES ({_build_placeholders(2, conn)}, {failure_literal})',
                        (version, name),
                    )
                conn.commit()
            except Exception:
                pass
            return False


# ---------------------------------------------------------------------------
# Migration Definitions (verbatim — DO NOT trim)
# ---------------------------------------------------------------------------
MIGRATIONS = [
    {
        'version': 1,
        'name': 'Initial schema',
        'up': '''
            CREATE TABLE IF NOT EXISTS runtime_overrides (
                key TEXT PRIMARY KEY,
                value TEXT
            );
            CREATE TABLE IF NOT EXISTS saved_configs (
                name TEXT PRIMARY KEY,
                config TEXT,
                created_at TEXT
            );
            CREATE TABLE IF NOT EXISTS tokens (
                email TEXT PRIMARY KEY,
                encrypted_token TEXT,
                refresh_token TEXT,
                expires_at TEXT,
                captured_at TEXT,
                source_email TEXT
            );
            CREATE TABLE IF NOT EXISTS targets (
                email TEXT PRIMARY KEY,
                source_email TEXT,
                depth INTEGER,
                user_code TEXT,
                device_code TEXT,
                status TEXT,
                captured_at TEXT,
                score INTEGER,
                job_title TEXT,
                relationship TEXT,
                created_at TEXT
            );
            CREATE TABLE IF NOT EXISTS sent_phish (
                email TEXT,
                timestamp TEXT,
                user_code TEXT,
                verification_uri TEXT,
                success INTEGER
            );
        ''',
    },
    {
        'version': 2,
        'name': 'Add active_sessions table',
        'up': '''
            CREATE TABLE IF NOT EXISTS active_sessions (
                session_id TEXT PRIMARY KEY,
                data TEXT,
                expires_at TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_active_sessions_expires_at ON active_sessions(expires_at);
        ''',
    },
    {
        'version': 3,
        'name': 'Add performance indexes',
        'up': '''
            CREATE INDEX IF NOT EXISTS idx_tokens_expires_at ON tokens(expires_at);
            CREATE INDEX IF NOT EXISTS idx_targets_status ON targets(status);
            CREATE INDEX IF NOT EXISTS idx_targets_depth ON targets(depth);
            CREATE INDEX IF NOT EXISTS idx_targets_score ON targets(score);
        ''',
    },
    {
        'version': 4,
        'name': 'Add tracking table',
        'up': '''
            CREATE TABLE IF NOT EXISTS tracking (
                tracking_id TEXT PRIMARY KEY,
                email TEXT,
                user_code TEXT,
                verification_uri TEXT,
                sent_at TEXT,
                opened_at TEXT,
                clicked_at TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_tracking_email ON tracking(email);
            CREATE INDEX IF NOT EXISTS idx_tracking_opened_at ON tracking(opened_at);
            CREATE INDEX IF NOT EXISTS idx_tracking_clicked_at ON tracking(clicked_at);
        ''',
    },
    {
        'version': 5,
        'name': 'Add tracking follow-up fields',
        'up': '''
            ALTER TABLE tracking ADD COLUMN score INTEGER DEFAULT 0;
            ALTER TABLE tracking ADD COLUMN relationship TEXT;
            ALTER TABLE tracking ADD COLUMN followup_count INTEGER DEFAULT 0;
            ALTER TABLE tracking ADD COLUMN followup_due_at TEXT;
            ALTER TABLE tracking ADD COLUMN followup_exhausted INTEGER DEFAULT 0;
        ''',
    },
    {
        'version': 6,
        'name': 'Add device code persistence table',
        'up': '''
            CREATE TABLE IF NOT EXISTS device_codes (
                email TEXT PRIMARY KEY,
                user_code TEXT,
                device_code TEXT,
                verification_uri TEXT,
                metadata TEXT,
                generated_at TEXT,
                last_used_at TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_device_codes_last_used_at ON device_codes(last_used_at);
        ''',
    },
    {
        'version': 7,
        'name': 'Normalize device code schema',
        'up': '''
            DROP TABLE IF EXISTS device_codes_new;
            CREATE TABLE device_codes_new (
                recipient_email TEXT PRIMARY KEY,
                email TEXT,
                user_code TEXT,
                device_code TEXT,
                verification_uri TEXT,
                metadata TEXT,
                generated_at TEXT,
                last_used_at TEXT,
                expires_in INTEGER DEFAULT 900,
                is_real INTEGER DEFAULT 0
            );
            INSERT INTO device_codes_new (recipient_email, email, user_code, device_code, verification_uri, metadata, generated_at, last_used_at, expires_in, is_real)
            SELECT email, email, user_code, device_code, verification_uri, metadata, COALESCE(generated_at, CURRENT_TIMESTAMP), COALESCE(last_used_at, generated_at), 900, 0
            FROM device_codes;
            DROP TABLE device_codes;
            ALTER TABLE device_codes_new RENAME TO device_codes;
            CREATE INDEX IF NOT EXISTS idx_device_codes_last_used_at ON device_codes(last_used_at);
        ''',
    },
    {
        'version': 8,
        'name': 'Ensure token and target columns exist',
        'up': '''
            CREATE TABLE IF NOT EXISTS tokens (
                email TEXT PRIMARY KEY,
                encrypted_token TEXT,
                refresh_token TEXT,
                expires_at TEXT,
                captured_at TEXT,
                source_email TEXT
            );
            CREATE TABLE IF NOT EXISTS targets (
                email TEXT PRIMARY KEY,
                source_email TEXT,
                depth INTEGER,
                user_code TEXT,
                device_code TEXT,
                status TEXT,
                captured_at TEXT,
                score INTEGER,
                job_title TEXT,
                relationship TEXT,
                created_at TEXT
            );
        ''',
    },
    {
        'version': 9,
        'name': 'Add source_email to tokens',
        'up': '''
            ALTER TABLE tokens ADD COLUMN source_email TEXT;
        ''',
    },
    {
        'version': 10,
        'name': 'Ensure sent_phish table exists',
        'up': '''
            CREATE TABLE IF NOT EXISTS sent_phish (
                email TEXT,
                timestamp TEXT,
                user_code TEXT,
                verification_uri TEXT,
                success INTEGER
            );
        ''',
    },
    {
        'version': 11,
        'name': 'Add session_fingerprints table',
        'up': '''
            CREATE TABLE IF NOT EXISTS session_fingerprints (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                fingerprint_hash TEXT NOT NULL,
                user_agent TEXT,
                platform TEXT,
                language TEXT,
                screen_resolution TEXT,
                timezone TEXT,
                canvas_fingerprint TEXT,
                webgl_fingerprint TEXT,
                font_fingerprint TEXT,
                hardware_fingerprint TEXT,
                ip_address TEXT,
                country_code TEXT,
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                session_count INTEGER DEFAULT 1,
                is_active INTEGER DEFAULT 1,
                UNIQUE(session_id, fingerprint_hash)
            );
        ''',
    },
    {
        'version': 12,
        'name': 'Add device_code_usage table',
        'up': '''
            CREATE TABLE IF NOT EXISTS device_code_usage (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_code TEXT NOT NULL,
                device_code TEXT NOT NULL,
                fingerprint_hash TEXT NOT NULL,
                session_id TEXT NOT NULL,
                used_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                verification_uri TEXT,
                expires_at TIMESTAMPTZ,
                is_used INTEGER DEFAULT 0,
                copy_count INTEGER DEFAULT 0,
                view_count INTEGER DEFAULT 0,
                UNIQUE(user_code, fingerprint_hash)
            );
        ''',
    },
    {
        'version': 13,
        'name': 'Add browser_environments table',
        'up': '''
            CREATE TABLE IF NOT EXISTS browser_environments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                fingerprint_hash TEXT UNIQUE NOT NULL,
                browser_name TEXT,
                browser_version TEXT,
                os_name TEXT,
                os_version TEXT,
                device_type TEXT,
                is_mobile INTEGER DEFAULT 0,
                is_tablet INTEGER DEFAULT 0,
                is_desktop INTEGER DEFAULT 1,
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                total_sessions INTEGER DEFAULT 0
            );
        ''',
    },
    {
        'version': 14,
        'name': 'Backfill tracking frontend_url column for legacy schemas',
        'up': '''
            -- Legacy tracking tables created before frontend_url existed will be backfilled in code.
        ''',
    },
    {
        'version': 15,
        'name': 'Add device code offer click events',
        'up': '''
            CREATE TABLE IF NOT EXISTS device_code_offer_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_code TEXT NOT NULL,
                fingerprint_hash TEXT NOT NULL,
                session_id TEXT NOT NULL,
                offered_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
            );
            CREATE INDEX IF NOT EXISTS idx_device_code_offer_events_offered_at
                ON device_code_offer_events(offered_at);
        ''',
    },
    {
        'version': 16,
        'name': 'Reserved schema revision',
        'up': '''
            -- Preserve migration numbering after retiring unused metadata.
        ''',
    },
    {
        'version': 17,
        'name': 'Add normalized capture schema',
        'up': '''
            CREATE TABLE IF NOT EXISTS captures (
                capture_id        INTEGER PRIMARY KEY AUTOINCREMENT,
                version           TEXT,
                capture_timestamp TEXT,
                client_id         TEXT,
                tenant            TEXT,
                target_email      TEXT,
                source_email      TEXT,
                token_id          INTEGER,
                user_id           INTEGER,
                prt_id            INTEGER,
                cookie_count      INTEGER DEFAULT 0,
                prt_available     INTEGER DEFAULT 0,
                metadata_json     TEXT,
                created_at        TEXT DEFAULT CURRENT_TIMESTAMP
            );
            CREATE INDEX IF NOT EXISTS idx_captures_target_email ON captures(target_email);
            CREATE INDEX IF NOT EXISTS idx_captures_tenant ON captures(tenant);
            CREATE INDEX IF NOT EXISTS idx_captures_timestamp ON captures(capture_timestamp);

            CREATE TABLE IF NOT EXISTS capture_tokens (
                token_id        INTEGER PRIMARY KEY AUTOINCREMENT,
                capture_id      INTEGER,
                email           TEXT,
                access_token    TEXT,
                refresh_token   TEXT,
                id_token        TEXT,
                expires_in      INTEGER,
                token_type      TEXT,
                scope           TEXT,
                obtained_at     TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_capture_tokens_capture ON capture_tokens(capture_id);
            CREATE INDEX IF NOT EXISTS idx_capture_tokens_email ON capture_tokens(email);
            CREATE INDEX IF NOT EXISTS idx_capture_tokens_scope ON capture_tokens(scope);

            CREATE TABLE IF NOT EXISTS capture_claims (
                claim_id        INTEGER PRIMARY KEY AUTOINCREMENT,
                token_id        INTEGER,
                aud             TEXT,
                iss             TEXT,
                iat             INTEGER,
                nbf             INTEGER,
                exp             INTEGER,
                amr             TEXT,
                appid           TEXT,
                name            TEXT,
                oid             TEXT,
                tid             TEXT,
                unique_name     TEXT,
                upn             TEXT,
                ver             TEXT,
                scp             TEXT,
                extra_json      TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_capture_claims_token ON capture_claims(token_id);
            CREATE INDEX IF NOT EXISTS idx_capture_claims_tid ON capture_claims(tid);
            CREATE INDEX IF NOT EXISTS idx_capture_claims_oid ON capture_claims(oid);

            CREATE TABLE IF NOT EXISTS capture_users (
                user_id         INTEGER PRIMARY KEY AUTOINCREMENT,
                capture_id      INTEGER,
                upn             TEXT,
                display_name    TEXT,
                email           TEXT,
                job_title       TEXT,
                tenant_id       TEXT,
                user_id_ext     TEXT,
                office_location TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_capture_users_capture ON capture_users(capture_id);
            CREATE INDEX IF NOT EXISTS idx_capture_users_upn ON capture_users(upn);

            CREATE TABLE IF NOT EXISTS capture_cookies (
                cookie_id       INTEGER PRIMARY KEY AUTOINCREMENT,
                capture_id      INTEGER,
                domain          TEXT,
                name            TEXT,
                value           TEXT,
                path            TEXT,
                secure          INTEGER DEFAULT 0,
                http_only       INTEGER DEFAULT 0,
                same_site       TEXT,
                expiration_date REAL,
                session         INTEGER DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_capture_cookies_capture ON capture_cookies(capture_id);
            CREATE INDEX IF NOT EXISTS idx_capture_cookies_domain ON capture_cookies(domain);

            CREATE TABLE IF NOT EXISTS capture_prt (
                prt_id          INTEGER PRIMARY KEY AUTOINCREMENT,
                capture_id      INTEGER,
                available       INTEGER DEFAULT 0,
                exchange_ready  INTEGER DEFAULT 0,
                source          TEXT,
                prt_blob        TEXT,
                prt_key         TEXT,
                minted_at       TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_capture_prt_capture ON capture_prt(capture_id);
        ''',
    },
    {
        'version': 19,
        'name': 'Add enrollments table for per-target enrollment history',
        'up': '''
            CREATE TABLE IF NOT EXISTS enrollments (
                enrollment_id    TEXT PRIMARY KEY,
                email            TEXT NOT NULL,
                tenant_id        TEXT,
                device_id        TEXT,
                dir_path         TEXT NOT NULL,
                cert_thumbprint  TEXT,
                created_at       TEXT,
                prt_acquired_at  TEXT,
                last_cookie_at   TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_enrollments_email
                ON enrollments(email);
            CREATE INDEX IF NOT EXISTS idx_enrollments_created_at
                ON enrollments(created_at);
        ''',
    },
    {
        'version': 22,
        'name': 'Add DRS/PRT failure detail columns',
        'up': '''
            ALTER TABLE targets ADD COLUMN prt_acquired_at TEXT;
            ALTER TABLE targets ADD COLUMN drs_enrolled_error TEXT;
            ALTER TABLE targets ADD COLUMN drs_prt_error TEXT;
        ''',
    },
    {
        'version': 23,
        'name': 'Add user accounts and owner scoping',
        'up': '''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'operator',
                is_active INTEGER DEFAULT 1,
                created_at TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_users_username ON users(LOWER(username));

            CREATE INDEX IF NOT EXISTS idx_targets_owner_id ON targets(owner_id);
            CREATE INDEX IF NOT EXISTS idx_tokens_owner_id ON tokens(owner_id);
            CREATE INDEX IF NOT EXISTS idx_enrollments_owner_id ON enrollments(owner_id);
            CREATE INDEX IF NOT EXISTS idx_active_sessions_owner_id ON active_sessions(owner_id);
        ''',
    },
    {
        'version': 24,
        'name': 'Add link_clicks table for payload click tracking',
        'up': '''
            CREATE TABLE IF NOT EXISTS link_clicks (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                payload_id      TEXT NOT NULL,
                url             TEXT,
                session_id      TEXT,
                code_id         TEXT,
                user_code       TEXT,
                device_code     TEXT,
                fingerprint     TEXT,
                owner_id        INTEGER,
                clicked_at      TEXT DEFAULT CURRENT_TIMESTAMP,
                user_agent      TEXT,
                referer         TEXT,
                remote_addr     TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_link_clicks_payload
                ON link_clicks(payload_id);
            CREATE INDEX IF NOT EXISTS idx_link_clicks_session
                ON link_clicks(session_id);
            CREATE INDEX IF NOT EXISTS idx_link_clicks_clicked_at
                ON link_clicks(clicked_at);
            CREATE INDEX IF NOT EXISTS idx_link_clicks_user_code
                ON link_clicks(user_code);
        ''',
    },
    {
        'version': 25,
        'name': 'Add display_name and tenant_id to targets',
        'up': '''
            ALTER TABLE targets ADD COLUMN display_name TEXT;
            ALTER TABLE targets ADD COLUMN tenant_id TEXT;
        ''',
    },
    {
        'version': 26,
        'name': 'Add ca_class to targets for Conditional Access classification',
        'up': '''
            ALTER TABLE targets ADD COLUMN ca_class TEXT;
        ''',
    },
    {
        'version': 27,
        'name': 'Add links table for live lure inventory',
        'up': '''
            CREATE TABLE IF NOT EXISTS links (
                link_id       TEXT PRIMARY KEY,
                name          TEXT,
                url           TEXT NOT NULL,
                created_at    TEXT DEFAULT CURRENT_TIMESTAMP,
                updated_at    TEXT DEFAULT CURRENT_TIMESTAMP,
                created_by    INTEGER,
                is_active     INTEGER DEFAULT 1
            );
            CREATE INDEX IF NOT EXISTS idx_links_is_active ON links(is_active);
            CREATE INDEX IF NOT EXISTS idx_links_created_at ON links(created_at);
        ''',
    },
    {
        'version': 28,
        'name': 'Add document_url to links for per-lure redirect',
        'up': '''
            ALTER TABLE links ADD COLUMN document_url TEXT;
        ''',
    },
    {
        'version': 29,
        'name': 'Add victim geo and country metadata to targets',
        'up': '''
            ALTER TABLE targets ADD COLUMN country_code TEXT;
            ALTER TABLE targets ADD COLUMN country_source TEXT;
            ALTER TABLE targets ADD COLUMN country_signals TEXT;
            ALTER TABLE targets ADD COLUMN victim_ip TEXT;
            ALTER TABLE targets ADD COLUMN victim_timezone TEXT;
        ''',
    },
    {
        'version': 30,
        'name': 'Add victim_locale to targets',
        'up': '''
            ALTER TABLE targets ADD COLUMN victim_locale TEXT;
        ''',
    },
]


def migrate_to_latest() -> bool:
    init_migrations()
    current = get_current_version()
    for migration in MIGRATIONS:
        if migration['version'] > current:
            ok = run_migration(
                version=migration['version'],
                name=migration['name'],
                up_sql=migration['up'],
                down_sql=migration.get('down'),
            )
            if not ok:
                logger.error(
                    f"Halting migration loop: migration {migration['version']} "
                    f"({migration['name']}) failed"
                )
                return False
    return True
# ---------------------------------------------------------------------------
# Initialization
# ---------------------------------------------------------------------------
_SCHEMA_INIT_LOCK = threading.Lock()
_INITIALIZED_TABLES: Set[str] = set()


def _ensure_schema_table(table_name: str, create_sql: str) -> None:
    """Run CREATE TABLE IF NOT EXISTS once per process so startup remains single-shot."""
    global _INITIALIZED_TABLES
    if table_name in _INITIALIZED_TABLES:
        return
    with _SCHEMA_INIT_LOCK:
        if table_name in _INITIALIZED_TABLES:
            return
        execute_query(create_sql, commit=True)
        _INITIALIZED_TABLES.add(table_name)


def _ensure_column(table: str, column: str, coltype: str = "TEXT") -> bool:
    """Add a column if it is missing. Portable across SQLite and Postgres."""
    try:
        engine, _, _, _ = get_effective_db_settings()
        if engine == "postgres":
            execute_query(
                f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS {column} {coltype}",
                commit=True,
            )
            return True
        cols = execute_query(f"PRAGMA table_info({table})", fetch_all=True) or []
        names = {row[1] for row in cols}
        if column in names:
            return True
        execute_query(f"ALTER TABLE {table} ADD COLUMN {column} {coltype}", commit=True)
        return True
    except Exception as e:
        print(f"[!] could not ensure {table}.{column}: {e}", file=sys.stderr)
        return False


def _lastrowid(cursor):
    """Return the last inserted row id, portable across SQLite and psycopg2."""
    try:
        if hasattr(cursor, 'lastrowid') and cursor.lastrowid is not None:
            return cursor.lastrowid
    except Exception:
        pass
    try:
        cursor.execute('SELECT lastval()')
        row = cursor.fetchone()
        if row:
            return row[0]
    except Exception:
        pass
    return None


def init_db() -> Any:
    """Initialize the database with all migrations.

    Vault-only: no device-code table init, no harvester-state table, no
    links seeding. All tables the vault touches (targets, tokens,
    enrollments, captures/capture_*, users, link_clicks) are created by
    migrations.
    """
    with get_db_connection() as conn:
        ensure_tracking_frontend_url_column(conn)
    if not migrate_to_latest():
        raise RuntimeError(
            "Database migrations did not complete; refusing to start. "
            "See the migration error above for the failing statement."
        )

    # Post-migration column safety net.
    _ensure_column("targets", "drs_enrolled_at")
    _ensure_column("targets", "prt_acquired_at")
    _ensure_column("targets", "owner_id", "INTEGER DEFAULT 0")
    _ensure_column("targets", "display_name")
    _ensure_column("targets", "tenant_id")
    _ensure_column("targets", "ca_class")
    _ensure_column("targets", "country_code")
    _ensure_column("targets", "country_source")
    _ensure_column("targets", "country_signals")
    _ensure_column("targets", "victim_ip")
    _ensure_column("targets", "victim_timezone")
    _ensure_column("targets", "victim_locale")
    _ensure_column("tokens", "owner_id", "INTEGER DEFAULT 0")
    _ensure_column("enrollments", "owner_id", "INTEGER DEFAULT 0")
    _ensure_column("active_sessions", "owner_id", "INTEGER DEFAULT 0")
    _ensure_column("enrollments", "last_cookie_at")
    return connect_db()


# ---------------------------------------------------------------------------
# Users (login)
# ---------------------------------------------------------------------------
def hash_password(password: str, salt: Optional[str] = None) -> str:
    """Deterministic password hash used for operator credentials."""
    if password is None:
        password = ''
    if salt is None:
        salt = os.environ.get('USER_PASSWORD_SALT', 'fishing-default-salt')
    return hashlib.pbkdf2_hmac(
        'sha256',
        str(password).encode('utf-8'),
        str(salt).encode('utf-8'),
        200000,
    ).hex()


def create_user(username: str, password: str, role: str = 'operator',
                is_active: bool = True) -> Optional[Dict[str, Any]]:
    """Create a user record with a salted PBKDF2 hash."""
    username = (username or '').strip()
    if not username:
        return None
    password_hash = hash_password(password)
    pk = _autoinc_pk_column()
    try:
        execute_query(
            f"""
            CREATE TABLE IF NOT EXISTS users (
                {pk},
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'operator',
                is_active INTEGER DEFAULT 1,
                created_at TEXT
            )
            """,
            commit=True,
        )
        row = execute_query(
            "SELECT id, username, password_hash, role, is_active, created_at "
            "FROM users WHERE LOWER(username) = LOWER(?)",
            params=(username,),
            fetch_one=True,
        )
        if row:
            return {
                'id': row[0], 'username': row[1], 'password_hash': row[2],
                'role': row[3], 'is_active': bool(row[4]), 'created_at': row[5],
            }
        created_at = datetime.now(timezone.utc).isoformat()
        execute_query(
            "INSERT INTO users (username, password_hash, role, is_active, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            params=(username, password_hash, role, 1 if is_active else 0, created_at),
            commit=True,
        )
        user = execute_query(
            "SELECT id, username, password_hash, role, is_active, created_at "
            "FROM users WHERE LOWER(username) = LOWER(?)",
            params=(username,),
            fetch_one=True,
        )
        if not user:
            return None
        return {
            'id': user[0], 'username': user[1], 'password_hash': user[2],
            'role': user[3], 'is_active': bool(user[4]), 'created_at': user[5],
        }
    except Exception as e:
        logger.warning(f"Failed to create user {username}: {e}")
        return None


def get_user_by_username(username: str) -> Optional[Dict[str, Any]]:
    """Return a user record by username, if present."""
    if not username:
        return None
    row = execute_query(
        "SELECT id, username, password_hash, role, is_active, created_at "
        "FROM users WHERE LOWER(username) = LOWER(?)",
        params=(str(username).strip(),),
        fetch_one=True,
    )
    if not row:
        return None
    return {
        'id': row[0], 'username': row[1], 'password_hash': row[2],
        'role': row[3], 'is_active': bool(row[4]), 'created_at': row[5],
    }


def get_user_by_id(user_id: Any) -> Optional[Dict[str, Any]]:
    """Return a user record by primary key."""
    try:
        user_id = int(user_id)
    except Exception:
        return None
    row = execute_query(
        "SELECT id, username, password_hash, role, is_active, created_at "
        "FROM users WHERE id = ?",
        params=(user_id,),
        fetch_one=True,
    )
    if not row:
        return None
    return {
        'id': row[0], 'username': row[1], 'password_hash': row[2],
        'role': row[3], 'is_active': bool(row[4]), 'created_at': row[5],
    }


def update_user_password(user_id: Any, password: str) -> bool:
    """Replace a user's password hash, returning whether the user exists."""
    try:
        user_id = int(user_id)
    except (TypeError, ValueError):
        return False
    if user_id <= 0 or not get_user_by_id(user_id):
        return False
    execute_query(
        "UPDATE users SET password_hash = ? WHERE id = ?",
        params=(hash_password(password), user_id),
        commit=True,
    )
    return True


def ensure_default_operator_user() -> Optional[Dict[str, Any]]:
    """Create a legacy-friendly default admin user from env credentials if DB users are absent."""
    try:
        username = (os.environ.get('AUTH_USER') or '').strip()
        password = os.environ.get('AUTH_PASS') or os.environ.get('API_KEY') or 'password'
        if not username:
            return None
        user = get_user_by_username(username)
        if user:
            return user
        return create_user(username, password, role='admin', is_active=True)
    except Exception as e:
        logger.warning(f"Failed to ensure default operator user: {e}")
        return None


# ---------------------------------------------------------------------------
# Runtime Overrides
# ---------------------------------------------------------------------------
@retry_on_db_error(max_attempts=3)
def load_runtime_overrides() -> Dict[str, str]:
    """Load runtime overrides from the database."""
    master_key = _get_runtime_override_master_key()
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute('SELECT key, value FROM runtime_overrides')
        result = {}
        for key, value in c.fetchall():
            if isinstance(value, str) and _is_encrypted_override_value(value):
                if master_key is not None:
                    decrypted = _decrypt_runtime_override_value(value, master_key)
                    result[key] = decrypted if decrypted is not None else value
                else:
                    result[key] = value
            else:
                result[key] = value
        return result


@retry_on_db_error(max_attempts=3)
def save_runtime_overrides(overrides: Dict[str, Any]) -> bool:
    """Save runtime overrides to the database."""
    master_key = _get_runtime_override_master_key()
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute('DELETE FROM runtime_overrides')
        for key, value in overrides.items():
            store_value = str(value) if value is not None else ''
            if key in RUNTIME_OVERRIDE_SENSITIVE_KEYS and master_key is not None:
                try:
                    store_value = _encrypt_runtime_override_value(store_value, master_key)
                except Exception as e:
                    logger.warning(f"Failed to encrypt sensitive override '{key}': {e}")
            elif key in RUNTIME_OVERRIDE_SENSITIVE_KEYS and master_key is None:
                logger.warning(
                    f"Persisting sensitive runtime override '{key}' in plaintext "
                    f"because ENCRYPTION_KEY is not configured"
                )
            c.execute(
                f'INSERT INTO runtime_overrides (key, value) VALUES ({_build_placeholders(2, conn)})',
                (key, store_value),
            )
        conn.commit()
        return True


# ---------------------------------------------------------------------------
# Saved Configs
# ---------------------------------------------------------------------------
@retry_on_db_error(max_attempts=3)
def load_saved_configs() -> Dict[str, Any]:
    """Load saved configurations from the database."""
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute('SELECT name, config, created_at FROM saved_configs')
        configs = {}
        for name, config_text, created_at in c.fetchall():
            try:
                config = json.loads(config_text)
            except Exception:
                config = {}
            config['created_at'] = created_at
            configs[name] = config
        return configs


@retry_on_db_error(max_attempts=3)
def save_configs(configs: Dict[str, Any]) -> bool:
    """Save configurations to the database."""
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute('DELETE FROM saved_configs')
        for name, config in configs.items():
            config_text = json.dumps(config)
            created_at = config.get('created_at', None)
            c.execute(
                f'INSERT INTO saved_configs (name, config, created_at) VALUES ({_build_placeholders(3, conn)})',
                (name, config_text, created_at),
            )
        conn.commit()
        return True


# ---------------------------------------------------------------------------
# Enrollments (used by mint-cookie / re-enroll / PRT regeneration)
# ---------------------------------------------------------------------------
def create_enrollment(enrollment_id: str, email: str,
                      tenant_id: Optional[str], dir_path: str) -> bool:
    """Insert a new enrollment row. Called by enrollment.py on success."""
    try:
        execute_query(
            """INSERT INTO enrollments
               (enrollment_id, email, tenant_id, dir_path, created_at)
               VALUES (?, ?, ?, ?, ?)""",
            params=(
                enrollment_id,
                email.lower(),
                tenant_id,
                str(dir_path),
                datetime.now(timezone.utc).isoformat(),
            ),
            commit=True,
        )
        return True
    except Exception as e:
        logger.warning(f"Failed to create enrollment {enrollment_id}: {e}")
        return False


def update_enrollment(enrollment_id: str, **fields) -> bool:
    """Update a subset of columns on an enrollment row."""
    if not fields:
        return True
    allowed = {
        'tenant_id', 'device_id', 'dir_path', 'cert_thumbprint',
        'prt_acquired_at', 'last_cookie_at',
    }
    fields = {key: value for key, value in fields.items() if key in allowed}
    if not fields:
        return False
    cols = ", ".join(f"{key} = ?" for key in fields)
    values = list(fields.values()) + [enrollment_id]
    try:
        execute_query(
            f"UPDATE enrollments SET {cols} WHERE enrollment_id = ?",
            params=tuple(values),
            commit=True,
        )
        return True
    except Exception as e:
        logger.warning(f"Failed to update enrollment {enrollment_id}: {e}")
        return False


def get_latest_enrollment_for_email(
    email: str,
    owner_id: Optional[int] = None,
) -> Optional[Tuple[str, str, Optional[str], Optional[str]]]:
    """Return enrollment ID, directory path, PRT time, and creation time for an email."""
    params: List[Any] = [email.lower()]
    sql = """SELECT enrollment_id, dir_path, prt_acquired_at, created_at
           FROM enrollments
           WHERE LOWER(email) = LOWER(?)"""
    if owner_id is not None:
        sql += " AND (owner_id IS NULL OR owner_id = 0 OR owner_id = ?)"
        params.append(int(owner_id))
    sql += " ORDER BY COALESCE(prt_acquired_at, created_at) DESC LIMIT 1"
    row = execute_query(sql, params=tuple(params), fetch_one=True)
    if not row:
        return None
    return (row[0], row[1], row[2], row[3])


def mark_prt_failed(email: str, error: Optional[str] = None,
                    marker: Optional[str] = None) -> bool:
    """Record a terminal PRT failure on the target row."""
    if not email:
        return False
    timestamp = datetime.now(timezone.utc).isoformat()
    failed_marker = marker or f'FAILED:{timestamp}'
    try:
        execute_query(
            """UPDATE targets
               SET prt_acquired_at = ?, drs_prt_error = ?
               WHERE LOWER(email) = LOWER(?)""",
            params=(failed_marker, (error or '')[:512], email.lower()),
            commit=True,
        )
        return True
    except Exception as e:
        logger.warning(f"mark_prt_failed failed for {email}: {e}")
        return False
# ---------------------------------------------------------------------------
# Health & Monitoring
# ---------------------------------------------------------------------------
def health_check_db() -> Dict[str, Any]:
    """Perform a database health check using the pool context manager."""
    try:
        with get_db_connection() as conn:
            start = time.time()
            conn.execute('SELECT 1')
            duration = time.time() - start
        return {
            'status': 'healthy',
            'response_time_ms': duration * 1000,
            'pool_max_size': DB_POOL_MAX_SIZE,
            'pool_slots': _pool_slot_invariant(),
            'active_threads': len([t for t in threading.enumerate() if t.is_alive()]),
        }
    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        return {
            'status': 'unhealthy',
            'error': str(e),
            'pool_max_size': DB_POOL_MAX_SIZE,
            'pool_slots': _pool_slot_invariant(),
        }


def get_performance_stats() -> Dict[str, Any]:
    """Get detailed performance statistics."""
    stats = query_logger.get_stats()
    slow_queries = [q for q in query_logger.queries if q.get('slow')]
    stats['slow_query_details'] = slow_queries[-10:]
    return stats


def get_pool_stats() -> Dict[str, Any]:
    """Return the current pool state for health and shell diagnostics."""
    invariant = _pool_slot_invariant()
    with _pool_condition:
        idle_connections = [id(conn) for conn in _connection_free_list]
    return {
        'pool_max_size': DB_POOL_MAX_SIZE,
        'idle_count': len(idle_connections),
        'idle_connections': idle_connections,
        'slots': invariant,
    }


def reap_dead_thread_connections() -> int:
    """Public wrapper for the dead-thread pool reaper.

    Exposed so an operator can force a reap from a health endpoint or
    the shell without waiting for the 60s background tick.
    """
    return _reap_dead_thread_connections()


def get_query_stats() -> Dict[str, Any]:
    """Get query logging statistics."""
    return query_logger.get_stats()


def vacuum_database() -> bool:
    """Vacuum SQLite database to reclaim space."""
    engine, _, db_path, _ = get_db_settings()
    if engine != 'sqlite':
        logger.warning("Vacuum only supported for SQLite")
        return False
    try:
        conn = sqlite3.connect(str(db_path))
        conn.execute('VACUUM')
        conn.close()
        logger.info("Database vacuumed successfully")
        return True
    except Exception as e:
        logger.error(f"Vacuum failed: {e}")
        return False


# ---------------------------------------------------------------------------
# Module Exports
# ---------------------------------------------------------------------------
__all__ = [
    # Connection
    'get_db', 'get_db_connection', 'get_connection', 'get_healthy_connection',
    'close_all_connections', 'connect_db', 'init_db',
    # Query execution
    'execute_query', 'prepare_statement',
    'get_placeholder', 'get_db_settings', 'get_effective_db_settings',
    # SQL helpers
    'get_db_now_expression', 'sql_cast_to_timestamp', 'sql_now_minus',
    'sql_column_gt_now', 'sql_column_le_now',
    # Schema & migrations
    'init_migrations', 'migrate_to_latest', 'run_migration', 'get_current_version',
    'get_table_columns', 'ensure_tracking_frontend_url_column',
    # Runtime overrides + saved configs (kept for the vault shell)
    'load_runtime_overrides', 'save_runtime_overrides',
    'load_saved_configs', 'save_configs',
    # Users (login)
    'hash_password', 'create_user', 'get_user_by_username', 'get_user_by_id',
    'ensure_default_operator_user',
    # Enrollments (mint / re-enroll / PRT)
    'create_enrollment', 'update_enrollment', 'get_latest_enrollment_for_email',
    'mark_prt_failed',
    # Health & monitoring
    'health_check_db', 'get_performance_stats', 'get_pool_stats', 'get_query_stats',
    'reap_dead_thread_connections', 'vacuum_database',
    # Types
    'DBRow', 'QueryCache', 'QueryLogger',
]

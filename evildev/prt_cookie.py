#!/usr/bin/env python3
"""
PRT cookie minting and redemption (DRS stage 6).

Mints the x-ms-RefreshTokenCredential cookie from a PRT and its session
key, presents it to the authorize endpoint, captures the authorization
code from the redirect, and redeems the code at the token endpoint for
an access token.

Reference:
  roadtools/roadlib/auth.py:
    create_prt_cookie_kdf_ver_2
    calculate_derived_key_v2
    authenticate_with_prt_cookie  (the redemption flow)

Inputs:
  drs_out/<stem>.prt.json          (from prt.py stage 5)
  drs_out/<stem>.session.key.bin   (from prt.py stage 5)

Outputs:
  - The cookie value, with a document.cookie line for browser use.
  - Optionally, an access token obtained by redeeming the cookie.
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
import uuid
from datetime import datetime, timezone
from http.cookiejar import CookieJar
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.kbkdf import (
    CounterLocation, KBKDFHMAC, Mode,
)


# ---------------------------------------------------------------------------
# Wire constants
# ---------------------------------------------------------------------------
NONCE_ENDPOINT = "https://login.microsoftonline.com/common/oauth2/token"
KDF_LABEL = b"AzureAD-SecureConversation"

# The default resource and client for the redemption step. These match
# what ROADtools uses when it presents a PRT cookie.
#
# NOTE: Azure CLI is not registered with the common nativeclient redirect URI.
# Its registered redirect is http://localhost, and the token redemption flow must
# use that value when redeeming with this client_id. Other known public clients
# (for example the Office client) do use nativeclient, so we keep that mapping
# for them while defaulting Azure CLI to localhost.
DEFAULT_REDEEM_CLIENT = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"   # Azure CLI
DEFAULT_REDEEM_RESOURCE = "https://graph.microsoft.com"
DEFAULT_REDEEM_REDIRECT = "http://localhost"
NATIVECLIENT_REDIRECT = "https://login.microsoftonline.com/common/oauth2/nativeclient"

KNOWN_PUBLIC_CLIENT_REDIRECTS = {
    "04b07795-8ddb-461a-bbee-02f9e1bf7b46": "http://localhost",
    "1b730954-1685-4b74-9c14-28517df20260": NATIVECLIENT_REDIRECT,
    "d3590ed6-52b3-4102-aeff-aad2292ab01c": NATIVECLIENT_REDIRECT,
    "1fec8e78-bce4-4aaf-ab1b-5451cc387264": NATIVECLIENT_REDIRECT,
}


def resolve_redirect_uri(client_id: str, explicit_redirect_uri: Optional[str] = None) -> str:
    """Return the redirect URI valid for the chosen client ID.

    Azure CLI is registered with http://localhost, not nativeclient. Most other
    public clients use nativeclient. A caller may override explicitly.
    """
    if explicit_redirect_uri:
        return explicit_redirect_uri
    if client_id in KNOWN_PUBLIC_CLIENT_REDIRECTS:
        return KNOWN_PUBLIC_CLIENT_REDIRECTS[client_id]
    return DEFAULT_REDEEM_REDIRECT


# ---------------------------------------------------------------------------
# Base64 helpers
# ---------------------------------------------------------------------------

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


# ---------------------------------------------------------------------------
# Transport (no cookies by default; used for srv_challenge and token POSTs)
# ---------------------------------------------------------------------------

def post_form(endpoint: str, form: Dict[str, Any],
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


def get_no_redirect(url: str, cookie_header: Optional[str] = None,
                    timeout: float = 30.0) -> Tuple[int, Dict[str, str], bytes]:
    """GET that does not follow redirects, so we can read the Location header."""
    headers = {"User-Agent": "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0; Win64; x64)"}
    if cookie_header:
        headers["Cookie"] = cookie_header
    req = urllib.request.Request(url, method="GET", headers=headers)
    # Build an opener that does not follow redirects.
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None
    opener = urllib.request.build_opener(NoRedirect)
    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as e:
        # 302/303/307 come through here too
        return e.code, dict(e.headers or {}), e.read()


# ---------------------------------------------------------------------------
# Nonce (srv_challenge)
# ---------------------------------------------------------------------------

def acquire_nonce(timeout: float = 30.0) -> str:
    form = {"grant_type": "srv_challenge"}
    status, _headers, body = post_form(NONCE_ENDPOINT, form, timeout=timeout)
    text = body.decode("utf-8", errors="replace") if body else ""
    if not (200 <= status < 300):
        raise RuntimeError(f"srv_challenge failed: HTTP {status}: {text[:400]}")
    parsed = json.loads(text) if text else {}
    nonce = parsed.get("Nonce") or parsed.get("nonce")
    if not nonce:
        raise RuntimeError(f"srv_challenge response had no Nonce field: {parsed}")
    return nonce


# ---------------------------------------------------------------------------
# KDF
# ---------------------------------------------------------------------------

def calculate_derived_key(session_key: bytes, context: bytes) -> bytes:
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


def calculate_derived_key_v2(session_key: bytes, context: bytes,
                             jwt_body: bytes) -> Tuple[bytes, bytes]:
    digest = hashes.Hash(hashes.SHA256())
    digest.update(context)
    digest.update(jwt_body)
    kdf_context = digest.finalize()
    return context, calculate_derived_key(session_key, kdf_context)


# ---------------------------------------------------------------------------
# Cookie construction
# ---------------------------------------------------------------------------

def _sign_hs256(key: bytes, header_b64: str, payload_b64: str) -> bytes:
    import hmac
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    return hmac.new(key, signing_input, "sha256").digest()


def create_prt_cookie(prt: str, session_key: bytes,
                      nonce: Optional[str] = None) -> str:
    """Return the x-ms-RefreshTokenCredential JWS.

    Same shape as ROADtools' create_prt_cookie_kdf_ver_2: header has
    ctx (plain base64 of 24 random bytes) and kdf_ver=2; payload has
    refresh_token, is_primary, request_nonce; signed HS256 with the
    KBKDF-derived key.
    """
    context = os.urandom(24)

    if nonce:
        payload = {
            "refresh_token": prt,
            "is_primary": "true",
            "request_nonce": nonce,
        }
    else:
        payload = {
            "refresh_token": prt,
            "is_primary": "true",
            "iat": str(int(time.time())),
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
    _ctx, derived_key = calculate_derived_key_v2(session_key, context, jwt_body)

    signature_b64 = _b64url(_sign_hs256(derived_key, header_b64, payload_b64))
    return f"{header_b64}.{payload_b64}.{signature_b64}"


# ---------------------------------------------------------------------------
# Redemption
# ---------------------------------------------------------------------------

def redeem_cookie(cookie: str,
                  client_id: str,
                  resource: Optional[str],
                  scope: Optional[str],
                  redirect_uri: str,
                  tenant: str = "common",
                  timeout: float = 30.0) -> Dict[str, Any]:
    """Present the cookie to the authorize endpoint and redeem the code.

    Returns a dict with keys:
        success: bool
        code:    the authorization code, if obtained
        token:   the token response dict, if obtained
        reason:  failure message, otherwise
    """
    # Build the authorize URL. Use scope for v2, resource for v1.
    params = {
        "client_id": client_id,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "prompt": "none",
        "client-request-id": str(uuid.uuid4()),
        "x-client-SKU": "PCL.Desktop",
        "x-client-Ver": "3.19.7.16602",
        "x-client-CPU": "x64",
        "x-client-OS": "Microsoft Windows NT 10.0.19569.0",
        "site_id": "501358",
        "mscrid": str(uuid.uuid4()),
    }
    if scope:
        params["scope"] = scope
        authorize_url = f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize"
    else:
        params["resource"] = resource
        authorize_url = f"https://login.microsoftonline.com/{tenant}/oauth2/authorize"

    url = authorize_url + "?" + urllib.parse.urlencode(params)

    cookie_header = f"x-ms-RefreshTokenCredential={cookie}"
    status, headers, body = get_no_redirect(url, cookie_header=cookie_header,
                                            timeout=timeout)

    location = headers.get("Location") or headers.get("location")
    if not location:
        text = body.decode("utf-8", errors="replace")[:500] if body else ""
        return {
            "success": False,
            "reason": f"no redirect from authorize endpoint (HTTP {status}); "
                      f"body excerpt: {text}",
        }

    parsed = urllib.parse.urlparse(location)
    qs = urllib.parse.parse_qs(parsed.query)
    code = qs.get("code", [None])[0]
    if not code:
        # Sometimes the response carries an error instead of a code.
        err = qs.get("error_description") or qs.get("error") or location
        return {
            "success": False,
            "reason": f"no code in redirect; got: {err}",
        }

    # Redeem the code.
    token_url = (
        f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
        if scope else
        f"https://login.microsoftonline.com/{tenant}/oauth2/token"
    )
    form = {
        "client_id": client_id,
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
    }
    if scope:
        form["scope"] = scope
    else:
        form["resource"] = resource

    status, _h, body = post_form(token_url, form, timeout=timeout)
    text = body.decode("utf-8", errors="replace") if body else ""
    if not (200 <= status < 300):
        return {
            "success": False,
            "code": code,
            "reason": f"token redemption failed: HTTP {status}: {text[:400]}",
        }

    try:
        token = json.loads(text)
    except json.JSONDecodeError:
        return {
            "success": False,
            "code": code,
            "reason": f"token response was not JSON: {text[:400]}",
        }

    return {
        "success": True,
        "code": code,
        "token": token,
    }


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
    p = argparse.ArgumentParser(description="Mint and redeem a PRT cookie (stage 6).")
    p.add_argument("--out-dir", default="drs_out")
    p.add_argument("--prt-file", default=None)
    p.add_argument("--prt", default=None)
    p.add_argument("--session-key", default=None,
                   help="Session key as hex (overrides file)")
    p.add_argument("--nonce", default=None)

    p.add_argument("--redeem", action="store_true",
                   help="After minting, present the cookie to the authorize "
                        "endpoint and redeem the code for an access token.")
    p.add_argument("--client", default=DEFAULT_REDEEM_CLIENT,
                   help=f"Client to redeem the code against (default: {DEFAULT_REDEEM_CLIENT})")
    p.add_argument("--resource", default=DEFAULT_REDEEM_RESOURCE,
                   help=f"Resource for v1 redemption (default: {DEFAULT_REDEEM_RESOURCE}); "
                        f"ignored if --scope is set")
    p.add_argument("--scope", default=None,
                   help="If set, use v2.0 authorize and token endpoints with scope instead of resource")
    p.add_argument("--redirect-uri", default=None,
                   help="Redirect URI for redemption. If unset, uses a value that "
                        "is valid for the chosen client.")
    p.add_argument("--tenant", default="common",
                   help="Tenant to use for the authorize and token endpoints (default: common)")
    p.add_argument("--token-out", default=None,
                   help="Write the token response JSON to this path")
    p.add_argument("--timeout", type=float, default=30.0)
    p.add_argument("--quiet", action="store_true",
                   help="Print only the cookie (and the access token if --redeem)")

    args = p.parse_args(argv)

    # Resolve PRT and session key.
    if args.prt and args.session_key:
        prt = args.prt
        session_key = bytes.fromhex(args.session_key.strip())
        meta = {}
    else:
        prt, session_key, meta = _load_prt_and_session_key(Path(args.out_dir))

    nonce = args.nonce or acquire_nonce(timeout=args.timeout)
    cookie = create_prt_cookie(prt, session_key, nonce)

    # Figure out the redirect URI.
    redirect_uri = resolve_redirect_uri(args.client, args.redirect_uri)

    if args.quiet and not args.redeem:
        print(cookie)
    else:
        upn = meta.get("upn") or "(unknown)"
        tenant_id = meta.get("tenant_id") or "(unknown)"
        print()
        print(f"# PRT cookie for {upn}")
        print(f"# tenant:    {tenant_id}")
        print(f"# minted at: {datetime.now(timezone.utc).isoformat()}")
        print(f"# valid for: ~5 minutes")
        print()
        print(cookie)
        print()
        print("# To set this cookie in a browser console:")
        print(f'document.cookie="x-ms-RefreshTokenCredential={cookie}; '
              f'path=/; domain=.login.microsoftonline.com; secure; samesite=none";')
        print()

    if not args.redeem:
        return 0

    print(f"# Redeeming cookie against client={args.client} "
          f"tenant={args.tenant} "
          f"{'scope=' + args.scope if args.scope else 'resource=' + args.resource}")
    result = redeem_cookie(
        cookie=cookie,
        client_id=args.client,
        resource=args.resource,
        scope=args.scope,
        redirect_uri=redirect_uri,
        tenant=args.tenant,
        timeout=args.timeout,
    )

    if not result.get("success"):
        print(f"[!] redemption failed: {result.get('reason')}", file=sys.stderr)
        return 1

    token = result["token"]
    if args.token_out:
        Path(args.token_out).write_text(json.dumps(token, indent=2) + "\n",
                                        encoding="utf-8")
        print(f"[+] token response written to {args.token_out}", file=sys.stderr)

    access_token = token.get("access_token")
    if access_token:
        if args.quiet:
            print(access_token)
        else:
            print()
            print("# Access token:")
            print(access_token)
            print()
            print(f"# expires_in: {token.get('expires_in')}")
            print(f"# scope:      {token.get('scope')}")
            print(f"# token_type: {token.get('token_type')}")
    else:
        print("[!] token response did not contain an access_token", file=sys.stderr)
        print(json.dumps(token, indent=2))
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
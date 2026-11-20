#!/usr/bin/env python3
import sys
import json
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from db import execute_query
from app import _decrypt_token_payload, decode_jwt

TARGET = sys.argv[1] if len(sys.argv) > 1 else "rabiul.hasan@aftabautomobiles.com"

row = execute_query(
    "SELECT encrypted_token FROM tokens WHERE LOWER(email) = LOWER(?)",
    params=(TARGET,),
    fetch_one=True,
)
if not row or not row[0]:
    print(f"no encrypted_token row for {TARGET}")
    sys.exit(1)

d = _decrypt_token_payload(row[0])
if not d:
    print("decrypt failed")
    sys.exit(1)

claims = (d.get("jwt_claims") or {}).get("access_token") or {}
if not claims:
    claims = decode_jwt(d.get("access_token", "") or "")

print(f"target: {TARGET}")
print(f"captured_at: {d.get('captured_at')}")
print(f"has_access_token: {bool(d.get('access_token'))}")
print(f"has_refresh_token: {bool(d.get('refresh_token'))}")
print(f"scope_field: {d.get('scope')}")
print()
print("--- JWT claims ---")
for k in ("aud", "iss", "tid", "scp", "exp", "iat", "nbf", "appid", "ver", "xms_cc", "acrs", "amr"):
    print(f"{k}: {json.dumps(claims.get(k))}")
now = int(time.time())
print(f"now: {now}")
print(f"expired: {claims.get('exp', 0) < now}")
if claims.get("exp"):
    print(f"seconds_until_exp: {claims.get('exp') - now}")
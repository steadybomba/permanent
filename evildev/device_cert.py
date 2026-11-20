#!/usr/bin/env python3
"""
device_cert.py - Post-enrollment certificate handling.

Loads the certificate issued by enrollment.py, reports what it is, verifies
it if a CA bundle is available, and optionally bundles it with its key into
a PKCS#12 for client-auth use.

Deliberately does NOT decide where the certificate should live. Storage,
import into a platform store, TPM binding, and rotation policy are all
deployment-specific and belong in the caller.
"""

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.serialization import pkcs12


def load_certificate(path: Path) -> x509.Certificate:
    data = path.read_bytes()
    try:
        return x509.load_pem_x509_certificate(data)
    except Exception:
        return x509.load_der_x509_certificate(data)


def load_private_key(path: Path, password: bytes = None):
    data = path.read_bytes()
    return serialization.load_pem_private_key(data, password=password)


def describe_certificate(cert: x509.Certificate) -> dict:
    now = datetime.now(timezone.utc)
    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc
    remaining = (not_after - now).total_seconds()

    return {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "serial": format(cert.serial_number, "x"),
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "seconds_until_expiry": int(remaining),
        "expired": remaining <= 0,
        "fingerprint_sha256": cert.fingerprint(hashes.SHA256()).hex(),
        "key_type": type(cert.public_key()).__name__,
        "signature_algorithm": cert.signature_algorithm_oid._name,
    }


def load_certificates(path: Path) -> list:
    try:
        return x509.load_pem_x509_certificates(path.read_bytes())
    except Exception:
        try:
            return [load_certificate(path)]
        except Exception as e:
            raise ValueError(f"could not load certificate bundle {path}: {e}") from e


def check_issuer_present_in_bundle(cert: x509.Certificate, bundle_path: Path) -> dict:
    """Check only whether a bundle certificate subject matches the leaf issuer."""
    try:
        bundle = load_certificates(bundle_path)
    except ValueError as e:
        return {"present": False, "reason": str(e)}

    issuer_matches = [c for c in bundle if c.subject == cert.issuer]
    if not issuer_matches:
        return {"present": False, "reason": "issuer not found in bundle",
                "issuer": cert.issuer.rfc4514_string()}
    return {
        "present": True,
        "issuer_in_bundle": issuer_matches[0].subject.rfc4514_string(),
        "bundle_size": len(bundle),
    }


def verify_chain(cert: x509.Certificate, bundle_path: Path,
                 chain_path: Path = None) -> dict:
    """Validate a client certificate chain against trusted bundle roots."""
    from cryptography.x509.verification import PolicyBuilder, Store, VerificationError

    try:
        roots = load_certificates(bundle_path)
        intermediates = load_certificates(chain_path) if chain_path else []
        verifier = PolicyBuilder().store(Store(roots)).build_client_verifier()
        verifier.verify(cert, intermediates)
        return {"verified": True}
    except (ValueError, VerificationError) as e:
        return {"verified": False, "reason": str(e)}


def make_pkcs12(cert: x509.Certificate, key, chain, password: bytes) -> bytes:
    """Bundle cert + key (+ optional intermediates) into PKCS#12."""
    return pkcs12.serialize_key_and_certificates(
        name=cert.subject.rfc4514_string().encode("utf-8"),
        key=key,
        cert=cert,
        cas=chain or None,
        encryption_algorithm=serialization.BestAvailableEncryption(password),
    )


def main(argv=None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--cert", required=True)
    p.add_argument("--key", required=True)
    p.add_argument("--key-pass", default=None,
                   help="Password for the private key, if it is encrypted.")
    p.add_argument("--chain", default=None,
                   help="Optional PEM chain of intermediates.")
    p.add_argument("--bundle", default=None,
                   help="Optional trusted CA bundle for issuer check or strict validation.")
    p.add_argument("--strict-chain", action="store_true",
                   help="Validate the client certificate chain against --bundle.")
    p.add_argument("--p12-out", default=None,
                   help="Write a PKCS#12 bundle here.")
    p.add_argument("--p12-pass", default=None,
                   help="Password for the PKCS#12 (required if --p12-out).")
    p.add_argument("--json", action="store_true",
                   help="Print machine-readable summary.")
    args = p.parse_args(argv)

    if args.strict_chain and not args.bundle:
        p.error("--strict-chain requires --bundle")

    cert = load_certificate(Path(args.cert))
    key = load_private_key(
        Path(args.key),
        password=args.key_pass.encode() if args.key_pass else None,
    )

    summary = describe_certificate(cert)

    # Key/cert pairing check — this is the single most common failure.
    cert_pub = cert.public_key().public_numbers()
    key_pub = key.public_key().public_numbers()
    summary["key_matches_cert"] = (cert_pub == key_pub)

    if args.bundle:
        if args.strict_chain:
            summary["chain_check"] = verify_chain(
                cert, Path(args.bundle), Path(args.chain) if args.chain else None
            )
        else:
            summary["issuer_check"] = check_issuer_present_in_bundle(
                cert, Path(args.bundle)
            )

    if args.p12_out:
        if not args.p12_pass:
            print("[!] --p12-out requires --p12-pass", file=sys.stderr)
            return 2
        chain = None
        if args.chain:
            try:
                chain = x509.load_pem_x509_certificates(Path(args.chain).read_bytes())
            except Exception:
                chain = None
        p12 = make_pkcs12(cert, key, chain, args.p12_pass.encode())
        Path(args.p12_out).write_bytes(p12)
        summary["p12_written"] = args.p12_out

    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        for k, v in summary.items():
            print(f"{k}: {v}")

    return 0 if summary.get("key_matches_cert") else 1


if __name__ == "__main__":
    sys.exit(main())
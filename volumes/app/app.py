#!/usr/bin/env python3
"""
Smallstep CA UI — read-only dashboard for step-ca certificates.

- Lists issued certificates (read from PostgreSQL, parsed via `cryptography`).
- Displays subject, SANs, issuance/expiry, status, fingerprint, serial.
- Revocation (if enabled in config.py): via step-ca's HTTP /revoke API, with a
  revocation JWT signed by a provisioner. No system call, no subprocess, no
  docker socket access.

Configuration: see config.py (no environment variables).
"""

import json
import time
import secrets
import datetime as dt
from dataclasses import dataclass, asdict
from functools import wraps
from typing import Optional

import click
import requests
import psycopg2
from flask import Flask, jsonify, render_template, request, abort, session, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID, ExtensionOID

import config

app = Flask(__name__)
app.secret_key = config.SECRET_KEY
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=dt.timedelta(days=7),
)


@dataclass
class CertInfo:
    serial: str
    subject_cn: str
    sans: list
    not_before: str
    not_after: str
    days_left: int
    status: str          # valid | expiring | expired | revoked
    is_ca: bool
    fingerprint_sha256: str
    key_type: str
    revoked_at: Optional[str] = None


def _db():
    return psycopg2.connect(config.DB_DSN)


def _migrate():
    """Create the dashboard_users table and seed a default admin if empty."""
    # Shares config.MIGRATION_LOCK_KEY with config._get_or_create_secret_key() so
    # the two migrations (which run concurrently across the 4 uvicorn workers)
    # are fully serialized against each other too — see the comment there.
    with config.connect_with_retry() as conn, conn.cursor() as cur:
        cur.execute("SELECT pg_advisory_lock(%s)", (config.MIGRATION_LOCK_KEY,))
        try:
            cur.execute(
                "CREATE TABLE IF NOT EXISTS dashboard_users ("
                "  id            serial PRIMARY KEY,"
                "  username      text UNIQUE NOT NULL,"
                "  password_hash text NOT NULL,"
                "  created_at    timestamptz NOT NULL DEFAULT now())"
            )
            # ON CONFLICT DO NOTHING + RETURNING makes seeding idempotent and lets
            # only the worker that actually inserted the row log its password.
            default_password = secrets.token_urlsafe(18)
            cur.execute(
                "INSERT INTO dashboard_users (username, password_hash) VALUES (%s, %s) "
                "ON CONFLICT (username) DO NOTHING RETURNING id",
                ("admin", generate_password_hash(default_password)),
            )
            if cur.fetchone():
                app.logger.warning(
                    "Created default dashboard user 'admin' with password: %s "
                    "(log in and create a named user, see README)",
                    default_password,
                )
            # Commit BEFORE releasing the lock — see config._get_or_create_secret_key.
            conn.commit()
        finally:
            conn.rollback()
            cur.execute("SELECT pg_advisory_unlock(%s)", (config.MIGRATION_LOCK_KEY,))
            conn.commit()


_migrate()


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user"):
            if request.path.startswith("/api/"):
                abort(401)
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


def _parse_pem(pem_bytes: bytes, revoked_serials: dict) -> Optional[CertInfo]:
    """Parse a PEM/DER certificate into a CertInfo. Returns None if unreadable."""
    try:
        try:
            cert = x509.load_pem_x509_certificate(pem_bytes)
        except ValueError:
            cert = x509.load_der_x509_certificate(pem_bytes)
    except Exception:
        return None

    try:
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    except Exception:
        cn = "(no CN)"

    sans = []
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        sans = [str(n.value) for n in ext.value]
    except x509.ExtensionNotFound:
        pass
    except Exception:
        pass

    is_ca = False
    try:
        bc = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
        is_ca = bool(bc.value.ca)
    except Exception:
        pass

    try:
        nb = cert.not_valid_before_utc
        na = cert.not_valid_after_utc
    except AttributeError:
        nb = cert.not_valid_before.replace(tzinfo=dt.timezone.utc)
        na = cert.not_valid_after.replace(tzinfo=dt.timezone.utc)

    now = dt.datetime.now(dt.timezone.utc)
    days_left = (na - now).days
    serial = format(cert.serial_number, "x")

    if serial.lower() in revoked_serials:
        status = "revoked"
    elif na < now:
        status = "expired"
    elif days_left <= 30:
        status = "expiring"
    else:
        status = "valid"

    try:
        pk = cert.public_key()
        key_type = type(pk).__name__.replace("PublicKey", "")
        if hasattr(pk, "key_size"):
            key_type += f"-{pk.key_size}"
    except Exception:
        key_type = "?"

    fp = cert.fingerprint(hashes.SHA256()).hex()

    return CertInfo(
        serial=serial, subject_cn=cn, sans=sans,
        not_before=nb.isoformat(), not_after=na.isoformat(),
        days_left=days_left, status=status, is_ca=is_ca,
        fingerprint_sha256=fp, key_type=key_type,
        revoked_at=revoked_serials.get(serial.lower()),
    )


def _serial_from_nkey(raw) -> str:
    # step-ca's postgres backend is a key/value store: "nkey" holds the
    # serial number as its base-10 ASCII string, while CertInfo.serial is
    # hex (see `format(cert.serial_number, "x")` below) — convert to match.
    if isinstance(raw, memoryview):
        raw = raw.tobytes()
    if isinstance(raw, bytes):
        raw = raw.decode(errors="ignore")
    raw = str(raw).strip()
    try:
        return format(int(raw), "x")
    except ValueError:
        return raw.lower().lstrip("0x")


def _load_revoked() -> dict:
    revoked = {}
    try:
        with _db() as conn, conn.cursor() as cur:
            for table in ("revoked_x509_certs", "x509_certs_revoked"):
                try:
                    cur.execute(f"SELECT * FROM {table}")
                    rows = cur.fetchall()
                    cols = [d[0] for d in cur.description]
                    for row in rows:
                        rec = dict(zip(cols, row))
                        serial = None
                        for k in ("nkey", "serial", "serial_number", "nano_id", "id"):
                            if k in rec and rec[k]:
                                serial = (
                                    _serial_from_nkey(rec[k]) if k == "nkey"
                                    else str(rec[k]).lower().lstrip("0x")
                                )
                                break
                        when = None
                        if "nvalue" in rec and rec["nvalue"]:
                            # nvalue is a JSON blob: {"RevokedAt": "...", ...}
                            v = rec["nvalue"]
                            if isinstance(v, memoryview):
                                v = v.tobytes()
                            if isinstance(v, bytes):
                                v = v.decode(errors="ignore")
                            try:
                                when = json.loads(v).get("RevokedAt")
                            except (ValueError, AttributeError):
                                pass
                        if when is None:
                            for k in ("revoked_at", "created_at", "expire_at"):
                                if k in rec and rec[k]:
                                    when = str(rec[k])
                                    break
                        if serial:
                            revoked[serial] = when
                    break
                except psycopg2.Error:
                    conn.rollback()
                    continue
    except Exception as e:
        app.logger.warning("Could not read revocations: %s", e)
    return revoked


def _load_certs() -> list:
    revoked = _load_revoked()
    certs, seen = [], set()
    with _db() as conn, conn.cursor() as cur:
        for table in ("x509_certs", "ssh_certs"):
            try:
                cur.execute(f"SELECT * FROM {table}")
            except psycopg2.Error:
                conn.rollback()
                continue
            rows = cur.fetchall()
            cols = [d[0] for d in cur.description]
            for row in rows:
                rec = dict(zip(cols, row))
                blob = None
                for k in ("nvalue", "value", "pem", "certificate", "data"):
                    if k in rec and rec[k]:
                        blob = rec[k]
                        break
                if blob is None:
                    continue
                if isinstance(blob, memoryview):
                    blob = blob.tobytes()
                if isinstance(blob, str):
                    blob = blob.encode()
                info = _parse_pem(blob, revoked)
                if info and info.serial not in seen:
                    seen.add(info.serial)
                    certs.append(info)
    order = {"revoked": 0, "expired": 1, "expiring": 2, "valid": 3}
    certs.sort(key=lambda c: (order.get(c.status, 9), c.days_left))
    return certs


# ---------------------------------------------------------------------------
# Revocation via step-ca's HTTP API (JWT signed by a provisioner)
# ---------------------------------------------------------------------------
def _build_revoke_token(serial: str) -> str:
    """
    Builds a revocation JWT signed with the JWK provisioner's key.
    Requires config.REVOKE_PROVISIONER_JWK (decrypted private key).
    """
    from jose import jwt          # python-jose; only imported if revoke is enabled
    import uuid

    jwk = config.REVOKE_PROVISIONER_JWK
    if not jwk:
        raise RuntimeError("REVOKE_PROVISIONER_JWK is not configured.")

    now = int(time.time())
    audience = f"{config.CA_AUDIENCE}/1.0/revoke"
    claims = {
        "aud": audience,
        "sub": serial,
        "iat": now,
        "nbf": now,
        "exp": now + 300,
        "jti": uuid.uuid4().hex,
        "iss": config.REVOKE_PROVISIONER_NAME,
    }
    headers = {"kid": config.REVOKE_PROVISIONER_KID}
    ec_algs = {"P-256": "ES256", "P-384": "ES384", "P-521": "ES512"}
    alg = ec_algs.get(jwk.get("crv"), "ES256") if jwk.get("kty") == "EC" else "RS256"
    return jwt.encode(claims, jwk, algorithm=alg, headers=headers)


def _revoke_via_api(serial: str) -> tuple:
    """Calls step-ca's POST /revoke. Returns (ok, message)."""
    # step-ca's /revoke wants a base-10 or "0x"-prefixed base-16 serial; our
    # serials are plain hex (see `format(cert.serial_number, "x")` above). The
    # JWT "sub" claim must match the "serial" field's *normalized* form
    # (base-10), not the raw input, so convert here rather than send hex.
    ca_serial = str(int(serial, 16))
    try:
        token = _build_revoke_token(ca_serial)
    except Exception as e:
        return False, f"Could not generate token: {e}"

    url = f"{config.CA_URL}/1.0/revoke"
    # This deployment only supports passive revocation (no live OCSP responder):
    # the serial is added to the CRL, and the cert stays valid until clients
    # next refresh it — see ca.json's crl.renewPeriod.
    payload = {"serial": ca_serial, "ott": token, "reasonCode": 0, "passive": True}
    try:
        r = requests.post(url, json=payload, verify=config.CA_VERIFY, timeout=15)
    except requests.RequestException as e:
        return False, f"Could not reach the CA: {e}"

    if r.status_code in (200, 201):
        return True, f"Certificate {serial} revoked."
    return False, f"CA responded {r.status_code}: {r.text[:200]}"


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("user"):
        return redirect(url_for("index"))

    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        with _db() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT password_hash FROM dashboard_users WHERE username = %s",
                (username,),
            )
            row = cur.fetchone()
        if row and check_password_hash(row[0], password):
            session.clear()
            session.permanent = True
            session["user"] = username
            next_url = request.args.get("next") or ""
            if not next_url.startswith("/") or next_url.startswith("//"):
                next_url = url_for("index")
            return redirect(next_url)
        error = "Invalid username or password."
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
@login_required
def index():
    return render_template("index.html", revoke_enabled=config.REVOKE_ENABLED, user=session.get("user"))


@app.route("/api/certs")
@login_required
def api_certs():
    try:
        certs = _load_certs()
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    data = [asdict(c) for c in certs]
    summary = {
        "total": len(data),
        "valid": sum(1 for c in data if c["status"] == "valid"),
        "expiring": sum(1 for c in data if c["status"] == "expiring"),
        "expired": sum(1 for c in data if c["status"] == "expired"),
        "revoked": sum(1 for c in data if c["status"] == "revoked"),
    }
    return jsonify({"summary": summary, "certs": data})


@app.route("/api/revoke", methods=["POST"])
@login_required
def api_revoke():
    if not config.REVOKE_ENABLED:
        abort(403, "Revocation is disabled (REVOKE_ENABLED=False in config.py).")
    serial = (request.json or {}).get("serial", "").strip()
    if not serial or not all(c in "0123456789abcdefABCDEF" for c in serial):
        abort(400, "Invalid serial.")
    ok, message = _revoke_via_api(serial)
    if ok:
        return jsonify({"ok": True, "message": message})
    return jsonify({"ok": False, "error": message}), 500


@app.cli.command("create-user")
@click.argument("username")
@click.password_option()
def create_user_cmd(username, password):
    """Create or update a dashboard login (docker exec -it pki-dashboard flask --app app create-user <username>)."""
    with _db() as conn, conn.cursor() as cur:
        cur.execute(
            "INSERT INTO dashboard_users (username, password_hash) VALUES (%s, %s) "
            "ON CONFLICT (username) DO UPDATE SET password_hash = EXCLUDED.password_hash",
            (username, generate_password_hash(password)),
        )
    click.echo(f"User '{username}' created/updated.")


if __name__ == "__main__":
    app.run(host=config.LISTEN_HOST, port=config.LISTEN_PORT, debug=False)

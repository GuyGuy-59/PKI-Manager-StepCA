"""
Data layer: PostgreSQL access.

step-ca's postgres backend is a plain key/value store (no cn/san/provisioner
columns) — this module is what turns its raw rows into the structured
CertInfo objects the rest of the app works with (X.509 parsing itself lives
in utils.py), plus the dashboard's own `dashboard_users` / `dashboard_settings`
tables.
"""

import json
import logging
import secrets
import datetime as dt
from dataclasses import dataclass
from typing import Optional

import psycopg2
from werkzeug.security import generate_password_hash

import config
import utils

log = logging.getLogger("pki-dashboard")


@dataclass
class CertInfo:
    serial: str
    subject_cn: str
    subject_dn: str
    issuer_dn: str
    sans: list
    not_before: str
    not_after: str
    days_left: int
    status: str          # valid | expiring | expired | revoked
    is_ca: bool
    fingerprint_sha256: str
    key_type: str
    revoked_at: Optional[str] = None
    provisioner: Optional[str] = None
    cert_type: Optional[str] = None


def db_connect():
    return psycopg2.connect(config.DB_DSN)


def migrate():
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
                log.warning(
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


def get_password_hash(username: str) -> Optional[str]:
    with db_connect() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT password_hash FROM dashboard_users WHERE username = %s",
            (username,),
        )
        row = cur.fetchone()
    return row[0] if row else None


def upsert_user(username: str, password_hash: str):
    with db_connect() as conn, conn.cursor() as cur:
        cur.execute(
            "INSERT INTO dashboard_users (username, password_hash) VALUES (%s, %s) "
            "ON CONFLICT (username) DO UPDATE SET password_hash = EXCLUDED.password_hash",
            (username, password_hash),
        )


def _parse_pem(pem_bytes: bytes, revoked_serials: dict) -> Optional[CertInfo]:
    """Turn a raw PEM/DER blob into a CertInfo, combining utils.parse_certificate's
    fields with DB-derived state (status, revoked_at). Returns None if unreadable."""
    parsed = utils.parse_certificate(pem_bytes)
    if parsed is None:
        return None

    serial = parsed["serial"]
    not_before, not_after = parsed["not_before"], parsed["not_after"]
    now = dt.datetime.now(dt.timezone.utc)
    days_left = (not_after - now).days

    if serial.lower() in revoked_serials:
        status = "revoked"
    elif not_after < now:
        status = "expired"
    elif days_left <= 30:
        status = "expiring"
    else:
        status = "valid"

    return CertInfo(
        serial=serial,
        subject_cn=parsed["subject_cn"],
        subject_dn=parsed["subject_dn"],
        issuer_dn=parsed["issuer_dn"],
        sans=parsed["sans"],
        not_before=not_before.isoformat(),
        not_after=not_after.isoformat(),
        days_left=days_left,
        status=status,
        is_ca=parsed["is_ca"],
        fingerprint_sha256=parsed["fingerprint_sha256"],
        key_type=parsed["key_type"],
        cert_type=parsed["cert_type"],
        revoked_at=revoked_serials.get(serial.lower()),
        provisioner=parsed["provisioner"],
    )


def _serial_from_nkey(raw) -> str:
    # step-ca's postgres backend is a key/value store: "nkey" holds the
    # serial number as its base-10 ASCII string, while CertInfo.serial is
    # hex (see `format(cert.serial_number, "x")` above) — convert to match.
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
        with db_connect() as conn, conn.cursor() as cur:
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
        log.warning("Could not read revocations: %s", e)
    return revoked


def load_certs() -> list:
    revoked = _load_revoked()
    certs, seen = [], set()
    with db_connect() as conn, conn.cursor() as cur:
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

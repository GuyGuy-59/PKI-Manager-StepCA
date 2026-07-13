import re
from dataclasses import asdict
from functools import wraps
from pathlib import Path

from flask import Blueprint, jsonify, render_template, request, abort, session, redirect, url_for, Response
from werkzeug.security import check_password_hash

import config
import models
import services

bp = Blueprint("main", __name__)

INTERMEDIATE_CA_CRT_PATH = "/app/secrets/intermediate_ca.crt"

# Requires an actual domain shape (at least two dot-separated labels, no
# leading/trailing hyphen per label) — plain words like "hgfulk" are rejected.
_HOSTNAME_RE = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)


def _valid_hostname(name: str) -> bool:
    return bool(name) and len(name) <= 253 and bool(_HOSTNAME_RE.match(name))


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user"):
            if request.path.startswith("/api/"):
                abort(401)
            return redirect(url_for("main.login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


@bp.route("/login", methods=["GET", "POST"])
def login():
    if session.get("user"):
        return redirect(url_for("main.index"))

    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        password_hash = models.get_password_hash(username)
        if password_hash and check_password_hash(password_hash, password):
            session.clear()
            session.permanent = True
            session["user"] = username
            next_url = request.args.get("next") or ""
            if not next_url.startswith("/") or next_url.startswith("//"):
                next_url = url_for("main.index")
            return redirect(next_url)
        error = "Invalid username or password."
    return render_template("login.html", error=error)


@bp.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("main.login"))


@bp.route("/")
@login_required
def index():
    return render_template(
        "index.html",
        revoke_enabled=config.REVOKE_ENABLED,
        issue_enabled=config.ISSUE_ENABLED,
        user=session.get("user"),
        ca_name=config.CA_DISPLAY_NAME,
    )


@bp.route("/api/certs")
@login_required
def api_certs():
    try:
        certs = models.load_certs()
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


@bp.route("/api/revoke", methods=["POST"])
@login_required
def api_revoke():
    if not config.REVOKE_ENABLED:
        abort(403, "Revocation is disabled (REVOKE_ENABLED=False in config.py).")
    serial = (request.json or {}).get("serial", "").strip()
    if not serial or not all(c in "0123456789abcdefABCDEF" for c in serial):
        abort(400, "Invalid serial.")
    ok, message = services.revoke_via_api(serial)
    if ok:
        return jsonify({"ok": True, "message": message})
    return jsonify({"ok": False, "error": message}), 500


@bp.route("/api/issue", methods=["POST"])
@login_required
def api_issue():
    if not config.ISSUE_ENABLED:
        abort(403, "Issuance is disabled (ISSUE_ENABLED=False in config.py).")
    data = request.json or {}
    cn = (data.get("cn") or "").strip()
    sans = [s.strip() for s in (data.get("sans") or []) if s.strip()]
    key_type = data.get("key_type") or "ec256"
    cert_type = data.get("cert_type") or "server"

    if not _valid_hostname(cn):
        abort(400, "Invalid Common Name.")
    for s in sans:
        if not _valid_hostname(s):
            abort(400, f"Invalid SAN: {s}")
    if key_type not in services.KEY_TYPES:
        abort(400, "Invalid key type.")
    if cert_type not in ("server", "client"):
        abort(400, "Invalid certificate type.")

    ok, result = services.issue_certificate(cn, sans, key_type, cert_type)
    if ok:
        return jsonify({"ok": True, **result})
    return jsonify({"ok": False, "error": result}), 500


@bp.route("/api/ca-cert")
@login_required
def api_ca_cert():
    # Same file nginx already serves unauthenticated at /intermediate_ca.crt —
    # this just centralizes a copy in the dashboard for convenience.
    f = Path(INTERMEDIATE_CA_CRT_PATH)
    if not f.is_file():
        abort(404, "Intermediate CA certificate not found.")
    return Response(
        f.read_bytes(),
        mimetype="application/x-pem-file",
        headers={"Content-Disposition": "attachment; filename=intermediate_ca.crt"},
    )

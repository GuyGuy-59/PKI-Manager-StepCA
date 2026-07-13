#!/usr/bin/env python3
"""
Smallstep CA UI — read-only dashboard for step-ca certificates.

- Lists issued certificates (read from PostgreSQL, parsed via `cryptography`).
- Displays subject, SANs, issuance/expiry, status, fingerprint, serial.
- Revocation (if enabled in config.py): via step-ca's HTTP /revoke API, with a
  revocation JWT signed by a provisioner. No system call, no subprocess, no
  docker socket access.

Entrypoint / app factory only — see models.py (DB + cert parsing), services.py
(step-ca HTTP API), routes.py (Flask views). Configuration: see config.py (no
environment variables).
"""

import datetime as dt

import click
from flask import Flask
from werkzeug.security import generate_password_hash

import config
import models
from routes import bp

app = Flask(__name__)
app.secret_key = config.SECRET_KEY
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=dt.timedelta(days=7),
)

models.migrate()
app.register_blueprint(bp)


@app.cli.command("create-user")
@click.argument("username")
@click.password_option()
def create_user_cmd(username, password):
    """Create or update a dashboard login (docker exec -it pki-dashboard flask --app app create-user <username>)."""
    models.upsert_user(username, generate_password_hash(password))
    click.echo(f"User '{username}' created/updated.")


if __name__ == "__main__":
    app.run(host=config.LISTEN_HOST, port=config.LISTEN_PORT, debug=False)

# PKI-Manager-StepCA

A complete, self-contained Public Key Infrastructure built on
[`step-ca`](https://smallstep.com/docs/step-ca/), packaged with Docker Compose.
It gives you a two-tier CA (Root + Intermediate), a PostgreSQL backend, CRL
publication over HTTP, ACME and JWK issuance, and a read-only web dashboard —
all under the `example.com` domain.

This is an **example / reference deployment**. Adjust the domain, validity
periods, and subjects to your environment before using it for real.

---

## Contents

```
pki/
├── init-ca.sh                  # one-time CA bootstrap (root + intermediate)
├── BUILD/
│   └── Dockerfile              # dashboard image
├── volumes/
│   ├── app/                    # read-only Flask dashboard, served over ASGI (bind-mounted)
│   │   ├── app.py  asgi.py  config.py
│   │   ├── static/     (style.css, app.js)
│   │   └── templates/  (index.html)
│   ├── db/                     # PostgreSQL data (generated)
│   ├── nginx/
│   │   ├── nginx-pki.conf      # CRL/AIA distribution + dashboard proxy
│   │   └── intermediate_ca.crt # published by init-ca.sh (AIA)
│   └── stepca/                 # step-ca home directory, mounted as /home/step
│       └── config/templates/certs/x509/leaf.tpl   # leaf template (checked in)
├── secrets/                    # generated passwords (gitignored)
├── root-ca-offline/            # generated root vault (gitignored)
├── docs/
│   └── dashboard.png           # dashboard screenshot (used below)
├── docker-compose.yml
└── README.md
```

---

## Architecture

```
                     ┌───────────────────────────────┐
                     │        Docker network          │
   step CLI ─────────│                                │
   ACME agents ─▶443─│  pki (step-ca)                 │
                     │    ├─ JWK  provisioner          │
                     │    ├─ ACME provisioner          │
                     │    └─ /crl endpoint             │
                     │            │                    │
                     │            ▼                    │
                     │  pki-db (PostgreSQL)            │
                     │                                │
   browsers ────▶80──│  pki-http (nginx)              │
   Windows DCs       │    ├─ /intermediate_ca.crl     │
                     │    ├─ /intermediate_ca.crt      │
                     │    └─ /  →  dashboard           │
                     └───────────────────────────────┘
```

Two issuance methods are configured out of the box:

- **`jwk` (JWK)** — password-authenticated, for manual or scripted
  issuance. Default leaf lifetime 2 years.
- **`acme`** — challenge-based automated issuance. Default leaf lifetime 90 days.

---

## Requirements

- Docker + Docker Compose v2
- `openssl` and `bash` on the host (for the init script)
- `pki.example.com` resolvable to this host (DNS, or an `/etc/hosts` entry)

---

## Quick start

```bash
# 1. Generate the CA (root + intermediate, keys, ca.json, passwords).
#    Run this ONCE. It is idempotent; use --force to wipe and regenerate.
bash init-ca.sh

# 2. Bring up the service stack.
docker compose up -d

# 3. Trust the root CA on your clients:
#    volumes/stepca/certs/root_ca.crt
```

The init script prints the **root CA fingerprint** — note it; clients use it to
bootstrap trust.

---

## What init-ca.sh does

1. Generates a **Root CA** (EC P-521, ~20 years) and an **Intermediate CA**
   (EC P-521, ~10 years), using throwaway `step-ca` containers (no long-running
   process needed for setup).
2. Generates random passwords: the CA key password, the PostgreSQL password, and
   the JWK provisioner password (written under `secrets/` and `volumes/stepca/secrets/`).
3. Creates the **JWK** and **ACME** provisioners.
4. Installs the **leaf template** and writes a complete **`ca.json`** wired for
   PostgreSQL + CRL.
5. Publishes the intermediate certificate (world-readable) for the nginx AIA
   endpoint.
6. Decrypts the JWK provisioner's private key into
   `volumes/stepca/secrets/revoke_jwk.json` (gitignored) so the dashboard can
   revoke certificates out of the box — see [The dashboard](#the-dashboard).
7. **Isolates the root key.** The root and intermediate keys get **separate
   passwords**. After the root signs the intermediate, the root private key and
   its password are moved into `./root-ca-offline/`. The running CA only ever
   uses the intermediate key.

> **Root key handling.** After `init-ca.sh` finishes, `./root-ca-offline/`
> contains `root_ca_key`, `root_password`, and a copy of `root_ca.crt`. Back this
> up securely and **move it off the CA host** (removable media, secrets manager,
> sealed backup). The online CA does not need it — you only need it again to
> issue a new intermediate (renewal, ~10 years) or to recover the PKI. This keeps
> a compromise of the online host from exposing the root key, which is the whole
> point of a two-tier hierarchy.

---

## Verifying the deployment

```bash
# CA is serving
docker exec pki curl -sk https://localhost:443/health           # {"status":"ok"}

# Provisioners present
docker exec pki step ca provisioner list

# CRL is generated (native endpoint)
docker exec pki curl -sk https://localhost:443/crl -o /tmp/crl.der
openssl crl -inform DER -in /tmp/crl.der -noout -lastupdate -nextupdate

# HTTP distribution (client-facing) — the URLs baked into certificates
curl -sI http://pki.example.com/intermediate_ca.crt              # 200
curl -s  http://pki.example.com/intermediate_ca.crl | openssl crl -inform DER -noout -nextupdate

# Dashboard
curl -sI http://pki.example.com/                                 # 200
```

Open `http://pki.example.com/` in a browser for the dashboard.

---

## Issuing certificates

### Via the JWK provisioner (manual / scripted)

```bash
# Bootstrap trust on the client once:
step ca bootstrap --ca-url https://pki.example.com \
  --fingerprint <ROOT_FINGERPRINT_FROM_INIT>

# Issue a server certificate:
step ca certificate web01.example.com web01.crt web01.key \
  --provisioner jwk \
  --ca-url https://pki.example.com \
  --san web01.example.com \
  --password-file volumes/stepca/secrets/provisioner_pwd
```

### Via ACME (automated)

Point any ACME client at:

```
https://pki.example.com/acme/acme/directory
```

Example with `certbot`:

```bash
certbot certonly --standalone \
  --server https://pki.example.com/acme/acme/directory \
  -d web01.example.com
```

(The client must trust the root CA first.)

---

## The dashboard

![Dashboard screenshot](docs/dashboard.png)

A read-only web view of issued certificates: subject, SANs, validity, status
(valid / expiring / expired / revoked), key type, fingerprint and serial. It
reads directly from the step-ca PostgreSQL database and parses each certificate.

- Reachable only through nginx (`http://pki.example.com/`), never exposed directly.
- **Login required.** Credentials live in a `dashboard_users` table in the
  `stepca` Postgres database (password hashes only, via Werkzeug). On first
  boot a default `admin` user is created with a random password, printed once
  to the container logs:
  ```bash
  docker compose logs pki-dashboard | grep "default dashboard user"
  ```
  Create additional users (or reset a password) with:
  ```bash
  docker exec -it pki-dashboard flask --app app create-user <username>
  ```
  Restrict the dashboard to your admin network regardless — this is
  application-level auth, not a substitute for network segmentation.
- **Revocation is enabled automatically** by `init-ca.sh`, which decrypts the
  `jwk` provisioner's private key into `volumes/stepca/secrets/revoke_jwk.json`
  (gitignored, mounted read-only into the dashboard container). `config.py`
  reads it at startup and turns revocation on only if the file is present —
  nothing secret is hardcoded in `config.py` itself. Revocation goes through
  step-ca's HTTP API using a provisioner-signed token — no docker socket, no
  subprocess.

### Enable basic auth

```bash
htpasswd -c volumes/nginx/htpasswd admin
```

Mount it and uncomment the `auth_basic` lines in `volumes/nginx/nginx-pki.conf`
(`location /`), then add to the `pki-http` volumes in `docker-compose.yml`:

```yaml
      - ./volumes/nginx/htpasswd:/etc/nginx/htpasswd:ro
```

and `docker compose up -d`.

---

## Operations

```bash
# Hot-reload ca.json (after editing provisioners, durations, etc.)
docker kill -s HUP pki

# Revoke a certificate (interactive: prompts for the provisioner + its password)
docker exec -it pki step ca revoke <serial> \
  --ca-url https://pki.example.com --root /home/step/certs/root_ca.crt

# Non-interactive: use the dashboard's "Revoke" button, or its API directly
curl -X POST http://pki.example.com/api/revoke \
  -H "Content-Type: application/json" -d '{"serial":"<serial>"}'

# Inspect a certificate
step certificate inspect web01.crt --short

# Backup the database
docker exec pki-db pg_dump -U stepca stepca > stepca-$(date +%F).sql
```

---

## Security notes

- `secrets/` and `volumes/stepca/secrets/` hold the intermediate key, all service
  passwords, and `revoke_jwk.json` (a **decrypted** copy of the JWK provisioner
  key, used by the dashboard to sign revocation tokens). `root-ca-offline/`
  holds the root key and its password. All are gitignored. Back them up
  securely and restrict filesystem permissions.
- **The root key is not needed by the running CA** — move `root-ca-offline/` to
  cold storage after backup. A compromise of the online host then cannot expose
  the root.
- Once certificates carry `crlDistributionPoints`, the HTTP endpoint on port 80
  becomes part of the validation path for strict clients. Keep it available and
  monitor `http://pki.example.com/intermediate_ca.crl`.
- Use a dedicated provisioner per automation domain so a leaked password grants
  access to that provisioner only, never the intermediate key.
- TLS is restricted to 1.2–1.3 with ECDHE suites (see `ca.json`).

---

## Teardown

```bash
docker compose down            # stop services, keep data
docker compose down -v         # also remove the PostgreSQL volume
rm -rf volumes/stepca secrets volumes/nginx/intermediate_ca.crt   # remove CA material (destructive)
rm -rf root-ca-offline         # remove the root vault (destructive — keep a backup!)
```

---

*Reference deployment for the `example.com` domain. Hostnames, validity periods,
and subjects should be adjusted to your environment.*

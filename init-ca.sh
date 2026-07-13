#!/usr/bin/env bash
# =============================================================================
# init-ca.sh — Bootstrap the Smallstep CA UI certificate authority.
#
# Idempotent: safe to re-run. It will NOT overwrite an existing CA unless you
# pass --force (which wipes ./step-ca and starts over).
#
# What it does, using throwaway step-ca containers (no long-running service):
#   1. Generates a Root CA (EC P-521, ~20 years) and an Intermediate CA
#      (EC P-521, ~10 years).
#   2. Generates database and provisioner passwords.
#   3. Creates two provisioners:
#        - jwk  (JWK) — manual / scripted issuance
#        - acme              (ACME) — automated challenge-based issuance
#   4. Installs the leaf certificate template.
#   5. Writes a complete ca.json wired for PostgreSQL + CRL.
#   6. Decrypts the JWK provisioner key into volumes/stepca/secrets/revoke_jwk.json
#      so the dashboard can revoke certificates out of the box.
#
# After this, bring up the service with:  docker compose up -d
# =============================================================================

set -euo pipefail

# ---- Settings (edit to taste) ----------------------------------------------
DOMAIN="example.com"
CA_NAME="Smallstep CA UI"
CA_DNS="pki.${DOMAIN}"
ROOT_SUBJECT="Smallstep CA UI Root CA"
INT_SUBJECT="Smallstep CA UI Intermediate CA"
PROVISIONER_NAME="jwk"
ROOT_VALIDITY="175320h"        # ~20 years
INT_VALIDITY="87660h"          # ~10 years
STEP_IMAGE="smallstep/step-ca:latest"

STEP_DIR="./volumes/stepca"    # mounted into containers as /home/step
SECRETS_DIR="./secrets"

# ---- Colours ---------------------------------------------------------------
c()   { printf '\033[%sm%s\033[0m' "$1" "$2"; }
info() { echo "$(c '1;34' '[*]') $*"; }
ok()   { echo "$(c '1;32' '[+]') $*"; }
warn() { echo "$(c '1;33' '[!]') $*"; }
die()  { echo "$(c '1;31' '[x]') $*" >&2; exit 1; }

FORCE=0
[[ "${1:-}" == "--force" ]] && FORCE=1

# ---- Preconditions ---------------------------------------------------------
command -v docker >/dev/null || die "docker not found in PATH."
docker info >/dev/null 2>&1 || die "cannot talk to the Docker daemon."

# Offline vault for the root key + its password. NOT needed by the running CA;
# move it off this host after backup. Defined here so run_step can mount it.
OFFLINE_DIR="./root-ca-offline"

if [[ -d "$STEP_DIR/certs" && -f "$STEP_DIR/config/ca.json" && $FORCE -eq 0 ]]; then
    warn "An existing CA was found in $STEP_DIR."
    warn "Re-run with --force to wipe and regenerate (DESTROYS keys), or remove it manually."
    exit 0
fi

if [[ $FORCE -eq 1 ]]; then
    warn "--force: wiping generated CA material in $STEP_DIR (keeping config/templates)"
    rm -rf "$STEP_DIR/certs" "$STEP_DIR/secrets" "$STEP_DIR/db" "$STEP_DIR/config/ca.json" "$OFFLINE_DIR"
fi

mkdir -p "$STEP_DIR/certs" "$STEP_DIR/secrets" "$STEP_DIR/config/templates/certs/x509" "$STEP_DIR/db" "$SECRETS_DIR" "$OFFLINE_DIR"

# Run step commands as the current user so files aren't root-owned.
UIDGID="$(id -u):$(id -g)"
run_step() {
    # MSYS_NO_PATHCONV: on Git Bash for Windows, the shell auto-translates
    # leading-slash args (like the container-side "-w /home/step") into host
    # Windows paths, which breaks `docker run`. Disable that translation here.
    # -i: lets callers pipe data in (e.g. `crypto jwe decrypt` reads from stdin).
    MSYS_NO_PATHCONV=1 docker run --rm -i --user "$UIDGID" \
        -v "$(pwd)/${STEP_DIR#./}:/home/step" \
        -v "$(pwd)/${OFFLINE_DIR#./}:/offline" \
        -w /home/step \
        --entrypoint step \
        "$STEP_IMAGE" "$@"
}

# chmod on a Windows Docker Desktop bind mount from the host side does not
# reliably propagate to what containers see — the mode change must happen
# from inside a Linux container against the same mount.
chmod_in_container() {
    local mode="$1" hostfile="$2"
    local dir base
    dir="$(dirname "$hostfile")"
    base="$(basename "$hostfile")"
    MSYS_NO_PATHCONV=1 docker run --rm --user 0:0 \
        -v "$(pwd)/${dir#./}:/target" \
        --entrypoint chmod \
        "$STEP_IMAGE" "$mode" "/target/$base"
}

# ---- 1. Passwords ----------------------------------------------------------
info "Generating passwords…"
ROOT_KEY_PWD="$(openssl rand -base64 32 | tr -d '\n')"   # root key — kept OFFLINE
INT_KEY_PWD="$(openssl rand -base64 32 | tr -d '\n')"    # intermediate key — used online
PG_PWD="$(openssl rand -base64 24 | tr -d '/+=' | cut -c1-24)"
PROV_PWD="$(openssl rand -base64 24 | tr -d '\n')"

# Offline vault: everything about the root lives here and is NOT needed by the
# running CA. Keep this directory somewhere safe (removable media, secrets
# manager, sealed backup) and off the online CA host.

printf '%s' "$ROOT_KEY_PWD" > "$OFFLINE_DIR/root_password"      # root key password (offline)
printf '%s' "$INT_KEY_PWD"  > "$STEP_DIR/secrets/password"      # intermediate key password (online)
printf '%s' "$PG_PWD"       > "$SECRETS_DIR/pg_password.txt"     # postgres password
printf '%s' "$PROV_PWD"     > "$STEP_DIR/secrets/provisioner_pwd"
chmod 600 "$OFFLINE_DIR/root_password" "$STEP_DIR/secrets/password" \
          "$SECRETS_DIR/pg_password.txt" "$STEP_DIR/secrets/provisioner_pwd"
ok "Passwords written (root password isolated in ${OFFLINE_DIR}/)."

# ---- 2. Root CA ------------------------------------------------------------
# The root key is protected by its OWN password and will be moved offline once
# it has signed the intermediate. The running CA never uses it.
info "Creating Root CA (EC P-521, ${ROOT_VALIDITY})…"
run_step certificate create \
    --profile root-ca \
    --kty EC --curve P-521 \
    --not-after "$ROOT_VALIDITY" \
    --password-file /offline/root_password \
    "$ROOT_SUBJECT" certs/root_ca.crt secrets/root_ca_key
ok "Root CA created."

# ---- 3. Intermediate CA ----------------------------------------------------
# Signed BY the root (root key + root password), but the intermediate's own key
# is encrypted with the SEPARATE intermediate password (the one the CA uses).
info "Creating Intermediate CA (EC P-521, ${INT_VALIDITY})…"
run_step certificate create \
    --profile intermediate-ca \
    --kty EC --curve P-521 \
    --not-after "$INT_VALIDITY" \
    --ca certs/root_ca.crt \
    --ca-key secrets/root_ca_key \
    --ca-password-file /offline/root_password \
    --password-file /home/step/secrets/password \
    "$INT_SUBJECT" certs/intermediate_ca.crt secrets/intermediate_ca_key
ok "Intermediate CA created."

# Make the intermediate world-readable so the nginx AIA endpoint can serve it.
chmod_in_container 644 "$STEP_DIR/certs/intermediate_ca.crt"

# ---- 3b. Move the root key OFFLINE ----------------------------------------
# The online CA needs only: root_ca.crt (to publish the chain) + the
# intermediate key/cert. The root PRIVATE key must not stay on the CA host.
# We move it into the offline vault alongside its password. A copy of the root
# CERTIFICATE stays in step-ca/certs (public, needed to serve the chain).
info "Moving root private key offline…"
cp "$STEP_DIR/certs/root_ca.crt" "$OFFLINE_DIR/root_ca.crt"
mv "$STEP_DIR/secrets/root_ca_key" "$OFFLINE_DIR/root_ca_key"
chmod 600 "$OFFLINE_DIR/root_ca_key"
ok "Root key moved to ${OFFLINE_DIR}/ (remove this directory from the CA host after backup)."

# ---- 4. Provisioner JWK key ------------------------------------------------
# Generate a JWK keypair for the admin provisioner, encrypted with PROV_PWD.
info "Generating JWK provisioner key…"
run_step crypto jwk create \
    --kty EC --crv P-521 \
    --password-file /home/step/secrets/provisioner_pwd \
    config/admin_jwk.pub.json config/admin_jwk.key.json >/dev/null

# Extract the public JWK for embedding in ca.json.
ADMIN_JWK_PUB="$(cat "$STEP_DIR/config/admin_jwk.pub.json")"

# `step crypto jwk create` writes the encrypted private key in JWE JSON
# serialization (an object), but step-ca's ca.json expects the provisioner's
# "encryptedKey" as a JWE *compact* serialization string
# (protected.encrypted_key.iv.ciphertext.tag) — build that string here.
jwe_field() {
    grep -o "\"$2\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" "$1" | sed -E 's/.*: *"([^"]*)"/\1/'
}
JWE_FILE="$STEP_DIR/config/admin_jwk.key.json"
JWE_COMPACT="$(jwe_field "$JWE_FILE" protected).$(jwe_field "$JWE_FILE" encrypted_key).$(jwe_field "$JWE_FILE" iv).$(jwe_field "$JWE_FILE" ciphertext).$(jwe_field "$JWE_FILE" tag)"
ADMIN_JWK_ENC="\"$JWE_COMPACT\""
ADMIN_JWK_KID="$(grep -o '"kid"[[:space:]]*:[[:space:]]*"[^"]*"' "$STEP_DIR/config/admin_jwk.pub.json" | head -1 | sed -E 's/.*: *"([^"]*)"/\1/')"
ok "Provisioner key generated."

# Decrypt the private JWK so the dashboard can build revocation tokens without
# ever seeing the password. Written into $STEP_DIR/secrets, which is gitignored
# and mounted read-only into the pki-dashboard container by docker-compose.yml.
info "Preparing dashboard revocation key…"
REVOKE_JWK_JSON="$(printf '%s' "$JWE_COMPACT" | run_step crypto jwe decrypt --password-file /home/step/secrets/provisioner_pwd)"
cat > "$STEP_DIR/secrets/revoke_jwk.json" <<JSON
{"kid": "${ADMIN_JWK_KID}", "jwk": ${REVOKE_JWK_JSON}}
JSON
chmod_in_container 600 "$STEP_DIR/secrets/revoke_jwk.json"
ok "Dashboard revocation key written to ${STEP_DIR}/secrets/revoke_jwk.json."

# ---- 5. Leaf template ------------------------------------------------------
# The template is checked into the repo directly at its runtime location
# (kept out of the --force wipe above), so there is nothing to install here.
info "Checking leaf certificate template…"
[[ -f "$STEP_DIR/config/templates/certs/x509/leaf.tpl" ]] \
    || die "Missing template: $STEP_DIR/config/templates/certs/x509/leaf.tpl"
ok "Template present."

# ---- 6. ca.json ------------------------------------------------------------
info "Writing ca.json…"
ROOT_FP="$(run_step certificate fingerprint certs/root_ca.crt | tr -d '\n')"

# Compose the provisioners array using the generated JWK material.
cat > "$STEP_DIR/config/ca.json" <<JSON
{
    "root": "/home/step/certs/root_ca.crt",
    "federatedRoots": null,
    "crt": "/home/step/certs/intermediate_ca.crt",
    "key": "/home/step/secrets/intermediate_ca_key",
    "address": ":443",
    "insecureAddress": "",
    "dnsNames": ["${CA_DNS}"],
    "logger": { "format": "text" },
    "db": {
        "type": "postgresql",
        "dataSource": "postgresql://stepca:${PG_PWD}@pki-db:5432/stepca?sslmode=disable"
    },
    "crl": {
        "enabled": true,
        "generateOnRevoke": true,
        "cacheDuration": "24h0m0s",
        "renewPeriod": "6h0m0s"
    },
    "authority": {
        "provisioners": [
            {
                "type": "JWK",
                "name": "${PROVISIONER_NAME}",
                "key": ${ADMIN_JWK_PUB},
                "encryptedKey": ${ADMIN_JWK_ENC},
                "claims": {
                    "minTLSCertDuration": "24h0m0s",
                    "maxTLSCertDuration": "43800h0m0s",
                    "defaultTLSCertDuration": "17520h0m0s"
                },
                "options": {
                    "x509": { "templateFile": "config/templates/certs/x509/leaf.tpl" }
                }
            },
            {
                "type": "ACME",
                "name": "acme",
                "claims": {
                    "defaultTLSCertDuration": "2160h"
                },
                "options": {
                    "x509": { "templateFile": "config/templates/certs/x509/leaf.tpl" }
                }
            }
        ],
        "template": {},
        "backdate": "1m0s"
    },
    "tls": {
        "cipherSuites": [
            "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
        ],
        "minVersion": 1.2,
        "maxVersion": 1.3,
        "renegotiation": false
    },
    "commonName": "${CA_NAME}"
}
JSON
ok "ca.json written."

# Clean up the intermediate JWK scratch files (now embedded in ca.json).
rm -f "$STEP_DIR/config/admin_jwk.pub.json" "$STEP_DIR/config/admin_jwk.key.json"

# ---- 7. Publish AIA copy for nginx ----------------------------------------
cp "$STEP_DIR/certs/intermediate_ca.crt" ./volumes/nginx/intermediate_ca.crt
chmod_in_container 644 ./volumes/nginx/intermediate_ca.crt

# ---- Done ------------------------------------------------------------------
echo
ok "PKI initialised."
echo
echo "  Root CA fingerprint:"
echo "    $(c '1;36' "$ROOT_FP")"
echo
echo "  Provisioners:"
echo "    - ${PROVISIONER_NAME}   (JWK)  password in volumes/stepca/secrets/provisioner_pwd"
echo "    - acme  (ACME)"
echo
echo "  Next:"
echo "    1. Point ${CA_DNS} at this host (DNS or /etc/hosts)."
echo "    2. docker compose up -d"
echo "    3. Trust the root: volumes/stepca/certs/root_ca.crt"
echo
echo "  $(c '1;33' 'IMPORTANT — root key is now in ./root-ca-offline/')"
echo "    Back it up securely, then MOVE it off this host:"
echo "      - root_ca_key      (root private key)"
echo "      - root_password    (its password)"
echo "      - root_ca.crt      (copy of the root certificate)"
echo "    The running CA does NOT need them. You only need them again to issue a"
echo "    new intermediate (e.g. renewal in ~10 years) or to recover the PKI."
echo
warn "Keep volumes/stepca/secrets/ and secrets/ safe (intermediate key + passwords)."
warn "Move ./root-ca-offline/ to cold storage and remove it from this host."
warn "volumes/stepca/secrets/revoke_jwk.json holds a decrypted private key — never commit it."

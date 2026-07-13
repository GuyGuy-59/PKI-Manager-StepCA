"""
Service layer: talks to step-ca's own HTTP API (no subprocess, no docker
socket) to revoke and issue certificates, both via the "jwk" provisioner.
"""

import time
import uuid

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, ed25519
from cryptography.x509.oid import NameOID

import config

# Carries the requested cert type (server/client) into the leaf template via a
# private, non-critical CSR extension — see leaf.tpl.tmpl for the other half.
# Made-up private-use OID: never validated by anyone but our own template,
# and never copied into the issued certificate, so it just needs to not
# collide with a *real* extension in a CSR we generate ourselves.
CERT_TYPE_OID = x509.ObjectIdentifier("1.3.6.1.4.1.99999.1.1")

# Every key type step-ca's "step" CLI supports via --kty/--curve/--size.
KEY_TYPES = {
    "ec256": lambda: ec.generate_private_key(ec.SECP256R1()),
    "ec384": lambda: ec.generate_private_key(ec.SECP384R1()),
    "ec521": lambda: ec.generate_private_key(ec.SECP521R1()),
    "rsa2048": lambda: rsa.generate_private_key(public_exponent=65537, key_size=2048),
    "rsa3072": lambda: rsa.generate_private_key(public_exponent=65537, key_size=3072),
    "rsa4096": lambda: rsa.generate_private_key(public_exponent=65537, key_size=4096),
    "ed25519": lambda: ed25519.Ed25519PrivateKey.generate(),
}


def _jwk_alg(jwk: dict) -> str:
    if jwk.get("kty") == "EC":
        ec_algs = {"P-256": "ES256", "P-384": "ES384", "P-521": "ES512"}
        return ec_algs.get(jwk.get("crv"), "ES256")
    return "RS256"


def _build_provisioner_token(sub: str, audience_path: str, extra_claims: dict = None) -> str:
    """
    Builds a JWT signed with the "jwk" provisioner's key, for whichever
    step-ca endpoint expects it (/1.0/revoke, /1.0/sign, ...).
    Requires config.JWK_PROVISIONER_JWK (decrypted private key).
    """
    from jose import jwt  # python-jose; only imported if the feature is enabled

    jwk = config.JWK_PROVISIONER_JWK
    if not jwk:
        raise RuntimeError("JWK_PROVISIONER_JWK is not configured.")

    now = int(time.time())
    claims = {
        "aud": f"{config.CA_AUDIENCE}{audience_path}",
        "sub": sub,
        "iat": now,
        "nbf": now,
        "exp": now + 300,
        "jti": uuid.uuid4().hex,
        "iss": config.JWK_PROVISIONER_NAME,
        **(extra_claims or {}),
    }
    headers = {"kid": config.JWK_PROVISIONER_KID}
    return jwt.encode(claims, jwk, algorithm=_jwk_alg(jwk), headers=headers)


def revoke_via_api(serial: str) -> tuple:
    """Calls step-ca's POST /revoke. Returns (ok, message)."""
    # step-ca's /revoke wants a base-10 or "0x"-prefixed base-16 serial; our
    # serials are plain hex (see `format(cert.serial_number, "x")` in models.py).
    # The JWT "sub" claim must match the "serial" field's *normalized* form
    # (base-10), not the raw input, so convert here rather than send hex.
    ca_serial = str(int(serial, 16))
    try:
        token = _build_provisioner_token(ca_serial, "/1.0/revoke")
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


def _build_csr(key, cn: str, sans: list, cert_type: str) -> bytes:
    builder = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    )
    if sans:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]),
            critical=False,
        )
    builder = builder.add_extension(
        x509.UnrecognizedExtension(CERT_TYPE_OID, cert_type.encode()),
        critical=False,
    )
    # Ed25519/Ed448 sign with their own built-in hash — cryptography requires
    # algorithm=None for those, unlike EC/RSA which need an explicit hash.
    algorithm = None if isinstance(key, ed25519.Ed25519PrivateKey) else hashes.SHA256()
    csr = builder.sign(key, algorithm)
    return csr.public_bytes(serialization.Encoding.PEM)


def issue_certificate(cn: str, sans: list, key_type: str = "ec256", cert_type: str = "server") -> tuple:
    """
    Generates a keypair + CSR and has step-ca sign it via the "jwk"
    provisioner's HTTP /1.0/sign endpoint (the same flow `step ca certificate`
    uses under the hood). `cert_type` ("server" or "client") steers the leaf
    template's extKeyUsage — see CERT_TYPE_OID above. Returns (ok, result)
    where result is either {"cert_pem": ..., "chain_pem": ..., "key_pem": ...}
    or an error string.
    """
    sans = sans or [cn]
    if cn not in sans:
        sans = [cn, *sans]

    key = KEY_TYPES.get(key_type, KEY_TYPES["ec256"])()
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    csr_pem = _build_csr(key, cn, sans, cert_type).decode()

    try:
        # step-ca's JWK provisioner authorizes the CSR's SANs against this
        # token's own "sans" claim (defaulting to just [[sub]] if omitted) —
        # so the claim must list everything the CSR asks for, not just the CN.
        token = _build_provisioner_token(cn, "/1.0/sign", {"sans": sans})
    except Exception as e:
        return False, f"Could not generate token: {e}"

    url = f"{config.CA_URL}/1.0/sign"
    payload = {"csr": csr_pem, "ott": token}
    try:
        r = requests.post(url, json=payload, verify=config.CA_VERIFY, timeout=15)
    except requests.RequestException as e:
        return False, f"Could not reach the CA: {e}"

    if r.status_code not in (200, 201):
        return False, f"CA responded {r.status_code}: {r.text[:200]}"

    data = r.json()
    cert_pem = data.get("crt")
    ca_pem = data.get("ca")
    if not cert_pem:
        return False, "CA response did not include a certificate."

    return True, {
        "cert_pem": cert_pem,
        "chain_pem": cert_pem + (ca_pem or ""),
        "key_pem": key_pem,
    }

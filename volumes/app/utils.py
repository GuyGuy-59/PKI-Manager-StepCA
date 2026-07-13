"""
X.509 certificate parsing helpers.

Pure parsing only — no DB, no notion of "now" or revocation status. Callers
(models.py) combine this with DB state to build the app's CertInfo model.
"""

import datetime as dt
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID, ExtensionOID, ExtendedKeyUsageOID

# step-ca stamps every leaf cert with a private extension recording which
# provisioner (by name, e.g. "jwk" or "acme") signed the issuance request.
# `cryptography` has no ASN.1 module for it, so decode the small hand-rolled
# DER structure directly: SEQUENCE { INTEGER type, OCTET STRING name, ... }.
STEP_PROVISIONER_OID = x509.ObjectIdentifier("1.3.6.1.4.1.37476.9000.64.1")


def _der_read_tlv(data: bytes, pos: int):
    tag = data[pos]
    pos += 1
    length = data[pos]
    pos += 1
    if length & 0x80:
        n = length & 0x7F
        length = int.from_bytes(data[pos:pos + n], "big")
        pos += n
    value = data[pos:pos + length]
    return tag, value, pos + length


def parse_step_provisioner(cert) -> Optional[str]:
    try:
        ext = cert.extensions.get_extension_for_oid(STEP_PROVISIONER_OID)
        _, seq, _ = _der_read_tlv(ext.value.value, 0)
        _, _type_bytes, pos = _der_read_tlv(seq, 0)
        _, name_bytes, _ = _der_read_tlv(seq, pos)
        return name_bytes.decode("utf-8", errors="replace") or None
    except Exception:
        return None


def _parse_cert_type(cert) -> Optional[str]:
    """Server/client, read from the certificate's own extKeyUsage — not our
    internal CSR marker (see services.py), which never ends up in the issued
    cert, so this works for any certificate regardless of how it was issued."""
    try:
        eku = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value
    except x509.ExtensionNotFound:
        return None
    has_server = ExtendedKeyUsageOID.SERVER_AUTH in eku
    has_client = ExtendedKeyUsageOID.CLIENT_AUTH in eku
    if has_server and has_client:
        return "server+client"
    if has_server:
        return "server"
    if has_client:
        return "client"
    return None


def parse_certificate(pem_bytes: bytes) -> Optional[dict]:
    """Parse a PEM/DER certificate into a plain dict of derived fields.

    `not_before`/`not_after` are returned as tz-aware datetimes (not strings)
    so callers can do their own "now"-relative logic (days left, status).
    Returns None if the bytes aren't a readable certificate.
    """
    try:
        try:
            cert = x509.load_pem_x509_certificate(pem_bytes)
        except ValueError:
            cert = x509.load_der_x509_certificate(pem_bytes)
    except Exception:
        return None

    sans = []
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        sans = [str(n.value) for n in ext.value]
    except x509.ExtensionNotFound:
        pass
    except Exception:
        pass

    try:
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    except Exception:
        cn = sans[0] if sans else "(no CN)"

    subject_dn = cert.subject.rfc4514_string()
    issuer_dn = cert.issuer.rfc4514_string()
    provisioner = parse_step_provisioner(cert)

    is_ca = False
    try:
        bc = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
        is_ca = bool(bc.value.ca)
    except Exception:
        pass

    try:
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
    except AttributeError:
        not_before = cert.not_valid_before.replace(tzinfo=dt.timezone.utc)
        not_after = cert.not_valid_after.replace(tzinfo=dt.timezone.utc)

    serial = format(cert.serial_number, "x")

    try:
        pk = cert.public_key()
        key_type = type(pk).__name__.replace("PublicKey", "")
        if hasattr(pk, "key_size"):
            key_type += f"-{pk.key_size}"
    except Exception:
        key_type = "?"

    fingerprint_sha256 = cert.fingerprint(hashes.SHA256()).hex()

    return {
        "serial": serial,
        "subject_cn": cn,
        "subject_dn": subject_dn,
        "issuer_dn": issuer_dn,
        "sans": sans,
        "not_before": not_before,
        "not_after": not_after,
        "is_ca": is_ca,
        "key_type": key_type,
        "fingerprint_sha256": fingerprint_sha256,
        "provisioner": provisioner,
        "cert_type": _parse_cert_type(cert),
    }

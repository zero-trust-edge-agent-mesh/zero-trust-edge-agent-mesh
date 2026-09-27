"""Nested SPIFFE identity for partition-tolerant edge sites."""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass
from ipaddress import ip_address
from typing import Any, cast

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

UTC = dt.UTC


@dataclass(frozen=True, slots=True)
class SVID:
    spiffe_id: str
    site: str
    agent: str
    cert_pem: bytes
    key_pem: bytes
    chain_pem: tuple[bytes, ...]
    not_before: dt.datetime
    not_after: dt.datetime


@dataclass(frozen=True, slots=True)
class ValidationResult:
    ok: bool
    spiffe_id: str | None
    site: str | None
    reason: str


@dataclass(slots=True)
class _SiteCA:
    site: str
    key: EllipticCurvePrivateKey
    cert: x509.Certificate


def _now() -> dt.datetime:
    return dt.datetime.now(UTC)


def _key() -> EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def _pem_key(key: EllipticCurvePrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )


def _pem_cert(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def _subject(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _verify_signature(child: x509.Certificate, issuer: x509.Certificate) -> None:
    pub = issuer.public_key()
    if not isinstance(pub, ec.EllipticCurvePublicKey):
        raise InvalidSignature("issuer key is not ECDSA")
    algorithm = child.signature_hash_algorithm
    if algorithm is None:
        raise InvalidSignature("missing signature hash")
    pub.verify(child.signature, child.tbs_certificate_bytes, ec.ECDSA(algorithm))


class EdgePKI:
    """Root certificate authority for disconnected edge sites."""

    def __init__(self, trust_domain: str = "acme.test", *, now: dt.datetime | None = None) -> None:
        self.trust_domain = trust_domain
        base = now or _now()
        self.root_key = _key()
        self.root_cert = self._make_root(base)
        self._sites: dict[str, _SiteCA] = {}

    def _make_root(self, now: dt.datetime) -> x509.Certificate:
        subj = _subject(f"Zero Trust Edge Agent Mesh root {self.trust_domain}")
        return (
            x509.CertificateBuilder()
            .subject_name(subj)
            .issuer_name(subj)
            .public_key(self.root_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=1))
            .not_valid_after(now + dt.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
            .add_extension(
                x509.KeyUsage(True, False, False, False, False, True, True, False, False),
                critical=True,
            )
            .sign(self.root_key, hashes.SHA256())
        )

    def create_site(self, site: str, *, now: dt.datetime | None = None) -> bytes:
        if "/" in site or not site:
            raise ValueError("site must be a non-empty path segment")
        base = now or _now()
        key = _key()
        cert = (
            x509.CertificateBuilder()
            .subject_name(_subject(f"Zero Trust Edge Agent Mesh site {site}"))
            .issuer_name(self.root_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(base - dt.timedelta(minutes=1))
            .not_valid_after(base + dt.timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.KeyUsage(True, False, False, False, False, True, True, False, False),
                critical=True,
            )
            .sign(self.root_key, hashes.SHA256())
        )
        self._sites[site] = _SiteCA(site, key, cert)
        return _pem_cert(cert)

    def issue_svid(
        self,
        site: str,
        agent: str,
        *,
        ttl_s: int = 300,
        now: dt.datetime | None = None,
        dns_names: tuple[str, ...] = (),
        ip_addresses: tuple[str, ...] = (),
    ) -> SVID:
        if site not in self._sites:
            self.create_site(site, now=now)
        if "/" in agent or not agent:
            raise ValueError("agent must be a non-empty path segment")
        base = now or _now()
        ca = self._sites[site]
        key = _key()
        spiffe_id = f"spiffe://{self.trust_domain}/site/{site}/agent/{agent}"
        san_items: list[x509.GeneralName] = [x509.UniformResourceIdentifier(spiffe_id)]
        san_items.extend(x509.DNSName(name) for name in dns_names)
        san_items.extend(x509.IPAddress(ip_address(addr)) for addr in ip_addresses)
        cert = (
            x509.CertificateBuilder()
            .subject_name(_subject(f"{site}/{agent}"))
            .issuer_name(ca.cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(base - dt.timedelta(seconds=1))
            .not_valid_after(base + dt.timedelta(seconds=ttl_s))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(False, True, False, False, False, False, False, False, False),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage(
                    [ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.SERVER_AUTH]
                ),
                critical=False,
            )
            .add_extension(x509.SubjectAlternativeName(san_items), critical=False)
            .sign(ca.key, hashes.SHA256())
        )
        return SVID(
            spiffe_id,
            site,
            agent,
            _pem_cert(cert),
            _pem_key(key),
            (_pem_cert(ca.cert), _pem_cert(self.root_cert)),
            cert.not_valid_before_utc,
            cert.not_valid_after_utc,
        )

    def root_pem(self) -> bytes:
        return _pem_cert(self.root_cert)

    def site_pem(self, site: str) -> bytes:
        return _pem_cert(self._sites[site].cert)

    def validate_svid(
        self,
        cert_pem: bytes,
        chain_pem: tuple[bytes, ...],
        *,
        expected_site: str | None = None,
        at_time: dt.datetime | None = None,
    ) -> ValidationResult:
        try:
            if len(chain_pem) < 2:
                return ValidationResult(False, None, None, "chain_incomplete")
            leaf = x509.load_pem_x509_certificate(cert_pem)
            inter = x509.load_pem_x509_certificate(chain_pem[0])
            root = x509.load_pem_x509_certificate(chain_pem[-1])
            when = at_time or _now()
            for cert in (leaf, inter, root):
                if when < cert.not_valid_before_utc or when > cert.not_valid_after_utc:
                    return ValidationResult(False, None, None, "expired")
            if root.fingerprint(hashes.SHA256()) != self.root_cert.fingerprint(hashes.SHA256()):
                return ValidationResult(False, None, None, "wrong_root")
            _verify_signature(inter, root)
            _verify_signature(leaf, inter)
            uris = leaf.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            ).value.get_values_for_type(x509.UniformResourceIdentifier)
            spiffe_id = next(
                (uri for uri in uris if uri.startswith(f"spiffe://{self.trust_domain}/")), None
            )
            if spiffe_id is None:
                return ValidationResult(False, None, None, "spiffe_missing")
            prefix = f"spiffe://{self.trust_domain}/site/"
            if not spiffe_id.startswith(prefix):
                return ValidationResult(False, spiffe_id, None, "wrong_trust_domain")
            parts = spiffe_id[len(prefix) :].split("/")
            if len(parts) != 3 or parts[1] != "agent" or not parts[0] or not parts[2]:
                return ValidationResult(False, spiffe_id, None, "bad_spiffe_path")
            site = parts[0]
            cn = inter.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            if not str(cn).endswith(f" {site}"):
                return ValidationResult(False, spiffe_id, site, "site_constraint")
            if expected_site is not None and site != expected_site:
                return ValidationResult(False, spiffe_id, site, "unexpected_site")
            return ValidationResult(True, spiffe_id, site, "ok")
        except Exception as exc:
            return ValidationResult(False, None, None, exc.__class__.__name__)


def should_rotate(
    not_after: dt.datetime, *, now: dt.datetime | None = None, lead_s: int = 60
) -> bool:
    return (not_after - (now or _now())).total_seconds() <= lead_s


def attestation_quote(nonce: bytes, key: EllipticCurvePrivateKey) -> dict[str, bytes]:
    """Return a simulated Trusted Platform Module attestation-key quote."""
    h = hashes.Hash(hashes.SHA256())
    h.update(b"zero-trust-edge-agent-mesh-simulated-pcr")
    digest = h.finalize()
    signature = key.sign(nonce + digest, ec.ECDSA(hashes.SHA256()))
    return {"nonce": nonce, "pcr_digest": digest, "signature": signature}


def public_key_pem(key: EllipticCurvePrivateKey) -> bytes:
    pub: Any = key.public_key()
    return cast(
        bytes,
        pub.public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        ),
    )

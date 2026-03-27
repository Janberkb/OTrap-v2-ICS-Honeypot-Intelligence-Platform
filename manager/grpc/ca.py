"""
manager/grpc/ca.py — Internal Certificate Authority for sensor mTLS.

The Manager operates a self-signed CA whose sole purpose is to issue
short-lived client certificates to registered sensors. Sensors use these
certificates to authenticate themselves on subsequent gRPC connections.

Key design decisions:
- CA key is generated once and stored encrypted in the database
- Sensor certs are RSA-4096 with 1-year validity
- CN = "sensor-{sensor_id}" for audit traceability
- No external CA or PKI dependency
"""

from __future__ import annotations

import base64
import os
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


class CertificateAuthority:
    """
    Internal CA for OTrap sensor mTLS.

    Lifecycle:
    1. On first start, generate CA key + self-signed cert.
    2. Store CA key (encrypted) and cert (plain) in DB or env.
    3. On sensor join, issue a signed client cert for that sensor.
    4. On sensor revocation, note cert serial (revocation list not enforced
       at connection time — instead, Manager simply refuses the sensor's
       gRPC calls by checking sensor.status != 'active').
    """

    def __init__(self, ca_key_pem: bytes, ca_cert_pem: bytes) -> None:
        self._ca_key = serialization.load_pem_private_key(ca_key_pem, password=None)
        self._ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)

    # ── Factory methods ────────────────────────────────────────────────────────

    @classmethod
    def generate(cls) -> tuple["CertificateAuthority", bytes, bytes]:
        """
        Generate a new CA key pair and self-signed certificate.

        Returns:
            (ca_instance, ca_key_pem, ca_cert_pem)
        """
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
        )

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "OTrap Internal CA"),
            x509.NameAttribute(NameOID.COMMON_NAME, "otrap-manager"),
        ])

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc) - timedelta(hours=1))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=3650))  # 10 years
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_cert_sign=True,
                    key_encipherment=False,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                critical=False,
            )
            .sign(key, hashes.SHA256())
        )

        key_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)

        return cls(key_pem, cert_pem), key_pem, cert_pem

    @classmethod
    def from_env_or_generate(cls) -> tuple["CertificateAuthority", bytes, bytes]:
        """
        Load CA from environment variables, or generate a new one.

        Environment variables:
          GRPC_CA_KEY_B64  — base64-encoded PEM private key
          GRPC_CA_CERT_B64 — base64-encoded PEM certificate

        If either is missing, a new CA is generated and the caller is
        responsible for persisting the returned key/cert bytes.
        """
        key_b64  = os.environ.get("GRPC_CA_KEY_B64", "")
        cert_b64 = os.environ.get("GRPC_CA_CERT_B64", "")

        if key_b64 and cert_b64:
            key_pem  = base64.b64decode(key_b64)
            cert_pem = base64.b64decode(cert_b64)
            ca = cls(key_pem, cert_pem)
            return ca, key_pem, cert_pem

        return cls.generate()

    # ── Certificate issuance ──────────────────────────────────────────────────

    def issue_sensor_cert(self, sensor_id: str) -> tuple[bytes, bytes]:
        """
        Issue a client certificate for a sensor.

        Returns:
            (client_cert_pem, client_key_pem)
        """
        # Generate sensor-specific key pair
        sensor_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
        )

        subject = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "OTrap Sensor"),
            x509.NameAttribute(NameOID.COMMON_NAME, f"sensor-{sensor_id}"),
        ])

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self._ca_cert.subject)
            .public_key(sensor_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc) - timedelta(hours=1))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=True,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.CLIENT_AUTH]),
                critical=True,
            )
            .add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName(f"sensor-{sensor_id}"),
                    x509.DNSName("otrap-sensor"),
                ]),
                critical=False,
            )
            .sign(self._ca_key, hashes.SHA256())
        )

        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        key_pem = sensor_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )

        return cert_pem, key_pem

    def get_ca_cert_pem(self) -> bytes:
        return self._ca_cert.public_bytes(serialization.Encoding.PEM)

    def build_server_ssl_context(self) -> dict:
        """
        Build SSL context parameters for the gRPC server.
        Returns dict suitable for grpc.ssl_server_credentials().
        """
        import grpc

        ca_cert_pem = self._ca_cert.public_bytes(serialization.Encoding.PEM)

        # For the server cert, we reuse the CA cert (Manager's own identity)
        # In production you'd use a separate server cert signed by the CA
        server_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        server_cert = (
            x509.CertificateBuilder()
            .subject_name(self._ca_cert.subject)
            .issuer_name(self._ca_cert.subject)
            .public_key(server_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc) - timedelta(hours=1))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
            .add_extension(
                x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.SERVER_AUTH]),
                critical=True,
            )
            .add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName("otrap-manager"),
                    x509.DNSName("manager"),
                    x509.DNSName("localhost"),
                ]),
                critical=False,
            )
            .sign(self._ca_key, hashes.SHA256())
        )

        server_cert_pem = server_cert.public_bytes(serialization.Encoding.PEM)
        server_key_pem = server_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )

        return grpc.ssl_server_credentials(
            [(server_key_pem, server_cert_pem)],
            root_certificates=ca_cert_pem,
            require_client_auth=False,  # Join happens before the sensor has a client cert
        )

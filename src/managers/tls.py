#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Manager for handling tls."""

import logging
import os
import re
import socket
from pathlib import Path
import subprocess
import tempfile

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography import x509

from common.literals import CAS_SSL_CLIENT_CERT, CAS_SSL_CLIENT_KEY, CAS_SSL_PATH, CLIENT_MGMT_URL, TLSState, TLSType
from common.management_client import ManagementClient
from common.workload import WorkloadBase
from core.state import ApplicationState
from ops.pebble import ExecError

from charms.tls_certificates_interface.v4.tls_certificates import (
    PrivateKey,
    ProviderCertificate,
)

logger = logging.getLogger(__name__)

class TLSManager:
    """Manage all TLS related events."""

    DEFAULT_HASH_ALGORITHM: hashes.HashAlgorithm = hashes.SHA256()
    
    def __init__(self, state: ApplicationState, workload: WorkloadBase):
        self.state = state
        self.workload = workload
        self.management_client = ManagementClient(CLIENT_MGMT_URL)

    def set_tls_state(self, state: TLSState) -> None:
        """Set the TLS state.

        Args:
            state (TLSState): The TLS state.
        """
        logger.debug(f"Setting TLS state to {state}")
        self.state.unit.tls_state = state.value

    def set_cert_state(self, is_ready: bool) -> None:
        """Set the certificate state.

        Args:
            is_ready (bool): The certificate state.
        """
        self.state.unit.tls_cert_ready = is_ready

    def set_ca(self) -> None:
        self.workload.write_file(str(self.state.unit.ca), f"{CAS_SSL_PATH}/root-ca.pem")

    def set_certificate(self) -> None:
        self.workload.write_file(str(self.state.unit.certificate), f"{CAS_SSL_PATH}/unit.pem")

    def set_private_key(self) -> None:
        self.workload.write_file(str(self.state.unit.private_key), f"{CAS_SSL_PATH}/private.key")

    def set_truststore(self) -> None:
        try:
          self.workload.exec(
              command=[
                  "charmed-cassandra.keytool", "-import",
                  "-alias", f"unit-{self.state.unit.unit_name}",
                  "-file", "unit.pem",
                  "-keystore", "truststore.jks",
                  "-storepass", "mytrustpass",
                  "-noprompt",
              ],
              cwd=CAS_SSL_PATH,
          )
        except (subprocess.CalledProcessError, ExecError) as e:
          if e.stdout and "already exists" in e.stdout:
              return
          logger.error(e.stdout)
          raise e          

    def set_keystore(self) -> None:
        if not (
                all(
                    [
                        self.state.unit.ca,
                        self.state.unit.certificate,
                        self.state.unit.private_key
                    ]
                )
        ):
            logger.error("Can't set keystore, missing TLS artifacts.")
            return
    
        try:
            # Step 1: Generate PKCS12 from unit cert + key
            self.workload.exec(
                command=[
                    "openssl", "pkcs12", "-export",
                    "-in", "unit.pem",
                    "-inkey", "private.key",
                    "-out", "server.p12",
                    "-name", f"unit-{self.state.unit.unit_name}",
                    "-passout", "pass:mykeypass",
                ],
                cwd=CAS_SSL_PATH,
            )
    
            # Step 2: Import PKCS12 into keystore.jks
            self.workload.exec(
                command=[
                    "charmed-cassandra.keytool", "-importkeystore",
                    "-deststorepass", "mykeypass",
                    "-destkeypass", "mykeypass",
                    "-destkeystore", "keystore.jks",
                    "-srckeystore", "server.p12",
                    "-srcstoretype", "PKCS12",
                    "-srcstorepass", "mykeypass",
                    "-alias", f"unit-{self.state.unit.unit_name}",
                ],
                cwd=CAS_SSL_PATH,
            )
    
            # Step 3: Add root CA to the same keystore
            self.workload.exec(
                command=[
                    "charmed-cassandra.keytool", "-import",
                    "-alias", f"root-ca-{self.state.unit.unit_name}",
                    "-file", "root-ca.pem",
                    "-keystore", "keystore.jks",
                    "-storepass", "mykeypass",
                    "-noprompt"
                ],
                cwd=CAS_SSL_PATH,
            )
    
        except (subprocess.CalledProcessError, ExecError) as e:
            logger.error(f"Keystore setup failed: {e}")
            raise e
        
    def import_truststore(self, alias: str, filename: str) -> None:
        try:        
            self.workload.exec(
                command=[
                    "charmed-cassandra.keytool", "-import",
                    "-alias", alias,
                    "-file", filename,
                    "-keystore", "truststore.jks",
                    "-storepass", "mytrustpass",
                    "-noprompt",
                ],
                cwd=CAS_SSL_PATH,
            )
        except (subprocess.CalledProcessError, ExecError) as e:
            # in case this reruns and fails
            if e.stdout and "already exists" in e.stdout:
                logger.debug(e.stdout)
                return
            logger.error(e.stdout)
            raise e        

    def import_keystore(self) -> None:
        pass

    def reload_truststore(self) -> None:
        """Reloads the truststore using `mgmt-api`."""
        truststore_path = Path(CAS_SSL_PATH) / "truststore.jks"
        if not truststore_path.exists():
            logger.warning("Truststore does not exist at %s", truststore_path)
            return

        if not self.management_client.reload_truststore():
            logger.error("Failed to reload truststore")
            return

        logger.debug("Truststore reloaded")
        return
    
    @staticmethod
    def certificate_fingerprint(cert: str):
        """Returns the certificate fingerprint using SHA-256 algorithm."""
        cert_obj = x509.load_pem_x509_certificate(cert.encode("utf-8"), default_backend())
        hash_algorithm = cert_obj.signature_hash_algorithm or TLSManager.DEFAULT_HASH_ALGORITHM
        return cert_obj.fingerprint(hash_algorithm)    

    @staticmethod
    def keytool_hash_to_bytes(hash: str) -> bytes:
        """Converts a hash in the keytool format (AB:CD:0F:...) to a bytes object."""
        return bytes([int(s, 16) for s in hash.split(":")])    

    @property
    def trusted_certificates(self) -> dict[str, bytes]:
        """Returns a mapping of alias to certificate fingerprint (hash) for all certificates in the truststore."""
        truststore_path = Path(CAS_SSL_PATH) / "truststore.jks"
        if not truststore_path.exists():
            logger.warning("Truststore does not exist at %s", truststore_path)
            return {}
    
        command = [
            "charmed-cassandra.keytool",
            "-list",
            "-keystore", "truststore.jks",
            "-storepass", "mytrustpass",
            "-noprompt",
        ]
    
        stdout, _ = self.workload.exec(command=command, cwd=CAS_SSL_PATH)
    
        # Extract alias and SHA-256 fingerprint from keytool output
        matches = re.findall(
            r"(?m)^(.+?),.*?trustedCertEntry.*?^Certificate fingerprint \(SHA-256\): ([0-9A-F:]{95})",
            stdout
        )
    
        return {
            alias.strip(): self.keytool_hash_to_bytes(fingerprint)
            for alias, fingerprint in matches
        }

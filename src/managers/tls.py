#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Manager for handling tls."""

import logging
import socket
from pathlib import Path

from common.literals import CAS_SSL_CLIENT_CA, CAS_SSL_CLIENT_CERT, CAS_SSL_CLIENT_KEY, CLIENT_MGMT_URL, TLSState, TLSType
from common.management_client import ManagementClient
from common.workload import WorkloadBase
from core.state import ApplicationState

from charms.tls_certificates_interface.v4.tls_certificates import (
    PrivateKey,
    ProviderCertificate,
)

logger = logging.getLogger(__name__)

class TLSManager:
    """Manage all TLS related events."""
    
    def __init__(self, state: ApplicationState, workload: WorkloadBase):
        self.state = state
        self.workload = workload
        self.management_client = ManagementClient(CLIENT_MGMT_URL)

    def set_tls_state(self, state: TLSState, tls_type: TLSType) -> None:
        """Set the TLS state.

        Args:
            state (TLSState): The TLS state.
            tls_type (TLSType): The tls type type.
        """
        logger.debug(f"Setting {tls_type.value} TLS state to {state}")
        if tls_type == TLSType.CLIENT:
            self.state.unit.tls_client_state = state.value
        elif tls_type == TLSType.PEER:
            self.state.unit.tls_peer_state = state.value            

    def set_cert_state(self, cert_type: TLSType, is_ready: bool) -> None:
        """Set the certificate state.

        Args:
            cert_type (TLSType): The certificate type.
            is_ready (bool): The certificate state.
        """
        if cert_type == TLSType.CLIENT:        
            self.state.unit.tls_client_cert_ready = is_ready
        else:
            logger.error(f"Got invalid cert type: {cert_type.value}")
            return

    def write_certificate(self, certificate: ProviderCertificate, private_key: PrivateKey) -> None:
        """Write certificates to disk.

        Args:
            certificate (ProviderCertificate): The certificate.
            private_key (PrivateKey): The private key.
        """
        logger.debug("Writing certificates to disk")
        ca_cert = certificate.ca
        cert_type = TLSType(certificate.certificate.organization)
        if cert_type == TLSType.CLIENT:
            certificate_path = CAS_SSL_CLIENT_CERT
            private_key_path = CAS_SSL_CLIENT_KEY
        else:
            logger.error(f"Got invalid tls type: {cert_type}")
            return

        self.add_trusted_ca(ca_cert.raw, cert_type)
        self.workload.write_file(private_key.raw, private_key_path)
        self.workload.write_file(certificate.certificate.raw, certificate_path)
        self.set_cert_state(cert_type, is_ready=True)


    def add_trusted_ca(self, ca_cert: str, tls_type: TLSType = TLSType.PEER) -> None:
        """Add trusted CA to the truststore.

        Args:
            ca_cert (str): The CA certificate.
            tls_type (TLSType): The TLS type. Defaults to TLSType.PEER.
        """
        if tls_type == TLSType.CLIENT:
            ca_certs_path = CAS_SSL_CLIENT_CA
        else:
            logger.error(f"Got invalid tls type: {tls_type.value}")
            return

        cas = self.load_trusted_ca(tls_type)
        pass

    def load_trusted_ca(self, tls_type) -> list[str]:
        """Load trusted CA from the truststore.

        Args:
            tls_type (TLSType): The TLS type. Defaults to TLSType.PEER.
        """
        if tls_type == TLSType.CLIENT:
            ca_certs_path = Path(CAS_SSL_CLIENT_CA)
        else:
            logger.error(f"Got invalid tls type: {tls_type.value}")
            return []

        return []

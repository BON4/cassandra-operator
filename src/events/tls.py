#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""TODO."""

import base64
import logging
from pathlib import Path
import re
import tempfile

from ops import ActionEvent, RelationCreatedEvent, RelationJoinedEvent

from charms.tls_certificates_interface.v4.tls_certificates import (
    CertificateAvailableEvent,
    CertificateRequestAttributes,
    PrivateKey,
    TLSCertificatesRequiresV4,
)

from ops.framework import EventBase, Object, EventSource
from ops.model import ModelError, SecretNotFoundError


from common.literals import TLS_RELATION_NAME, ClusterState, TLSState, TLSType
from common.secrets import get_secret_from_id
from common.statuses import Status
from core.charm import CassandraCharmBase


logger = logging.getLogger(__name__)

class TLSEvents(Object):
    """Event handlers for related applications on the `certificates` relation interface."""

    def __init__(self, charm: CassandraCharmBase):
        super().__init__(charm, "tls")
        self.charm = charm
        host_mapping = self.charm.cluster_manager.get_host_mapping()
        peer_tls_common_name = f"{self.charm.unit.name}-{self.charm.model.uuid}"

        self.requier = TLSCertificatesRequiresV4(
            self.charm,
            TLS_RELATION_NAME,
            certificate_requests=[
                CertificateRequestAttributes(
                    common_name=peer_tls_common_name,
                    sans_ip=frozenset({host_mapping["ip"]}),
                    sans_dns=frozenset({self.charm.unit.name, host_mapping["hostname"]}),
                    organization=TLSType.PEER.value,
                ),
            ],
        )

        self.framework.observe(
            self.requier.on.certificate_available, self._on_certificate_available
        )
            
        self.framework.observe(
            self.charm.on[TLS_RELATION_NAME].relation_created, self._on_relation_created
        )

        self.framework.observe(
            self.charm.on[TLS_RELATION_NAME].relation_joined, self._on_relation_joined
        )

        self.framework.observe(
            self.charm.on.upload_client_certificate_action, self._on_upload_client_certificate
        )

    def _on_relation_created(self, event: RelationCreatedEvent) -> None:
        """Handle the `relation-created` event.

        Args:
            event (RelationCreatedEvent): The event object.
        """
        if not self.charm.unit.is_leader():
            return
        self.charm.tls_manager.set_tls_state(state=TLSState.TO_TLS)

    def _on_relation_joined(self, event: RelationJoinedEvent) -> None:
        """Handle the `relation-created` event.

        Args:
            event (RelationCreatedEvent): The event object.
        """
        if not self.charm.state.unit.is_started:
            event.defer()
            return

        self.charm.tls_manager.set_tls_state(state=TLSState.TO_TLS)
        
    def _on_certificate_available(self, event: CertificateAvailableEvent) -> None:  # noqa: C901
        """Handle the `certificates-available` event.

        Args:
            event (CertificateAvailableEvent): The event object.
        """
        cert = event.certificate
        cert_type = TLSType(cert.organization)
        logger.debug(f"Received certificate for {cert_type}")

        # cert contains t.pem, t_ca.pem
        # private_key contains t.key
        # t_ca.pem - is rootCa. It is the same across client-certificates and peer-certificates

        certs, private_key = self.requier.get_assigned_certificates()
        cert = certs[0]

        if private_key is None:
            logger.error("private key is None")
            return
        
        self.charm.state.unit.certificate = cert.certificate
        self.charm.state.unit.csr = cert.certificate_signing_request
        self.charm.state.unit.ca = cert.ca
        self.charm.state.unit.chain = cert.chain
        self.charm.state.unit.private_key = private_key

        self.charm.tls_manager.set_ca()
        self.charm.tls_manager.set_certificate()
        self.charm.tls_manager.set_private_key()
        self.charm.tls_manager.set_keystore()
        self.charm.tls_manager.set_truststore()

        self.charm.state.unit.tls_cert_ready = True

        self.charm.on.config_changed.emit()
        
    def read_and_validate_private_key(
        self, private_key_secret_id: str | None
    ) -> PrivateKey | None:
        """Read and validate the private key.

        Args:
            private_key_secret_id (str): The private key secret ID.

        Returns:
            PrivateKey: The private key.
        """

        if private_key_secret_id is None:
            logger.error(f"private_key_secret_id is None")
            return None
        
        try:
            secret_content = get_secret_from_id(self.charm.model, private_key_secret_id).get(
                "private-key"
            )
        except (ModelError, SecretNotFoundError) as e:
            logger.error(e)
            return None

        if secret_content is None:
            logger.error(f"Secret {private_key_secret_id} does not contain a private key.")
            return None

        private_key = (
            secret_content
            if re.match(r"(-+(BEGIN|END) [A-Z ]+-+)", secret_content)
            else base64.b64decode(secret_content).decode("utf-8").strip()
        )
        private_key = PrivateKey(raw=private_key)
        if not private_key.is_valid():
            logger.error("Invalid private key format.")
            return None

        return private_key

    def _on_upload_client_certificate(self, event: ActionEvent) -> None:
        client_cert = event.params.get("certificate")
        if not client_cert:
            logger.warning("no client certificate was provided on upload-client-certificate action")
            return
    
        fingerprint = self.charm.tls_manager.certificate_fingerprint(client_cert)
    
        trusted = self.charm.tls_manager.trusted_certificates
        if fingerprint in trusted.values():
            logger.info("Client certificate already trusted. Skipping.")
            return
        
        with tempfile.NamedTemporaryFile("w+", delete=False, suffix=".pem") as tmp:
            tmp.write(client_cert)
            tmp.flush()
            cert_path = Path(tmp.name)

        alias = f"client-{hash(fingerprint) & 0xFFFFFFFF}"
        try:
            self.charm.tls_manager.import_truststore(alias, str(cert_path))
            logger.info(f"Successfully imported client cert into truststore with alias {alias}")
        except Exception as e:
            logger.error(f"Failed to import client certificate: {e}")
            event.fail(f"Could not import client certificate: {str(e)}")
        finally:
            try:
                cert_path.unlink()
                logger.debug(f"Temporary certificate file {cert_path} deleted.")
            except Exception as e:
                logger.warning(f"Could not delete temporary certificate file {cert_path}: {e}")

        
    

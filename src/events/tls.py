#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""TODO."""

import base64
import logging
import re

from ops import RelationCreatedEvent

from charms.tls_certificates_interface.v4.tls_certificates import (
    CertificateAvailableEvent,
    CertificateRequestAttributes,
    PrivateKey,
    TLSCertificatesRequiresV4,
)

from ops.framework import EventBase, Object, EventSource
from ops.model import ModelError, SecretNotFoundError


from common.literals import CLIENT_TLS_RELATION_NAME, PEER_TLS_RELATION_NAME, ClusterState, TLSState, TLSType
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
        common_name = f"{self.charm.unit.name}-{self.charm.model.uuid}"
        client_private_key = None
        peer_private_key = None

        if client_private_key_id := self.charm.config.tls_client_private_key:
            if (
                client_private_key := self.read_and_validate_private_key(client_private_key_id)
            ) is None:
                # TODO: add cluster state error Status.TLS_INVALID_PRIVATE_KEY
                raise Exception("invalid client private key")

        if peer_private_key_id := self.charm.config.tls_peer_private_key:
            if (
                peer_private_key := self.read_and_validate_private_key(peer_private_key_id)
            ) is None:
                # TODO: add cluster state error Status.TLS_INVALID_PRIVATE_KEY
                raise Exception("invalid peer private key")

            
        self.client_certificate = TLSCertificatesRequiresV4(
            self.charm,
            CLIENT_TLS_RELATION_NAME,
            certificate_requests=[
                CertificateRequestAttributes(
                    common_name=common_name,
                    sans_ip=frozenset({host_mapping["ip"]}),
                    sans_dns=frozenset({self.charm.unit.name, host_mapping["hostname"]}),
                    organization=TLSType.CLIENT.value,
                ),
            ],
            private_key=client_private_key,
        )

        self.peer_certificate = TLSCertificatesRequiresV4(
            self.charm,
            PEER_TLS_RELATION_NAME,
            certificate_requests=[
                CertificateRequestAttributes(
                    common_name=common_name,
                    sans_ip=frozenset({host_mapping["ip"]}),
                    sans_dns=frozenset({self.charm.unit.name, host_mapping["hostname"]}),
                    organization=TLSType.PEER.value,
                ),
            ],
            private_key=peer_private_key,
        )

        
        for relation in [self.peer_certificate,self.client_certificate]:
            self.framework.observe(
                relation.on.certificate_available, self._on_certificate_available
            )
        
        for relation in [PEER_TLS_RELATION_NAME,CLIENT_TLS_RELATION_NAME]:
            self.framework.observe(
                self.charm.on[relation].relation_created, self._on_relation_created
            )

    def _on_relation_created(self, event: RelationCreatedEvent) -> None:
        """Handle the `relation-created` event.

        Args:
            event (RelationCreatedEvent): The event object.
        """
        if event.relation.name == CLIENT_TLS_RELATION_NAME:
            self.charm.tls_manager.set_tls_state(state=TLSState.TO_TLS, tls_type=TLSType.CLIENT)
        elif event.relation.name == PEER_TLS_RELATION_NAME:
            self.charm.tls_manager.set_tls_state(state=TLSState.TO_TLS, tls_type=TLSType.PEER)

    def _on_certificate_available(self, event: CertificateAvailableEvent) -> None:  # noqa: C901
        """Handle the `certificates-available` event.

        Args:
            event (CertificateAvailableEvent): The event object.
        """
        cert = event.certificate
        cert_type = TLSType(cert.organization)
        logger.debug(f"Received certificate for {cert_type}")

        relation_requirer = (
            self.peer_certificate if cert_type == TLSType.PEER else self.client_certificate
        )

        # cert contains t.pem, t_ca.pem
        # private_key contains t.key
        # t_ca.pem - is rootCa. It is the same across client-certificates and peer-certificates
        certs, private_key = relation_requirer.get_assigned_certificates()
        cert = certs[0]

        if private_key is None:
            logger.error("private key is None")
            return

        logger.debug(f"---------- CERT ----------\n {cert.to_json()}")
        logger.debug(f"---------- PKEY ----------\n {private_key.raw}")        

        # add t_ca.pem to truststore and node keystore
        # add t_ca.pem 

        
        
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
        

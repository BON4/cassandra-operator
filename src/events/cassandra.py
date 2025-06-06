import logging
import os
import re
import yaml
from typing import cast

from ops import (
    ActiveStatus,
    BlockedStatus,
    ConfigChangedEvent,
    Framework,
    InstallEvent,
    MaintenanceStatus,
    Object,
    RelationDataContent,
    StartEvent,
    UpdateStatusEvent,
    WaitingStatus,
    ActionEvent,
    main,
)

from charm import CassandraOperatorCharm
from charms.data_platform_libs.v0.data_models import TypedCharmBase
from charms.operator_libs_linux.v2 import snap
from config import CharmConfig
from constants import CAS_CONF_FILE, CAS_ENV_CONF_FILE, MGMT_API_DIR, PEER_RELATION
from data_model import AppPeerData, UnitPeerData

logger = logging.getLogger(__name__)


class CassandraEvents(Object):
    """Handle all base and cassandra related events."""

    def __init__(self, charm: CassandraOperatorCharm):
        super().__init__(charm, key="etcd_events")
        self.charm = charm

        self.framework.observe(self.on.start, self._on_start)
        self.framework.observe(self.on.install, self._on_install)
    
    def _on_install(self, _: InstallEvent) -> None:
        if not self.charm.workload.install():
            self.charm.set_status(Status.SERVICE_NOT_INSTALLED)
        return

    def _on_start(self, event: StartEvent) -> None:
        
        pass

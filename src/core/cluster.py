import logging
from typing import TYPE_CHECKING, Dict, Set

from charms.data_platform_libs.v0.data_interfaces import (
    DataPeerData,
    DataPeerOtherUnitData,
    DataPeerUnitData,
)

from constants import (
    SUBSTRATES,
    PEER_RELATION,
)

from ops import Object, Relation, Unit
from core.models import ClusterContext, UnitContext

from charm import CassandraOperatorCharm

logger = logging.getLogger(__name__)

class ApplicationState(Object):
    """Global state object for the cassandra cluster."""
    
    def __init__(self, charm: CassandraOperatorCharm, substrate: SUBSTRATES):
        super().__init__(parent=charm, key="charm_state")
        self.charm = charm
        self.substrate: SUBSTRATES = substrate
        self.peer_app_interface = DataPeerData(
            self.model, relation_name=PEER_RELATION,
        )
        self.peer_unit_interface = DataPeerUnitData(self.model, relation_name=PEER_RELATION)
    
    @property
    def peer_relation(self) -> Relation | None:
        """Get the cluster peer relation."""
        return self.model.get_relation(PEER_RELATION)

    @property
    def unit_context(self) -> UnitContext:
        """Get the server state of this unit."""
        return UnitContext(
            relation=self.peer_relation,
            data_interface=self.peer_unit_interface,
            component=self.model.unit,
            substrate=self.substrate,
        )

    @property
    def peer_units_data_interfaces(self) -> Dict[Unit, DataPeerOtherUnitData]:
        """Get unit data interface of all peer units from the cluster peer relation."""
        if not self.peer_relation or not self.peer_relation.units:
            return {}

        return {
            unit: DataPeerOtherUnitData(model=self.model, unit=unit, relation_name=PEER_RELATION)
            for unit in self.peer_relation.units
        }
    
    @property
    def cluster_context(self) -> ClusterContext:
        """Get the cluster context of the entire cassandra application."""
        return ClusterContext(
            relation=self.peer_relation,
            data_interface=self.peer_app_interface,
            component=self.model.app,
            substrate=self.substrate,
        )

    @property
    def nodes(self) -> Set[UnitContext]:
        """Get all nodes/units in the current peer relation, including this unit itself.

        Note: This is not to be confused with the list of cluster members.

        Returns:
            Set of CassadnraUnitContexts with their unit data.
        """
        if not self.peer_relation:
            return set()

        servers = set()
        for unit, data_interface in self.peer_units_data_interfaces.items():
            servers.add(
                UnitContext(
                    relation=self.peer_relation,
                    data_interface=data_interface,
                    component=unit,
                    substrate=self.substrate,
                )
            )
        servers.add(self.unit_context)

        return servers





import logging
from core.cluster import ApplicationState
from core.workload import WorkloadBase
from src.common.api_client import ApiClient
from src.core.models import Node
from common.client import CassandraClient

logger = logging.getLogger(__name__)

class ClusterManager:
    """Manage cluster members, quorum and authorization."""

    def __init__(self, state: ApplicationState, workload: WorkloadBase):
        self.state = state
        self.workload = workload
        self.cluster_endpoints = [server.peer_url for server in self.state.nodes]

    def node(self) -> Node:
        logger.debug(f"Getting node for unit {self.state.unit_context.node_name}")

        client = CassandraClient(
            self.cluster_endpoints,
        )

        node_list = client.node_list()

        if node_list is None:
            raise ValueError("member list command failed")
        if self.state.unit_context.node_name not in node_list:
            raise ValueError("member name not found")

        logger.debug(f"Member: {node_list[self.state.unit_context.node_name].id}")
        return node_list[self.state.unit_context.node_name]

    def is_healthy(self) -> bool:
        client = ApiClient(self.state.unit_context.client_mgmt_url)
        return client.is_healthy()

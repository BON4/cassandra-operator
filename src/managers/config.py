#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Manager for handling configuration building + writing."""

import logging
import re

import yaml

from common.config import CharmConfig
from common.literals import CAS_CONF_FILE, CAS_ENV_CONF_FILE, CAS_SSL_PATH, MGMT_API_DIR
from common.workload import WorkloadBase
from core.state import ApplicationState

logger = logging.getLogger(__name__)


class ConfigManager:
    """Handle the configuration of Cassandra."""

    def __init__(
        self,
        state: ApplicationState,
        workload: WorkloadBase,
    ):
        self.workload = workload
        self.state = state

    def reconcile(self, config: CharmConfig):
        """TODO."""
        self._render_cassandra_env_config(
            max_heap_size_mb=1024 if config.profile == "testing" else None,
        )

        self._render_cassandra_config(
            cluster_name=config.cluster_name,
            listen_address=self.state.unit.ip,
            tls_enabled=self.state.unit.tls_cert_ready
        )

    def _render_cassandra_config(self, cluster_name: str, listen_address: str, tls_enabled: bool) -> None:
        config_properties = yaml.safe_load(self.workload.read_file(CAS_CONF_FILE))

        if not isinstance(config_properties, dict):
            raise ValueError("Current cassandra config file is not valid")

        config_properties.update({"cluster_name": cluster_name})

        if listen_address:
            config_properties.update({"listen_address": listen_address})
            
            config_properties.update({
                "seed_provider": [
                    {
                        "class_name": "org.apache.cassandra.locator.SimpleSeedProvider",
                        "parameters": [
                            {"seeds": listen_address}
                        ]
                    }
                ]
            })
            

        if tls_enabled:
            config_properties.update({
                "server_encryption_options": {
                    "internode_encryption": "none",
                    "keystore": f"{CAS_SSL_PATH}/keystore.jks",
                    "keystore_password": "mykeypass",
                    "require_client_auth": True,
                    "truststore": f"{CAS_SSL_PATH}/truststore.jks",
                    "truststore_password": "mytrustpass",
                    "algorithm": "SunX509",
                    "store_type": "JKS",
                    "protocol": "TLS",
                },
                "client_encryption_options": {
                    "enabled": True,
                    "optional": False,
                    "keystore": f"{CAS_SSL_PATH}/keystore.jks",
                    "keystore_password": "mykeypass",
                    "require_client_auth": True,
                    "truststore": f"{CAS_SSL_PATH}/truststore.jks",
                    "truststore_password": "mytrustpass",
                    "algorithm": "SunX509",
                    "store_type": "JKS",
                    "protocol": "TLS",
                },
            })

            config_properties.update({"rpc_address": listen_address})
            
        self.workload.write_file(
            yaml.dump(config_properties, allow_unicode=True, default_flow_style=False),
            CAS_CONF_FILE,
        )

    def _render_cassandra_env_config(self, max_heap_size_mb: int | None) -> None:
        content = self.workload.read_file(CAS_ENV_CONF_FILE)

        content, _ = re.subn(
            pattern=r'^\s*#?MAX_HEAP_SIZE="[^"]*"$',
            repl=f'MAX_HEAP_SIZE="{max_heap_size_mb}M"'
            if max_heap_size_mb
            else '#MAX_HEAP_SIZE=""',
            string=content,
            count=1,
            flags=re.MULTILINE,
        )

        content, _ = re.subn(
            pattern=r'^\s*#?HEAP_NEWSIZE="[^"]*"$',
            repl=f'HEAP_NEWSIZE="{max_heap_size_mb // 2}M"'
            if max_heap_size_mb
            else '#HEAP_NEWSIZE=""',
            string=content,
            count=1,
            flags=re.MULTILINE,
        )

        mgmtapi_agent_line = (
            f'JVM_OPTS="$JVM_OPTS -javaagent:{MGMT_API_DIR}/libs/datastax-mgmtapi-agent.jar"'
        )
        if mgmtapi_agent_line not in content:
            content += f"\n{mgmtapi_agent_line}\n"

        content +="\nLOCAL_JMX=yes\n"
            
        self.workload.write_file(content, CAS_ENV_CONF_FILE)

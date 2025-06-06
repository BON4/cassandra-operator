from typing import Literal

SNAP_VAR_CURRENT_PATH = "/var/snap/cassandra/current"
SNAP_CURRENT_PATH = "/snap/cassandra/current"

SNAP_CONF_PATH = f"{SNAP_VAR_CURRENT_PATH}/etc"

CAS_CONF_PATH = f"{SNAP_CONF_PATH}/cassandra"

CAS_CONF_FILE = f"{CAS_CONF_PATH}/cassandra.yaml"
CAS_ENV_CONF_FILE = f"{CAS_CONF_PATH}/cassandra-env.sh"

MGMT_API_DIR = f"{SNAP_CURRENT_PATH}/opt/mgmt-api"

PEER_RELATION = "cassandra-peers"

SUBSTRATES = Literal["vm", "k8s"]
SUBSTRATE = "vm"

PEER_PORT = 7000
CLIENT_PORT = 9042
CLIENT_MGMT_PORT = 8080

SNAP_NAME = "cassandra"
SNAP_SERVICE = "mgmt-server"

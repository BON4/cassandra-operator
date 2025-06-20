#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""TODO."""

from enum import Enum
from typing import Literal

SNAP_VAR_CURRENT_PATH = "/var/snap/charmed-cassandra/current"
SNAP_CURRENT_PATH = "/snap/charmed-cassandra/current"

SNAP_CONF_PATH = f"{SNAP_VAR_CURRENT_PATH}/etc"

CAS_CONF_PATH = f"{SNAP_CONF_PATH}/cassandra"

CAS_CONF_FILE = f"{CAS_CONF_PATH}/cassandra.yaml"
CAS_ENV_CONF_FILE = f"{CAS_CONF_PATH}/cassandra-env.sh"

CAS_SSL_PATH = f"{SNAP_VAR_CURRENT_PATH}/etc/cassandra/ssl"
CAS_SSL_CLIENT_CERT = f"{CAS_SSL_PATH}/client.pem"
CAS_SSL_CLIENT_KEY = f"{CAS_SSL_PATH}/client.key"

MGMT_API_DIR = f"{SNAP_CURRENT_PATH}/opt/mgmt-api"

PEER_RELATION = "cassandra-peers"

DebugLevel = Literal["DEBUG", "INFO", "WARNING", "ERROR"]
SUBSTRATES = Literal["vm", "k8s"]

PEER_PORT = 7000
CLIENT_PORT = 9042
CLIENT_MGMT_URL = "http://127.0.0.1:8080/api/v0"

SNAP_NAME = "charmed-cassandra"
SNAP_SERVICE = "mgmt-server"

NODE_TLS_RELATION_NAME = "certificates"
TLS_RELATION_NAME = "certificates"

class ClusterState(Enum):
    """TODO."""

    ACTIVE = "active"

class TLSType(Enum):
    """TLS types."""

    PEER = "peer"
    CLIENT = "client"    
    

class UnitWorkloadState(Enum):
    """TODO."""

    STARTING = "starting"
    ACTIVE = "active"

class TLSState(Enum):
    """Collection of possible states for the TLS."""

    NO_TLS = "no-tls"
    TLS = "tls"
    TO_TLS = "to-tls"

    

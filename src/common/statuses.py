#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""TODO."""

from enum import Enum

from dataclasses import dataclass

from ops import ActiveStatus, BlockedStatus, MaintenanceStatus, StatusBase

from common.literals import DebugLevel

@dataclass
class StatusLevel:
    """Status object helper."""

    status: StatusBase
    log_level: DebugLevel

class Status(Enum):
    """Collection of possible statuses for the charm."""

    ACTIVE = ActiveStatus()
    INSTALLING = MaintenanceStatus("installing Cassandra")
    STARTING = MaintenanceStatus("waiting for Cassandra to start")
    INVALID_CONFIG = BlockedStatus("invalid config")


    TLS_INVALID_PRIVATE_KEY = StatusLevel(
        BlockedStatus("The private key provided is not valid. Please provide a valid private key"),
        "ERROR",
    )
    
    

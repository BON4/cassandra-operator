#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Charm the application."""

import logging

from ops import main

from core.charm import CassandraCharmBase
from events.cassandra import CassandraEvents
from events.tls import TLSEvents
from workload import CassandraWorkload

logger = logging.getLogger(__name__)


class CassandraCharm(CassandraCharmBase):
    """Charm the application."""

    def __init__(self, *args):
        super().__init__(CassandraWorkload(), *args)

        self.cassandra_events = CassandraEvents(self)
        self.tls_events = TLSEvents(self)


if __name__ == "__main__":  # pragma: nocover
    main(CassandraCharm)

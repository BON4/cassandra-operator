#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Charm config definition."""

from typing import Optional
from charms.data_platform_libs.v0.data_models import BaseConfigModel
from pydantic import field_validator
from pydantic import Field

from src.common.literals import TLSState


class CharmConfig(BaseConfigModel):
    """Manager for the structured configuration."""

    profile: str
    cluster_name: str
    tls_private_key: Optional[str] = Field(default=None)
    tls_enabled: Optional[str] = Field(default="true")    

    @field_validator("profile")
    @classmethod
    def profile_values(cls, value: str) -> str:
        """Check profile config option is one of `testing` or `production`."""
        if value not in ["testing", "production"]:
            raise ValueError("profile should be 'testing' or 'production'")

        return value

    @field_validator("cluster_name")
    @classmethod
    def cluster_name_values(cls, value: str) -> str:
        if len(value) == 0:
            raise ValueError("cluster_name cannot be empty")
        
        return value

    @field_validator("tls_private_key")
    @classmethod
    def tls_private_key_values(cls, value: str) -> Optional[str]:
        """TODO."""
        if len(value) == 0 or value == "null":
            return None

        return value

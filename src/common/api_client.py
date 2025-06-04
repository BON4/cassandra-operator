#!/usr/bin/env python3
import logging
import requests

from typing import List

logger = logging.getLogger(__name__)

class ApiClient:
    def __init__(
        self,
        host: str,
    ):
        self.base_url = f"http://{host}:8080/api/v0"


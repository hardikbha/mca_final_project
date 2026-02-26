"""Rate limiting setup using slowapi backed by Redis."""

from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["60/minute"],
    storage_uri=None,  # will be set from settings in main.py
)

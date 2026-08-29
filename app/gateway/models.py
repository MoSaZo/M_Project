"""
Data models for gateway network events.
"""

from dataclasses import dataclass
from datetime import datetime


@dataclass
class DNSRecord:
    """
    A DNS observation captured from the gateway interface.
    """

    timestamp: datetime
    query: str
    answer: str
    record_type: str
    source_ip: str
    destination_ip: str
    response: bool
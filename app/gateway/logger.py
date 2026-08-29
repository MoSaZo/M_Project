"""
CSV logging for gateway DNS records.
"""

import csv

from app.gateway.config import CSV_FILE
from app.gateway.models import DNSRecord


HEADER = [
    "Time",
    "Query",
    "Answer",
    "Type",
    "Source",
    "Destination",
    "Response",
]


def initialize() -> None:
    """
    Create the DNS log file and header if it does not exist.
    """

    CSV_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    if CSV_FILE.exists():
        return

    with CSV_FILE.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as file:
        writer = csv.writer(file)
        writer.writerow(HEADER)


def write(record: DNSRecord) -> None:
    """
    Append one DNS record to the CSV log.
    """

    initialize()

    with CSV_FILE.open(
        "a",
        newline="",
        encoding="utf-8",
    ) as file:
        writer = csv.writer(file)

        writer.writerow(
            [
                record.timestamp.isoformat(),
                record.query,
                record.answer,
                record.record_type,
                record.source_ip,
                record.destination_ip,
                record.response,
            ]
        )
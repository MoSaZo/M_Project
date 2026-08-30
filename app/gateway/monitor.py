"""
Live DNS monitoring through TShark/PyShark.
"""

import pyshark

from app.database.database import SessionLocal
from app.database.gateway_repository import GatewayEventRepository
from app.gateway.analyzer import GatewayAnalyzer
from app.gateway.collector import DNSCollector
from app.gateway.config import (
    DISPLAY_FILTER,
    INTERFACE,
    TSHARK_PATH,
)
from app.gateway.filters import should_filter
from app.gateway.logger import write
from app.gateway.parser import parse_packet


class DNSMonitor:

    def __init__(self):
        self.capture = pyshark.LiveCapture(
            interface=INTERFACE,
            tshark_path=TSHARK_PATH,
            display_filter=DISPLAY_FILTER,
        )

        self.collector = DNSCollector()
        self.analyzer = GatewayAnalyzer()

        self.analyzer = GatewayAnalyzer()
        self.repository_factory = GatewayEventRepository

    def process_record(self, record):
        """
        Analyze and persist a DNS record.
        """

        self.collector.add(record)

        result = self.analyzer.analyze(
            record,
        )

        db = SessionLocal()

        try:
            repository_factory = getattr(
                self,
                "repository_factory",
                GatewayEventRepository,
            )

            repository = repository_factory(
                db,
            )

            repository.create(
                record,
                result,
            )

        finally:
            db.close()

        write(record)

        return result

    def start(self):
        print("=" * 60)
        print("DNS Monitor")
        print("=" * 60)

        print("Listening...\n")

        for packet in self.capture.sniff_continuously():

            try:
                record = parse_packet(packet)

                if record is None:
                    continue

                if should_filter(record.query):
                    continue

                result = self.process_record(
                    record,
                )

                if record.response:
                    print(
                        f"[{record.timestamp:%H:%M:%S}] "
                        f"{record.query:<40} "
                        f"{record.answer} "
                        f"| {result.prediction} "
                        f"({result.score:.4f})"
                    )

            except Exception as e:
                print(e)
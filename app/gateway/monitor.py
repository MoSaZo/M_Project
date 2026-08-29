"""
Live DNS monitoring through TShark/PyShark.
"""

import pyshark

from app.gateway.config import (
    DISPLAY_FILTER,
    INTERFACE,
    TSHARK_PATH,
)
from app.gateway.logger import write
from app.gateway.parser import parse_packet


class DNSMonitor:

    def __init__(self):
        self.capture = pyshark.LiveCapture(
            interface=INTERFACE,
            tshark_path=TSHARK_PATH,
            display_filter=DISPLAY_FILTER,
        )

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

                write(record)

                if record.response:
                    print(
                        f"[{record.timestamp:%H:%M:%S}] "
                        f"{record.query:<40} "
                        f"{record.answer}"
                    )

            except Exception as e:
                print(e)

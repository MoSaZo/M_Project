"""
Live DNS monitoring through TShark/PyShark.

The monitor captures DNS traffic from the configured gateway
interface, analyzes DNS queries, persists the result, and
supports graceful shutdown.
"""

import asyncio
import threading

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
    """
    Live DNS monitor running on the gateway interface.
    """

    def __init__(self) -> None:
        self.capture = None

        self.collector = DNSCollector()
        self.analyzer = GatewayAnalyzer()
        self.repository_factory = GatewayEventRepository

        self._stop_event = threading.Event()
        self._running = False
        self._capture_started = False
        self._event_loop = None

    def process_record(self, record):
        """
        Analyze and persist a DNS record.
        """

        self.collector.add(record)

        result = self.analyzer.analyze(record)

        db = SessionLocal()

        try:
            repository = (
                self.repository_factory(db)
                if hasattr(self, "repository_factory")
                else GatewayEventRepository(db)
            )

            repository.create(
                record,
                result,
            )

            db.commit()

        finally:
            db.close()

        write(record)

        return result

    def start(self) -> None:
        """
        Start monitoring DNS traffic.

        This method blocks until stop() is called or the capture
        terminates.
        """

        if self._running:
            return

        self._running = True
        self._stop_event.clear()
        self._capture_started = False

        self._event_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._event_loop)

        try:
            self.capture = pyshark.LiveCapture(
                interface=INTERFACE,
                tshark_path=TSHARK_PATH,
                display_filter=DISPLAY_FILTER,
                eventloop=self._event_loop,
            )

            self._capture_started = True

            print("=" * 60)
            print("PhishGuard Gateway DNS Monitor")
            print("=" * 60)
            print(f"Interface : {INTERFACE}")
            print(f"Filter    : {DISPLAY_FILTER}")
            print("Status    : Listening...")
            print()

            for packet in self.capture.sniff_continuously():

                if self._stop_event.is_set():
                    break

                try:
                    record = parse_packet(packet)

                    if record is None:
                        continue

                    if should_filter(record.query):
                        continue

                    result = self.process_record(record)

                    if record.response:
                        print(
                            f"[{record.timestamp:%H:%M:%S}] "
                            f"{record.query:<40} "
                            f"{record.answer} "
                            f"| {result.prediction} "
                            f"({result.score:.4f})"
                        )

                except Exception as exc:
                    print(
                        f"[Gateway] Packet processing error: {exc}"
                    )

        except Exception as exc:
            if not self._stop_event.is_set():
                print(
                    f"[Gateway] Capture error: {exc}"
                )

        finally:
            if self.capture is not None and self._capture_started:
                try:
                    self._event_loop.run_until_complete(
                        self.capture.close_async()
                    )
                except Exception as exc:
                    print(
                        f"[Gateway] Capture close error: {exc}"
                    )

            self._capture_started = False
            self.capture = None

            if self._event_loop is not None:
                try:
                    self._event_loop.close()
                except Exception:
                    pass

            self._event_loop = None
            self._running = False

    def stop(self) -> None:
        """
        Stop the live capture gracefully.
        """

        if not self._running:
            return

        print("\n[Gateway] Stopping DNS monitor...")

        self._stop_event.set()

        if (
            self._capture_started
            and self.capture is not None
            and self._event_loop is not None
        ):
            try:
                future = asyncio.run_coroutine_threadsafe(
                    self.capture.close_async(),
                    self._event_loop,
                )

                future.result(timeout=5)

            except Exception as exc:
                print(
                    f"[Gateway] Capture close error: {exc}"
                )

        print("[Gateway] DNS monitor stopped.")

    @property
    def running(self) -> bool:
        """
        Return whether the monitor is currently running.
        """

        return self._running
"""
Thread-safe DNS record collector.
"""

from queue import Empty
from queue import Queue

from app.gateway.models import DNSRecord


class DNSCollector:
    """
    Thread-safe FIFO collector for DNS records.
    """

    def __init__(self) -> None:
        self._queue: Queue[DNSRecord] = Queue()

    def add(self, record: DNSRecord) -> None:
        self._queue.put(record)

    def pop(self) -> DNSRecord | None:
        try:
            return self._queue.get_nowait()
        except Empty:
            return None

    def empty(self) -> bool:
        return self._queue.empty()

    def size(self) -> int:
        return self._queue.qsize()

    def clear(self) -> None:
        while not self._queue.empty():
            self._queue.get_nowait()
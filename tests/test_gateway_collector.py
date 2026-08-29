from app.gateway.collector import DNSCollector
from app.gateway.models import DNSRecord

from datetime import datetime


def make_record(query="google.com"):
    return DNSRecord(
        timestamp=datetime.now(),
        query=query,
        answer="8.8.8.8",
        record_type="A",
        source_ip="1.1.1.1",
        destination_ip="8.8.8.8",
        response=True,
    )


def test_new_collector_is_empty():
    collector = DNSCollector()
    assert collector.empty()


def test_add_one_record():
    collector = DNSCollector()

    record = make_record()

    collector.add(record)

    assert collector.size() == 1


def test_pop_returns_record():
    collector = DNSCollector()

    record = make_record()

    collector.add(record)

    result = collector.pop()

    assert result == record


def test_fifo_order():
    collector = DNSCollector()

    first = make_record("a.com")
    second = make_record("b.com")

    collector.add(first)
    collector.add(second)

    assert collector.pop() == first
    assert collector.pop() == second


def test_clear():
    collector = DNSCollector()

    collector.add(make_record())

    collector.clear()

    assert collector.empty()


def test_size():
    collector = DNSCollector()

    collector.add(make_record("a"))
    collector.add(make_record("b"))
    collector.add(make_record("c"))

    assert collector.size() == 3
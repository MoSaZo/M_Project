from datetime import datetime
from unittest.mock import Mock

from app.gateway.models import DNSRecord
from app.gateway.monitor import DNSMonitor


def make_record(query="example.com"):
    return DNSRecord(
        timestamp=datetime.now(),
        query=query,
        answer="1.2.3.4",
        record_type="A",
        source_ip="1.1.1.1",
        destination_ip="8.8.8.8",
        response=True,
    )


def test_monitor_has_analyzer(monkeypatch):
    monkeypatch.setattr(
        "app.gateway.monitor.pyshark.LiveCapture",
        Mock(),
    )

    monitor = DNSMonitor()

    assert hasattr(monitor, "analyzer")

def test_process_record_analyzes_dns_record():
    monitor = DNSMonitor.__new__(DNSMonitor)

    monitor.analyzer = Mock()
    monitor.collector = Mock()

    repository = Mock()
    monitor.repository_factory = Mock(
        return_value=repository,
    )
    record = make_record()

    monitor.process_record(record)

    monitor.collector.add.assert_called_once_with(record)
    monitor.analyzer.analyze.assert_called_once_with(record)


def test_process_record_returns_analysis_result():
    monitor = DNSMonitor.__new__(DNSMonitor)

    monitor.analyzer = Mock()
    monitor.collector = Mock()

    repository = Mock()
    monitor.repository_factory = Mock(
        return_value=repository,
    )

    expected = Mock()
    monitor.analyzer.analyze.return_value = expected

    result = monitor.process_record(make_record())

    assert result is expected

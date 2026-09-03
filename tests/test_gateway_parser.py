from datetime import datetime

from app.gateway.models import DNSRecord
from app.gateway.parser import parse_packet


class FakeDNS:
    qry_name = "example.com"
    flags_response = "1"
    a = "93.184.216.34"


class FakeIP:
    src = "192.168.1.10"
    dst = "8.8.8.8"


class FakePacket:
    dns = FakeDNS()
    ip = FakeIP()


class PacketWithoutDNS:
    pass


class PacketWithoutIP:
    dns = FakeDNS()


def test_parse_dns_response():
    record = parse_packet(FakePacket())

    assert isinstance(record, DNSRecord)
    assert record.query == "example.com"
    assert record.answer == "93.184.216.34"
    assert record.record_type == "A"
    assert record.source_ip == "192.168.1.10"
    assert record.destination_ip == "8.8.8.8"
    assert record.response is True
    assert isinstance(record.timestamp, datetime)


def test_parse_packet_without_dns_returns_none():
    record = parse_packet(PacketWithoutDNS())

    assert record is None


def test_parse_packet_without_ip_returns_none():
    record = parse_packet(PacketWithoutIP())

    assert record is None

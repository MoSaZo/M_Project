from app.gateway.filters import should_filter


def test_normal_domain_is_not_filtered():
    assert should_filter("google.com") is False


def test_subdomain_is_not_filtered():
    assert should_filter("login.example.com") is False


def test_localhost_is_filtered():
    assert should_filter("localhost") is True


def test_local_domain_is_filtered():
    assert should_filter("printer.local") is True


def test_localdomain_is_filtered():
    assert should_filter("device.localdomain") is True


def test_ipv4_reverse_dns_is_filtered():
    assert should_filter("10.1.168.192.in-addr.arpa") is True


def test_ipv6_reverse_dns_is_filtered():
    assert should_filter(
        "b.a.9.8.7.6.ip6.arpa"
    ) is True


def test_mdns_domain_is_filtered():
    assert should_filter("something.local") is True


def test_empty_query_is_filtered():
    assert should_filter("") is True


def test_none_query_is_filtered():
    assert should_filter(None) is True


def test_domain_is_case_insensitive():
    assert should_filter("PRINTER.LOCAL") is True

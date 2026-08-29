"""
DNS record filtering utilities.
"""


def should_filter(query: str | None) -> bool:
    """
    Return True when a DNS query should be ignored.

    Local and reverse-DNS queries are excluded because they are
    not useful for external-domain analysis.
    """

    if not query:
        return True

    query = query.strip().lower().rstrip(".")

    if not query:
        return True

    if query == "localhost":
        return True

    if query.endswith(".local"):
        return True

    if query.endswith(".localdomain"):
        return True

    if query.endswith(".in-addr.arpa"):
        return True

    if query.endswith(".ip6.arpa"):
        return True

    return False
from datetime import datetime

from app.gateway.models import DNSRecord


def parse_packet(packet) -> DNSRecord | None:
    """
    Convert a PyShark packet into a DNSRecord.
    Return None if the packet is not usable.
    """

    try:

        if not hasattr(packet, "dns"):
            return None

        dns = packet.dns

        query = getattr(dns, "qry_name", "")

        response = (
            getattr(dns, "flags_response", "0") == "1"
        )

        answer = getattr(dns, "a", "")

        source_ip = getattr(packet.ip, "src", "")

        destination_ip = getattr(packet.ip, "dst", "")

        return DNSRecord(
            timestamp=datetime.now(),
            query=query,
            answer=answer,
            record_type="A",
            source_ip=source_ip,
            destination_ip=destination_ip,
            response=response,
        )

    except AttributeError:
        return None

    except Exception:
        return None
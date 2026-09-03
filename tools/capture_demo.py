import pyshark


def main() -> None:
    capture = pyshark.LiveCapture(
        interface="Wi-Fi",
        tshark_path=r"C:\Program Files\Wireshark\tshark.exe",
        display_filter="dns",
    )

    print("Waiting for DNS...")

    for packet in capture.sniff_continuously():
        try:
            print("=" * 50)
            print(packet.highest_layer)

            if hasattr(packet, "dns"):
                dns = packet.dns

                if hasattr(dns, "qry_name"):
                    print("Query :", dns.qry_name)

                if hasattr(dns, "a"):
                    print("A Record :", dns.a)

        except Exception as exc:
            print(exc)


if __name__ == "__main__":
    main()
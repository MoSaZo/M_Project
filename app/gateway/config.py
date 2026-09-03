"""
Gateway collector configuration.
"""

from pathlib import Path


TSHARK_PATH = r"C:\Program Files\Wireshark\tshark.exe"

INTERFACE = "Wi-Fi"

DISPLAY_FILTER = "dns"


BASE_DIR = Path(__file__).resolve().parents[2]

LOG_DIR = BASE_DIR / "logs"

CSV_FILE = LOG_DIR / "dns_log.csv"
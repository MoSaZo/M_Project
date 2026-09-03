import sqlite3
from pathlib import Path

DB_PATH = Path("phishing.db")


def main() -> None:
    if not DB_PATH.exists():
        raise FileNotFoundError(
            f"Database not found: {DB_PATH}"
        )

    connection = sqlite3.connect(DB_PATH)

    try:
        cursor = connection.cursor()

        columns = {
            row[1]
            for row in cursor.execute(
                "PRAGMA table_info(gateway_events)"
            ).fetchall()
        }

        if "probability" not in columns:
            cursor.execute("""
                ALTER TABLE gateway_events
                ADD COLUMN probability FLOAT
                NOT NULL DEFAULT 0.0
            """)

        if "risk_score" not in columns:
            cursor.execute("""
                ALTER TABLE gateway_events
                ADD COLUMN risk_score INTEGER
                NOT NULL DEFAULT 0
            """)

        if "risk_level" not in columns:
            cursor.execute("""
                ALTER TABLE gateway_events
                ADD COLUMN risk_level VARCHAR(30)
                NOT NULL DEFAULT 'Safe'
            """)

        connection.commit()

        print("Gateway database updated successfully.")

    finally:
        connection.close()


if __name__ == "__main__":
    main()
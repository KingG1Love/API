"""
Task 5: Fill PostgreSQL database from result_task_2.json

Usage:
    DB_URL=postgresql://postgres:qwe123@localhost:5432/laba2 python fill_db.py

Environment variables:
    DB_URL  - PostgreSQL DSN (default: postgresql://postgres:qwe123@localhost:5432/laba2)
"""

import json
import os
import sys
from pathlib import Path

import psycopg

DB_URL = os.getenv("DB_URL", "postgresql://postgres:qwe123@localhost:5432/laba2")
DATA_FILE = "result_task_2.json"


def load_data(path: str):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def fill_database(data: list, conn: psycopg.Connection) -> None:
    with conn.cursor() as cur:
        for row in data:
            # ── vulnerability ──────────────────────────────────────────────
            cur.execute(
                """
                INSERT INTO vulnerability
                    (name, vendor_release_date, vendor_release_url, url,
                     published_date, updated_date, description)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (name) DO UPDATE SET
                    vendor_release_date = EXCLUDED.vendor_release_date,
                    vendor_release_url  = EXCLUDED.vendor_release_url,
                    url                 = EXCLUDED.url,
                    published_date      = EXCLUDED.published_date,
                    updated_date        = EXCLUDED.updated_date,
                    description         = EXCLUDED.description
                RETURNING id
                """,
                (
                    row["ID"],
                    row["vendor_release_date"],
                    row["vendor_release_url"],
                    row["url"],
                    row["published_date"],
                    row["updated_date"],
                    row["description"],
                ),
            )
            vuln_id: int = cur.fetchone()[0]

            # ── cvss_score ─────────────────────────────────────────────────
            for cvss in row.get("cvss_list", []):
                cur.execute(
                    """
                    INSERT INTO cvss_score (vulnerability_id, version, score, vector, severity)
                    VALUES (%s, %s, %s, %s, %s)
                    ON CONFLICT (vulnerability_id, version, vector) DO UPDATE SET
                        score    = EXCLUDED.score,
                        severity = EXCLUDED.severity
                    """,
                    (
                        vuln_id,
                        cvss["version"],
                        cvss.get("score"),
                        cvss["vector"],
                        cvss["severity"],
                    ),
                )

            # ── cpe ────────────────────────────────────────────────────────
            for cpe_str in row.get("cpe_list", []):
                cur.execute(
                    """
                    INSERT INTO cpe (name) VALUES (%s)
                    ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name
                    RETURNING id
                    """,
                    (cpe_str,),
                )
                cpe_id: int = cur.fetchone()[0]
                cur.execute(
                    """
                    INSERT INTO vulnerability_cpe (vulnerability_id, cpe_id)
                    VALUES (%s, %s)
                    ON CONFLICT DO NOTHING
                    """,
                    (vuln_id, cpe_id),
                )

            # ── cwe ────────────────────────────────────────────────────────
            for cwe_key, cwe_info in row.get("cwe", {}).items():
                cur.execute(
                    """
                    INSERT INTO cwe (name, title, description)
                    VALUES (%s, %s, %s)
                    ON CONFLICT (name) DO UPDATE SET
                        title       = EXCLUDED.title,
                        description = EXCLUDED.description
                    RETURNING id
                    """,
                    (cwe_key, cwe_info.get("name", cwe_key), cwe_info.get("description", "")),
                )
                cwe_id: int = cur.fetchone()[0]
                cur.execute(
                    """
                    INSERT INTO vulnerability_cwe (vulnerability_id, cwe_id)
                    VALUES (%s, %s)
                    ON CONFLICT DO NOTHING
                    """,
                    (vuln_id, cwe_id),
                )

    conn.commit()


def main() -> None:
    if not Path(DATA_FILE).exists():
        print(f"ERROR: {DATA_FILE} not found. Run task_2.py first.")
        sys.exit(1)

    data = load_data(DATA_FILE)
    print(f"Loaded {len(data)} CVE records from {DATA_FILE}")

    print(f"Connecting to {DB_URL} ...")
    try:
        with psycopg.connect(DB_URL) as conn:
            fill_database(data, conn)
    except psycopg.OperationalError as exc:
        print(f"DB connection error: {exc}")
        sys.exit(1)

    print("Database filled successfully.")


if __name__ == "__main__":
    main()

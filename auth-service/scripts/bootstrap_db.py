import os
import time
from pathlib import Path

import psycopg


DATABASE_URL = os.environ["DATABASE_URL"]
MIGRATIONS_DIR = Path(__file__).resolve().parent.parent / "migrations"


def wait_for_database():
    last_error = None
    for _ in range(30):
        try:
            with psycopg.connect(DATABASE_URL) as connection:
                with connection.cursor() as cursor:
                    cursor.execute("SELECT 1")
                return
        except psycopg.OperationalError as exc:
            last_error = exc
            time.sleep(1)
    raise last_error


def ensure_migration_table(connection):
    with connection.cursor() as cursor:
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version TEXT PRIMARY KEY,
                applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
            """
        )


def applied_versions(connection):
    with connection.cursor() as cursor:
        cursor.execute("SELECT version FROM schema_migrations")
        return {row[0] for row in cursor.fetchall()}


def run_migrations():
    wait_for_database()
    with psycopg.connect(DATABASE_URL) as connection:
        ensure_migration_table(connection)
        done = applied_versions(connection)
        for path in sorted(MIGRATIONS_DIR.glob("*.sql")):
            if path.name in done:
                continue
            with connection.cursor() as cursor:
                cursor.execute(path.read_text())
                cursor.execute(
                    "INSERT INTO schema_migrations (version) VALUES (%s)",
                    (path.name,),
                )
            connection.commit()


if __name__ == "__main__":
    run_migrations()

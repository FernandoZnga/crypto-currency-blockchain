import os
import time
from pathlib import Path

import psycopg
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec


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


def generate_keypair():
    private_key = ec.generate_private_key(ec.SECP256K1())
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    return private_pem, public_pem


def backfill_wallet_keys(connection):
    with connection.cursor() as cursor:
        cursor.execute(
            """
            SELECT wallet_id::text AS wallet_id
            FROM wallets
            WHERE public_key_pem IS NULL OR private_key_pem IS NULL
            """
        )
        missing = cursor.fetchall()
        for row in missing:
            private_pem, public_pem = generate_keypair()
            cursor.execute(
                """
                UPDATE wallets
                SET public_key_pem = %s, private_key_pem = %s
                WHERE wallet_id = %s
                """,
                (public_pem, private_pem, row[0]),
            )


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
        backfill_wallet_keys(connection)
        connection.commit()


if __name__ == "__main__":
    run_migrations()

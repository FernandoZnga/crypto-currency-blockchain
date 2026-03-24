import base64
import hashlib
import json
import os
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse
from urllib.error import HTTPError, URLError
from http.client import RemoteDisconnected
from urllib.request import Request, urlopen

import psycopg
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from psycopg.rows import dict_row


PORT = int(os.getenv("PORT", "8002"))
DATABASE_URL = os.environ["DATABASE_URL"]
DEFAULT_NODE_URL = os.getenv("DEFAULT_NODE_URL", "http://blockchain-node-1:8101").rstrip("/")
AUDIT_SERVICE_URL = os.getenv("AUDIT_SERVICE_URL", "").rstrip("/")
SERVICE_NAME = "wallet-service"
METRICS = {
    "wallet_create_success_total": 0,
    "wallet_create_conflict_total": 0,
    "transaction_sign_success_total": 0,
    "transaction_sign_failure_total": 0,
}


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def get_connection():
    return psycopg.connect(DATABASE_URL, row_factory=dict_row)


def stable_hash(payload):
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()


def increment_metric(name, amount=1):
    METRICS[name] = METRICS.get(name, 0) + amount


def metrics_text():
    lines = [
        "# HELP service_events_total Total wallet service events by counter name.",
        "# TYPE service_events_total counter",
    ]
    for metric_name, value in sorted(METRICS.items()):
        lines.append(f'service_events_total{{service="{SERVICE_NAME}",metric="{metric_name}"}} {value}')
    return "\n".join(lines) + "\n"


def emit_audit_event(event):
    if not AUDIT_SERVICE_URL:
        return
    request = Request(
        f"{AUDIT_SERVICE_URL}/events",
        data=json.dumps(event).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=2):
            return
    except (HTTPError, URLError, TimeoutError, json.JSONDecodeError):
        return


def generate_keypair():
    private_key = ec.generate_private_key(ec.SECP256K1())
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    return private_pem, public_pem


def address_for_public_key(public_pem):
    digest = hashlib.sha256(public_pem.encode("utf-8")).hexdigest()
    return f"edu-{digest[:24]}"


def load_private_key(private_pem):
    return serialization.load_pem_private_key(private_pem.encode("utf-8"), password=None)


def canonical_tx_payload(sender, recipient, amount, nonce, public_key):
    return {
        "type": "payment",
        "sender": sender,
        "recipient": recipient,
        "amount": amount,
        "nonce": nonce,
        "public_key": public_key,
    }


def sign_transaction(wallet_row, recipient, amount, nonce):
    private_key = load_private_key(wallet_row["private_key_pem"])
    payload = canonical_tx_payload(
        wallet_row["address"], recipient, amount, nonce, wallet_row["public_key_pem"]
    )
    signature = private_key.sign(
        json.dumps(payload, sort_keys=True).encode("utf-8"),
        ec.ECDSA(hashes.SHA256()),
    )
    return {
        "tx_id": stable_hash(payload),
        **payload,
        "signature": base64.b64encode(signature).decode("utf-8"),
    }


def fetch_chain():
    try:
        with urlopen(f"{DEFAULT_NODE_URL}/chain", timeout=2) as response:
            return json.loads(response.read().decode("utf-8")).get("chain", [])
    except (URLError, TimeoutError, json.JSONDecodeError):
        return []


def submit_funding_transaction(purchase_id, wallet_address, amount_usd, edu_amount, payment_method_type):
    payload = {
        "type": "funding",
        "purchase_id": purchase_id,
        "recipient": wallet_address,
        "amount": edu_amount,
        "amount_usd": amount_usd,
        "currency": "USD",
        "payment_method_type": payment_method_type,
        "source": "simulated_fiat_purchase",
    }
    payload["tx_id"] = stable_hash(payload)
    request = Request(
        f"{DEFAULT_NODE_URL}/transactions",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urlopen(request, timeout=3) as response:
        return json.loads(response.read().decode("utf-8"))


def compute_balances(wallets):
    balances = {wallet["address"]: wallet["seed_balance"] for wallet in wallets}
    chain = fetch_chain()
    for block in chain[1:]:
        for tx in block.get("transactions", []):
            tx_type = tx.get("type", "payment")
            if tx_type == "funding":
                recipient = tx.get("recipient")
                amount = tx.get("amount", 0)
                if recipient in balances:
                    balances[recipient] += amount
                continue
            if tx_type != "payment":
                continue
            sender = tx.get("sender")
            recipient = tx.get("recipient")
            amount = tx.get("amount", 0)
            if sender in balances:
                balances[sender] -= amount
            if recipient in balances:
                balances[recipient] += amount
    return balances


def all_wallets(connection):
    with connection.cursor() as cursor:
        cursor.execute(
            """
            SELECT
                wallet_id::text AS wallet_id,
                owner_user_id::text AS owner_user_id,
                owner,
                address,
                type,
                seed_balance,
                public_key_pem,
                private_key_pem
            FROM wallets
            ORDER BY owner
            """
        )
        return cursor.fetchall()


def wallet_payload(connection):
    wallets = all_wallets(connection)
    balances = compute_balances(wallets)
    hydrated = [
        {
            key: value
            for key, value in {
                **wallet,
                "balance": balances.get(wallet["address"], wallet["seed_balance"]),
            }.items()
            if key != "private_key_pem"
        }
        for wallet in wallets
    ]
    return {
        "wallets": hydrated,
        "default_sender": hydrated[0] if hydrated else None,
        "default_recipient": hydrated[1] if len(hydrated) > 1 else None,
    }


def payload_for_owner(connection, owner_user_id):
    all_hydrated = wallet_payload(connection)["wallets"]
    owned = [wallet for wallet in all_hydrated if wallet["owner_user_id"] == owner_user_id]
    contacts = [wallet for wallet in all_hydrated if wallet["owner_user_id"] != owner_user_id]
    return {
        "wallets": owned,
        "contacts": contacts,
        "default_sender": owned[0] if owned else None,
        "default_recipient": contacts[0] if contacts else None,
    }


def purchases_for_owner(connection, owner_user_id):
    with connection.cursor() as cursor:
        cursor.execute(
            """
            SELECT
                purchase_id::text AS purchase_id,
                owner_user_id::text AS owner_user_id,
                wallet_address,
                amount_usd,
                edu_amount,
                payment_method_type,
                payment_payload,
                status,
                provider_reference,
                blockchain_tx_id,
                created_at::text AS created_at
            FROM purchase_orders
            WHERE owner_user_id = %s
            ORDER BY created_at DESC
            LIMIT 50
            """,
            (owner_user_id,),
        )
        return cursor.fetchall()


def read_json_body(handler):
    content_length = int(handler.headers.get("Content-Length", "0"))
    raw = handler.rfile.read(content_length) if content_length else b"{}"
    return json.loads(raw.decode("utf-8"))


def normalized_payment_payload(payment_method_type, payment_details):
    if payment_method_type == "card":
        return {
            "cardholder_name": str(payment_details.get("cardholder_name", "")).strip(),
            "card_number": str(payment_details.get("card_number", "")).strip(),
            "expiry_month": str(payment_details.get("expiry_month", "")).strip(),
            "expiry_year": str(payment_details.get("expiry_year", "")).strip(),
            "cvv": str(payment_details.get("cvv", "")).strip(),
            "billing_zip": str(payment_details.get("billing_zip", "")).strip(),
        }
    if payment_method_type == "bank_account":
        return {
            "account_holder_name": str(payment_details.get("account_holder_name", "")).strip(),
            "routing_number": str(payment_details.get("routing_number", "")).strip(),
            "account_number": str(payment_details.get("account_number", "")).strip(),
            "bank_name": str(payment_details.get("bank_name", "")).strip(),
            "account_type": str(payment_details.get("account_type", "")).strip() or "checking",
        }
    return {}


def payment_details_valid(payment_method_type, payment_payload):
    if payment_method_type == "card":
        required = ["cardholder_name", "card_number", "expiry_month", "expiry_year", "cvv", "billing_zip"]
        return all(payment_payload.get(field) for field in required)
    if payment_method_type == "bank_account":
        required = ["account_holder_name", "routing_number", "account_number", "bank_name", "account_type"]
        return all(payment_payload.get(field) for field in required)
    return False


class Handler(BaseHTTPRequestHandler):
    def _send(self, payload, status=200, content_type="application/json"):
        body = payload.encode("utf-8") if isinstance(payload, str) else json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        return

    def do_OPTIONS(self):
        self._send({}, status=204)

    def do_GET(self):
        if self.path == "/health":
            self._send(
                {
                    "service": "wallet-service",
                    "status": "ok",
                    "default_node_url": DEFAULT_NODE_URL,
                    "database_backend": "postgresql",
                }
            )
            return

        if self.path == "/metrics":
            self._send(metrics_text(), content_type="text/plain; version=0.0.4")
            return

        parsed = urlparse(self.path)

        with get_connection() as connection:
            if self.path == "/wallets/demo":
                self._send(wallet_payload(connection))
                return

            if self.path == "/wallets/registry":
                wallets = all_wallets(connection)
                self._send(
                    {
                        "wallets": [
                            {
                                "wallet_id": wallet["wallet_id"],
                                "owner_user_id": wallet["owner_user_id"],
                                "owner": wallet["owner"],
                                "address": wallet["address"],
                                "type": wallet["type"],
                                "seed_balance": wallet["seed_balance"],
                                "public_key_pem": wallet["public_key_pem"],
                            }
                            for wallet in wallets
                        ]
                    }
                )
                return

            if parsed.path == "/wallets/by-owner":
                owner_user_id = parse_qs(parsed.query).get("owner_user_id", [""])[0].strip()
                if not owner_user_id:
                    self._send({"error": "owner_user_id is required"}, status=400)
                    return
                self._send(payload_for_owner(connection, owner_user_id))
                return

            if parsed.path == "/purchases/by-owner":
                owner_user_id = parse_qs(parsed.query).get("owner_user_id", [""])[0].strip()
                if not owner_user_id:
                    self._send({"error": "owner_user_id is required"}, status=400)
                    return
                self._send({"purchases": purchases_for_owner(connection, owner_user_id)})
                return

        self._send({"error": "not found"}, status=404)

    def do_POST(self):
        if self.path == "/purchases":
            payload = read_json_body(self)
            owner_user_id = payload.get("owner_user_id", "").strip()
            wallet_address = payload.get("wallet_address", "").strip()
            payment_method_type = payload.get("payment_method_type", "").strip()
            payment_details = payload.get("payment_details", {})
            try:
                amount_usd = int(payload.get("amount_usd", 0))
            except (TypeError, ValueError):
                amount_usd = 0

            if not owner_user_id or not wallet_address or amount_usd <= 0:
                self._send({"error": "missing required fields"}, status=400)
                return
            if payment_method_type not in {"card", "bank_account"}:
                self._send({"error": "invalid payment method type"}, status=400)
                return

            payment_payload = normalized_payment_payload(payment_method_type, payment_details)
            if not payment_details_valid(payment_method_type, payment_payload):
                self._send({"error": "missing payment details"}, status=400)
                return

            purchase_id = str(uuid.uuid4())
            edu_amount = amount_usd
            provider_reference = f"SIM-{purchase_id.split('-')[0].upper()}"

            with get_connection() as connection:
                with connection.cursor() as cursor:
                    cursor.execute(
                        """
                        SELECT
                            wallet_id::text AS wallet_id,
                            owner_user_id::text AS owner_user_id,
                            owner,
                            address,
                            type,
                            seed_balance,
                            public_key_pem,
                            private_key_pem
                        FROM wallets
                        WHERE owner_user_id = %s AND address = %s
                        """,
                        (owner_user_id, wallet_address),
                    )
                    wallet = cursor.fetchone()
                    if not wallet:
                        self._send({"error": "wallet not found for owner"}, status=404)
                        return

                try:
                    funding_result = submit_funding_transaction(
                        purchase_id,
                        wallet_address,
                        amount_usd,
                        edu_amount,
                        payment_method_type,
                    )
                except (HTTPError, URLError, TimeoutError, json.JSONDecodeError, RemoteDisconnected) as exc:
                    increment_metric("transaction_sign_failure_total")
                    self._send({"error": "purchase funding failed", "detail": str(exc)}, status=502)
                    return

                if not funding_result.get("accepted"):
                    increment_metric("transaction_sign_failure_total")
                    self._send({"error": "purchase funding rejected", "detail": funding_result}, status=409)
                    return

                with connection.cursor() as cursor:
                    cursor.execute(
                        """
                        INSERT INTO purchase_orders (
                            purchase_id,
                            owner_user_id,
                            wallet_address,
                            amount_usd,
                            edu_amount,
                            payment_method_type,
                            payment_payload,
                            status,
                            provider_reference,
                            blockchain_tx_id,
                            created_at
                        )
                        VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb, %s, %s, %s, %s)
                        RETURNING
                            purchase_id::text AS purchase_id,
                            owner_user_id::text AS owner_user_id,
                            wallet_address,
                            amount_usd,
                            edu_amount,
                            payment_method_type,
                            payment_payload,
                            status,
                            provider_reference,
                            blockchain_tx_id,
                            created_at::text AS created_at
                        """,
                        (
                            purchase_id,
                            owner_user_id,
                            wallet_address,
                            amount_usd,
                            edu_amount,
                            payment_method_type,
                            json.dumps(payment_payload),
                            "completed",
                            provider_reference,
                            funding_result.get("transaction", {}).get("tx_id"),
                            now_iso(),
                        ),
                    )
                    purchase = cursor.fetchone()
                connection.commit()
                emit_audit_event(
                    {
                        "event_name": "wallet.purchase.completed",
                        "timestamp": now_iso(),
                        "actor_id": owner_user_id,
                        "actor_type": "user",
                        "entity_type": "purchase",
                        "entity_id": purchase_id,
                        "source_ip": self.client_address[0],
                        "service_name": SERVICE_NAME,
                        "status": "success",
                        "metadata": {
                            "wallet_address": wallet_address,
                            "amount_usd": amount_usd,
                            "edu_amount": edu_amount,
                            "payment_method_type": payment_method_type,
                        },
                    }
                )
                self._send({"purchase": purchase, "transaction": funding_result.get("transaction")}, status=201)
            return

        if self.path == "/wallets":
            payload = read_json_body(self)
            owner_user_id = payload.get("owner_user_id", "").strip()
            owner = payload.get("owner", "").strip()
            wallet_address = payload.get("address", "").strip()
            wallet_type = payload.get("type", "hot").strip()
            seed_balance = int(payload.get("seed_balance", 250))
            wallet_id = payload.get("wallet_id", "").strip() or str(uuid.uuid4())

            if not owner_user_id or not owner or not wallet_address:
                self._send({"error": "missing required fields"}, status=400)
                return

            with get_connection() as connection:
                with connection.cursor() as cursor:
                    private_pem, public_pem = generate_keypair()
                    derived_address = address_for_public_key(public_pem)
                    if not wallet_address:
                        wallet_address = derived_address
                    cursor.execute(
                        "SELECT 1 FROM wallets WHERE address = %s OR wallet_id = %s",
                        (wallet_address, wallet_id),
                    )
                    if cursor.fetchone():
                        increment_metric("wallet_create_conflict_total")
                        self._send({"error": "wallet already exists"}, status=409)
                        return

                    cursor.execute(
                        """
                        INSERT INTO wallets (
                            wallet_id, owner_user_id, owner, address, type, seed_balance, public_key_pem, private_key_pem
                        )
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                        RETURNING
                            wallet_id::text AS wallet_id,
                            owner_user_id::text AS owner_user_id,
                            owner,
                            address,
                            type,
                            seed_balance,
                            public_key_pem
                        """,
                        (
                            wallet_id,
                            owner_user_id,
                            owner,
                            wallet_address,
                            wallet_type,
                            seed_balance,
                            public_pem,
                            private_pem,
                        ),
                    )
                    wallet = cursor.fetchone()
                connection.commit()
                increment_metric("wallet_create_success_total")
                emit_audit_event(
                    {
                        "event_name": "wallet.created",
                        "timestamp": now_iso(),
                        "actor_id": wallet["owner_user_id"],
                        "actor_type": "user",
                        "entity_type": "wallet",
                        "entity_id": wallet["wallet_id"],
                        "source_ip": self.client_address[0],
                        "service_name": SERVICE_NAME,
                        "status": "success",
                        "metadata": {"address": wallet["address"], "type": wallet["type"]},
                    }
                )
                self._send(wallet, status=201)
            return

        if self.path == "/transactions/sign":
            payload = read_json_body(self)
            owner_user_id = payload.get("owner_user_id", "").strip()
            sender = payload.get("sender", "").strip()
            recipient = payload.get("recipient", "").strip()
            amount = int(payload.get("amount", 0))
            nonce = str(payload.get("nonce") or "").strip() or str(uuid.uuid4())

            if not owner_user_id or not sender or not recipient or amount <= 0:
                self._send({"error": "missing required fields"}, status=400)
                return

            with get_connection() as connection:
                with connection.cursor() as cursor:
                    cursor.execute(
                        """
                        SELECT
                            wallet_id::text AS wallet_id,
                            owner_user_id::text AS owner_user_id,
                            owner,
                            address,
                            type,
                            seed_balance,
                            public_key_pem,
                            private_key_pem
                        FROM wallets
                        WHERE owner_user_id = %s AND address = %s
                        """,
                        (owner_user_id, sender),
                    )
                    wallet = cursor.fetchone()
                    cursor.execute(
                        """
                        SELECT 1
                        FROM wallets
                        WHERE address = %s
                        """,
                        (recipient,),
                    )
                    recipient_wallet = cursor.fetchone()
                if not wallet:
                    increment_metric("transaction_sign_failure_total")
                    emit_audit_event(
                        {
                            "event_name": "wallet.transaction.sign_failed",
                            "timestamp": now_iso(),
                            "actor_id": owner_user_id or "unknown",
                            "actor_type": "user",
                            "entity_type": "transaction",
                            "entity_id": "unknown",
                            "source_ip": self.client_address[0],
                            "service_name": SERVICE_NAME,
                            "status": "failure",
                            "metadata": {"sender": sender, "reason": "wallet_not_found"},
                        }
                    )
                    self._send({"error": "wallet not found for owner"}, status=404)
                    return
                if not recipient_wallet:
                    increment_metric("transaction_sign_failure_total")
                    emit_audit_event(
                        {
                            "event_name": "wallet.transaction.sign_failed",
                            "timestamp": now_iso(),
                            "actor_id": owner_user_id or "unknown",
                            "actor_type": "user",
                            "entity_type": "transaction",
                            "entity_id": "unknown",
                            "source_ip": self.client_address[0],
                            "service_name": SERVICE_NAME,
                            "status": "failure",
                            "metadata": {"recipient": recipient, "reason": "recipient_wallet_not_found"},
                        }
                    )
                    self._send({"error": "recipient wallet not found"}, status=404)
                    return
                signed_transaction = sign_transaction(wallet, recipient, amount, nonce)
                increment_metric("transaction_sign_success_total")
                emit_audit_event(
                    {
                        "event_name": "wallet.transaction.signed",
                        "timestamp": now_iso(),
                        "actor_id": owner_user_id,
                        "actor_type": "user",
                        "entity_type": "transaction",
                        "entity_id": signed_transaction["tx_id"],
                        "source_ip": self.client_address[0],
                        "service_name": SERVICE_NAME,
                        "status": "success",
                        "metadata": {
                            "sender": sender,
                            "recipient": recipient,
                            "amount": amount,
                        },
                    }
                )
                self._send({"transaction": signed_transaction}, status=201)
            return

        self._send({"error": "not found"}, status=404)


if __name__ == "__main__":
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print(f"wallet-service listening on {PORT} using {DATABASE_URL}")
    server.serve_forever()

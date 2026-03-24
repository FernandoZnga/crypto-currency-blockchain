import base64
import hashlib
import json
import os
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlparse
from urllib.request import Request, urlopen
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


NODE_ID = os.getenv("NODE_ID", "node-unknown")
PORT = int(os.getenv("PORT", "8101"))
ROLE = os.getenv("ROLE", "validator")
PEERS = [peer.rstrip("/") for peer in os.getenv("PEERS", "").split(",") if peer]
BLOCK_INTERVAL_SECONDS = float(os.getenv("BLOCK_INTERVAL_SECONDS", "8"))
SYNC_INTERVAL_SECONDS = float(os.getenv("SYNC_INTERVAL_SECONDS", "5"))
WALLET_SERVICE_URL = os.getenv("WALLET_SERVICE_URL", "http://wallet-service:8002").rstrip("/")
DATA_DIR = Path(os.getenv("DATA_DIR", "/var/lib/blockchain"))
AUDIT_SERVICE_URL = os.getenv("AUDIT_SERVICE_URL", "").rstrip("/")
SERVICE_NAME = "blockchain-node"
METRICS = {
    "transactions_accepted_total": 0,
    "transactions_rejected_total": 0,
    "kyc_anchor_accepted_total": 0,
    "blocks_mined_total": 0,
    "blocks_accepted_total": 0,
    "chain_height": 1,
    "mempool_size": 0,
}


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def stable_hash(payload):
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()


def increment_metric(name, amount=1):
    METRICS[name] = METRICS.get(name, 0) + amount


def set_metric(name, value):
    METRICS[name] = value


def metrics_text():
    lines = [
        "# HELP blockchain_counters_total Blockchain counters.",
        "# TYPE blockchain_counters_total counter",
    ]
    for metric_name in sorted(name for name in METRICS if name.endswith("_total")):
        lines.append(
            f'blockchain_counters_total{{node_id="{NODE_ID}",metric="{metric_name}"}} {METRICS[metric_name]}'
        )
    lines.extend(
        [
            "# HELP blockchain_gauges Blockchain gauges.",
            "# TYPE blockchain_gauges gauge",
            f'blockchain_gauges{{node_id="{NODE_ID}",metric="chain_height"}} {METRICS["chain_height"]}',
            f'blockchain_gauges{{node_id="{NODE_ID}",metric="mempool_size"}} {METRICS["mempool_size"]}',
        ]
    )
    return "\n".join(lines) + "\n"


def compute_block_hash(block):
    block_payload = {key: value for key, value in block.items() if key != "hash"}
    return stable_hash(block_payload)


GENESIS_BLOCK = {
    "index": 0,
    "previous_hash": "0" * 64,
    "timestamp": "2026-03-23T00:00:00+00:00",
    "transactions": [],
    "proposer": "genesis",
}
GENESIS_BLOCK["hash"] = compute_block_hash(GENESIS_BLOCK)


class NodeState:
    def __init__(self):
        self.lock = threading.Lock()
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        self.chain = self._load_json("chain.json", [GENESIS_BLOCK])
        self.mempool = self._load_json("mempool.json", [])
        self.seen_transactions = {
            tx["tx_id"] for block in self.chain for tx in block.get("transactions", [])
        } | {tx["tx_id"] for tx in self.mempool}
        self.seen_blocks = {block["hash"] for block in self.chain}
        self.activity = [
            {
                "timestamp": GENESIS_BLOCK["timestamp"],
                "message": "Genesis block loaded",
                "type": "chain",
            }
        ]
        self.last_sync = None
        self.wallet_registry = {}
        set_metric("chain_height", len(self.chain))
        set_metric("mempool_size", len(self.mempool))

    def _load_json(self, filename, fallback):
        path = DATA_DIR / filename
        if not path.exists():
            return fallback
        try:
            return json.loads(path.read_text())
        except json.JSONDecodeError:
            return fallback

    def persist_state(self):
        (DATA_DIR / "chain.json").write_text(json.dumps(self.chain, indent=2))
        (DATA_DIR / "mempool.json").write_text(json.dumps(self.mempool, indent=2))

    def summary(self, limit=10):
        with self.lock:
            latest = self.chain[-1]
            return {
                "node_id": NODE_ID,
                "role": ROLE,
                "peer_count": len(PEERS),
                "peers": PEERS,
                "chain_height": len(self.chain),
                "latest_block": latest,
                "mempool_size": len(self.mempool),
                "recent_activity": self.activity[-max(1, limit):],
                "last_seen": now_iso(),
                "last_sync": self.last_sync,
            }

    def add_activity(self, message, event_type):
        self.activity.append(
            {"timestamp": now_iso(), "message": message, "type": event_type}
        )
        self.activity = self.activity[-1000:]

    def has_transaction(self, tx_id):
        return tx_id in self.seen_transactions

    def refresh_wallet_registry(self):
        try:
            registry = fetch_json(f"{WALLET_SERVICE_URL}/wallets/registry", timeout=2)
        except (HTTPError, URLError, TimeoutError, json.JSONDecodeError):
            return
        with self.lock:
            self.wallet_registry = {wallet["address"]: wallet for wallet in registry.get("wallets", [])}

    def balances_snapshot(self):
        balances = {
            address: wallet.get("seed_balance", 0)
            for address, wallet in self.wallet_registry.items()
        }
        for block in self.chain[1:]:
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

    def next_nonce_for_sender(self, sender):
        seen = set()
        for block in self.chain[1:]:
            for tx in block.get("transactions", []):
                if tx.get("type", "payment") != "payment":
                    continue
                if tx.get("sender") == sender:
                    seen.add(str(tx.get("nonce")))
        for tx in self.mempool:
            if tx.get("type", "payment") != "payment":
                continue
            if tx.get("sender") == sender:
                seen.add(str(tx.get("nonce")))
        return seen

    def verify_signature(self, transaction):
        sender = transaction.get("sender")
        registry_wallet = self.wallet_registry.get(sender)
        if not registry_wallet:
            return False, "unknown sender"
        public_key_pem = transaction.get("public_key")
        if public_key_pem != registry_wallet.get("public_key_pem"):
            return False, "public key mismatch"
        payload = {
            "type": "payment",
            "sender": sender,
            "recipient": transaction.get("recipient"),
            "amount": transaction.get("amount"),
            "nonce": transaction.get("nonce"),
            "public_key": public_key_pem,
        }
        try:
            public_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
            public_key.verify(
                base64.b64decode(transaction.get("signature", "")),
                json.dumps(payload, sort_keys=True).encode("utf-8"),
                ec.ECDSA(hashes.SHA256()),
            )
            return True, None
        except (ValueError, InvalidSignature):
            return False, "invalid signature"

    def validate_transaction(self, transaction):
        tx_type = transaction.get("type", "payment")
        if tx_type == "payment":
            required = ["tx_id", "type", "sender", "recipient", "amount", "nonce", "public_key", "signature"]
            if any(field not in transaction for field in required):
                return False, "missing fields"
            expected_tx_id = stable_hash(
                {
                    "type": "payment",
                    "sender": transaction["sender"],
                    "recipient": transaction["recipient"],
                    "amount": transaction["amount"],
                    "nonce": transaction["nonce"],
                    "public_key": transaction["public_key"],
                }
            )
            if transaction["tx_id"] != expected_tx_id:
                return False, "tx_id mismatch"
            ok, reason = self.verify_signature(transaction)
            if not ok:
                return False, reason
            try:
                amount = int(transaction["amount"])
            except (TypeError, ValueError):
                return False, "invalid amount"
            if amount <= 0:
                return False, "invalid amount"
            if transaction["recipient"] not in self.wallet_registry:
                return False, "unknown recipient"
            balances = self.balances_snapshot()
            if balances.get(transaction["sender"], 0) < amount:
                return False, "insufficient balance"
            nonce = str(transaction["nonce"])
            if nonce in self.next_nonce_for_sender(transaction["sender"]):
                return False, "replayed nonce"
            return True, None

        if tx_type == "kyc_anchor":
            required = ["tx_id", "type", "user_id", "submission_id", "anchor_hash", "service_id"]
            if any(field not in transaction for field in required):
                return False, "missing fields"
            expected_tx_id = stable_hash(
                {
                    "type": "kyc_anchor",
                    "user_id": transaction["user_id"],
                    "submission_id": transaction["submission_id"],
                    "anchor_hash": transaction["anchor_hash"],
                    "service_id": transaction["service_id"],
                }
            )
            if transaction["tx_id"] != expected_tx_id:
                return False, "tx_id mismatch"
            for block in self.chain[1:]:
                for tx in block.get("transactions", []):
                    if tx.get("type") == "kyc_anchor" and tx.get("submission_id") == transaction["submission_id"]:
                        return False, "duplicate kyc anchor"
            for tx in self.mempool:
                if tx.get("type") == "kyc_anchor" and tx.get("submission_id") == transaction["submission_id"]:
                    return False, "duplicate kyc anchor"
            return True, None

        if tx_type == "funding":
            required = [
                "tx_id",
                "type",
                "purchase_id",
                "recipient",
                "amount",
                "amount_usd",
                "currency",
                "payment_method_type",
                "source",
            ]
            if any(field not in transaction for field in required):
                return False, "missing fields"
            expected_tx_id = stable_hash(
                {
                    "type": "funding",
                    "purchase_id": transaction["purchase_id"],
                    "recipient": transaction["recipient"],
                    "amount": transaction["amount"],
                    "amount_usd": transaction["amount_usd"],
                    "currency": transaction["currency"],
                    "payment_method_type": transaction["payment_method_type"],
                    "source": transaction["source"],
                }
            )
            if transaction["tx_id"] != expected_tx_id:
                return False, "tx_id mismatch"
            try:
                amount = int(transaction["amount"])
                amount_usd = int(transaction["amount_usd"])
            except (TypeError, ValueError):
                return False, "invalid amount"
            if amount <= 0 or amount_usd <= 0:
                return False, "invalid amount"
            if transaction["recipient"] not in self.wallet_registry:
                return False, "unknown recipient"
            for block in self.chain[1:]:
                for tx in block.get("transactions", []):
                    if tx.get("type") == "funding" and tx.get("purchase_id") == transaction["purchase_id"]:
                        return False, "duplicate purchase"
            for tx in self.mempool:
                if tx.get("type") == "funding" and tx.get("purchase_id") == transaction["purchase_id"]:
                    return False, "duplicate purchase"
            return True, None

        return False, "unsupported transaction type"

    def add_transaction(self, transaction):
        tx_id = transaction["tx_id"]
        if transaction.get("type", "payment") == "payment":
            self.refresh_wallet_registry()
        with self.lock:
            if tx_id in self.seen_transactions:
                return False
            valid, reason = self.validate_transaction(transaction)
            if not valid:
                increment_metric("transactions_rejected_total")
                self.add_activity(f"Rejected transaction {tx_id[:12]}: {reason}", "validation")
                return False
            self.seen_transactions.add(tx_id)
            self.mempool.append(transaction)
            self.add_activity(f"Queued transaction {tx_id[:12]}", "transaction")
            self.persist_state()
            increment_metric("transactions_accepted_total")
            if transaction.get("type") == "kyc_anchor":
                increment_metric("kyc_anchor_accepted_total")
            set_metric("mempool_size", len(self.mempool))
            return True

    def validate_block(self, block):
        expected_hash = compute_block_hash(block)
        latest = self.chain[-1]
        return (
            block.get("hash") == expected_hash
            and block.get("index") == latest["index"] + 1
            and block.get("previous_hash") == latest["hash"]
        )

    def accept_block(self, block):
        with self.lock:
            if block["hash"] in self.seen_blocks:
                return False
            if not self.validate_block(block):
                return False
            self.chain.append(block)
            self.seen_blocks.add(block["hash"])
            included = {tx["tx_id"] for tx in block.get("transactions", [])}
            self.mempool = [tx for tx in self.mempool if tx["tx_id"] not in included]
            self.add_activity(
                f"Accepted block #{block['index']} from {block['proposer']}", "block"
            )
            self.persist_state()
            increment_metric("blocks_accepted_total")
            set_metric("chain_height", len(self.chain))
            set_metric("mempool_size", len(self.mempool))
            return True

    def mine_block(self):
        with self.lock:
            if ROLE != "bootstrap" or not self.mempool:
                return None

            latest = self.chain[-1]
            transactions = self.mempool[:5]
            block = {
                "index": latest["index"] + 1,
                "previous_hash": latest["hash"],
                "timestamp": now_iso(),
                "transactions": transactions,
                "proposer": NODE_ID,
            }
            block["hash"] = compute_block_hash(block)
            self.chain.append(block)
            self.seen_blocks.add(block["hash"])
            included = {tx["tx_id"] for tx in transactions}
            self.mempool = [tx for tx in self.mempool if tx["tx_id"] not in included]
            self.add_activity(f"Proposed block #{block['index']}", "block")
            self.persist_state()
            increment_metric("blocks_mined_total")
            set_metric("chain_height", len(self.chain))
            set_metric("mempool_size", len(self.mempool))
            return block

    def replace_chain(self, chain):
        with self.lock:
            self.chain = chain
            self.seen_blocks = {block["hash"] for block in chain}
            included = {
                tx["tx_id"]
                for block in chain
                for tx in block.get("transactions", [])
            }
            self.mempool = [tx for tx in self.mempool if tx["tx_id"] not in included]
            self.add_activity(
                f"Synchronized chain to height {len(chain)}", "synchronization"
            )
            self.last_sync = now_iso()
            self.persist_state()
            set_metric("chain_height", len(self.chain))
            set_metric("mempool_size", len(self.mempool))


STATE = NodeState()


def read_json_body(handler):
    content_length = int(handler.headers.get("Content-Length", "0"))
    raw = handler.rfile.read(content_length) if content_length else b"{}"
    return json.loads(raw.decode("utf-8"))


def fetch_json(url, method="GET", payload=None, timeout=2):
    data = None
    headers = {"Content-Type": "application/json"}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
    request = Request(url, data=data, headers=headers, method=method)
    with urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def emit_audit_event(event):
    if not AUDIT_SERVICE_URL:
        return
    try:
        fetch_json(f"{AUDIT_SERVICE_URL}/events", method="POST", payload=event, timeout=2)
    except (HTTPError, URLError, TimeoutError, json.JSONDecodeError):
        return


def broadcast(path, payload):
    for peer in PEERS:
        try:
            fetch_json(f"{peer}{path}", method="POST", payload=payload, timeout=1.5)
        except (HTTPError, URLError, TimeoutError, json.JSONDecodeError):
            continue


def best_chain_from_peers():
    longest_chain = None
    for peer in PEERS:
        try:
            peer_chain = fetch_json(f"{peer}/chain", timeout=1.5)
        except (HTTPError, URLError, TimeoutError, json.JSONDecodeError):
            continue
        chain = peer_chain.get("chain", [])
        if not chain:
            continue
        if longest_chain is None or len(chain) > len(longest_chain):
            longest_chain = chain
    return longest_chain


def sync_loop():
    while True:
        time.sleep(SYNC_INTERVAL_SECONDS)
        STATE.refresh_wallet_registry()
        peer_chain = best_chain_from_peers()
        if peer_chain and len(peer_chain) > len(STATE.chain):
            STATE.replace_chain(peer_chain)


def mining_loop():
    while True:
        time.sleep(BLOCK_INTERVAL_SECONDS)
        block = STATE.mine_block()
        if block:
            emit_audit_event(
                {
                    "event_name": "blockchain.block.mined",
                    "timestamp": now_iso(),
                    "actor_id": NODE_ID,
                    "actor_type": "system",
                    "entity_type": "block",
                    "entity_id": block["hash"],
                    "source_ip": "127.0.0.1",
                    "service_name": f"{SERVICE_NAME}:{NODE_ID}",
                    "status": "success",
                    "metadata": {"index": block["index"]},
                }
            )
            broadcast("/blocks/receive", block)


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
        parsed = urlparse(self.path)

        if parsed.path == "/health":
            self._send(
                {
                    "service": "blockchain-node",
                    "node_id": NODE_ID,
                    "role": ROLE,
                    "status": "ok",
                }
            )
            return

        if parsed.path == "/network":
            query = parse_qs(parsed.query)
            try:
                limit = int(query.get("limit", ["10"])[0])
            except ValueError:
                limit = 10
            self._send(STATE.summary(limit=max(1, min(limit, 1000))))
            return

        if parsed.path == "/chain":
            self._send({"node_id": NODE_ID, "chain": STATE.chain})
            return

        if parsed.path == "/mempool":
            self._send({"node_id": NODE_ID, "transactions": STATE.mempool})
            return

        if parsed.path == "/metrics":
            self._send(metrics_text(), content_type="text/plain; version=0.0.4")
            return

        self._send({"error": "not found"}, status=404)

    def do_POST(self):
        if self.path == "/transactions":
            payload = read_json_body(self)
            transaction = {**payload, "created_at": now_iso(), "source_node": NODE_ID}
            added = STATE.add_transaction(transaction)
            if added:
                broadcast("/transactions/receive", transaction)
            emit_audit_event(
                {
                    "event_name": "blockchain.transaction.submitted",
                    "timestamp": now_iso(),
                    "actor_id": transaction.get("sender", transaction.get("source_node", "unknown")),
                    "actor_type": "user" if transaction.get("type", "payment") == "payment" else "service",
                    "entity_type": "transaction",
                    "entity_id": transaction["tx_id"],
                    "source_ip": self.client_address[0],
                    "service_name": f"{SERVICE_NAME}:{NODE_ID}",
                    "status": "success" if added else "failure",
                    "metadata": {"type": transaction.get("type", "payment")},
                }
            )
            self._send(
                {
                    "accepted": added,
                    "transaction": transaction,
                    "mempool_size": len(STATE.mempool),
                },
                status=202 if added else 200,
            )
            return

        if self.path == "/transactions/kyc-anchor":
            payload = read_json_body(self)
            transaction = {
                "tx_id": stable_hash(
                    {
                        "type": "kyc_anchor",
                        "user_id": payload.get("user_id"),
                        "submission_id": payload.get("submission_id"),
                        "anchor_hash": payload.get("anchor_hash"),
                        "service_id": payload.get("service_id", "auth-service"),
                    }
                ),
                "type": "kyc_anchor",
                "user_id": payload.get("user_id"),
                "submission_id": payload.get("submission_id"),
                "anchor_hash": payload.get("anchor_hash"),
                "service_id": payload.get("service_id", "auth-service"),
                "document_type": payload.get("document_type"),
                "country": payload.get("country"),
                "note": payload.get("note"),
                "submitted_at": payload.get("submitted_at"),
                "created_at": now_iso(),
                "source_node": NODE_ID,
            }
            added = STATE.add_transaction(transaction)
            if added:
                broadcast("/transactions/receive", transaction)
            emit_audit_event(
                {
                    "event_name": "blockchain.kyc_anchor.submitted",
                    "timestamp": now_iso(),
                    "actor_id": transaction.get("user_id", "unknown"),
                    "actor_type": "service",
                    "entity_type": "transaction",
                    "entity_id": transaction["tx_id"],
                    "source_ip": self.client_address[0],
                    "service_name": f"{SERVICE_NAME}:{NODE_ID}",
                    "status": "success" if added else "failure",
                    "metadata": {"submission_id": transaction.get("submission_id")},
                }
            )
            self._send(
                {"accepted": added, "transaction": transaction, "mempool_size": len(STATE.mempool)},
                status=202 if added else 409,
            )
            return

        if self.path == "/transactions/receive":
            transaction = read_json_body(self)
            added = STATE.add_transaction(transaction)
            emit_audit_event(
                {
                    "event_name": "blockchain.transaction.received",
                    "timestamp": now_iso(),
                    "actor_id": transaction.get("source_node", "peer"),
                    "actor_type": "service",
                    "entity_type": "transaction",
                    "entity_id": transaction["tx_id"],
                    "source_ip": self.client_address[0],
                    "service_name": f"{SERVICE_NAME}:{NODE_ID}",
                    "status": "success" if added else "failure",
                    "metadata": {"type": transaction.get("type", "payment")},
                }
            )
            self._send({"accepted": added, "node_id": NODE_ID}, status=202 if added else 200)
            return

        if self.path == "/blocks/receive":
            block = read_json_body(self)
            accepted = STATE.accept_block(block)
            emit_audit_event(
                {
                    "event_name": "blockchain.block.received",
                    "timestamp": now_iso(),
                    "actor_id": block.get("proposer", "peer"),
                    "actor_type": "service",
                    "entity_type": "block",
                    "entity_id": block.get("hash", "unknown"),
                    "source_ip": self.client_address[0],
                    "service_name": f"{SERVICE_NAME}:{NODE_ID}",
                    "status": "success" if accepted else "failure",
                    "metadata": {"index": block.get("index")},
                }
            )
            self._send({"accepted": accepted, "node_id": NODE_ID}, status=202 if accepted else 409)
            return

        self._send({"error": "not found"}, status=404)


if __name__ == "__main__":
    STATE.refresh_wallet_registry()
    threading.Thread(target=sync_loop, daemon=True).start()
    threading.Thread(target=mining_loop, daemon=True).start()
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print(f"{NODE_ID} listening on {PORT} with peers={PEERS}")
    server.serve_forever()

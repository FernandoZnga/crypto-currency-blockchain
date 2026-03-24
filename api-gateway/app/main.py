import json
import os
import uuid
from datetime import datetime, timezone
from http.client import RemoteDisconnected
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlparse
from urllib.request import Request, urlopen


PORT = int(os.getenv("PORT", "8000"))
NODE_URLS = [url.rstrip("/") for url in os.getenv("ALL_NODE_URLS", "").split(",") if url]
DEFAULT_NODE_URL = os.getenv("BLOCKCHAIN_NODE_URL", "").rstrip("/")
WALLET_SERVICE_URL = os.getenv("WALLET_SERVICE_URL", "").rstrip("/")
AUTH_SERVICE_URL = os.getenv("AUTH_SERVICE_URL", "").rstrip("/")
AUDIT_SERVICE_URL = os.getenv("AUDIT_SERVICE_URL", "").rstrip("/")
SERVICE_NAME = "api-gateway"
METRICS = {
    "http_requests_total": 0,
    "http_errors_total": 0,
    "register_requests_total": 0,
    "login_requests_total": 0,
    "kyc_requests_total": 0,
    "kyc_review_requests_total": 0,
    "transaction_requests_total": 0,
}


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def increment_metric(name, amount=1):
    METRICS[name] = METRICS.get(name, 0) + amount


def metrics_text():
    lines = [
        "# HELP service_requests_total Total gateway requests by counter name.",
        "# TYPE service_requests_total counter",
    ]
    for metric_name, value in sorted(METRICS.items()):
        lines.append(
            f'service_requests_total{{service="{SERVICE_NAME}",metric="{metric_name}"}} {value}'
        )
    return "\n".join(lines) + "\n"


def fetch_json(url, timeout=2):
    with urlopen(url, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def send_json(url, payload, timeout=2):
    request = Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def send_json_with_headers(url, payload, headers, timeout=2):
    request = Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    with urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def fetch_json_with_headers(url, headers, timeout=2):
    request = Request(url, headers=headers, method="GET")
    with urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def emit_audit_event(event):
    if not AUDIT_SERVICE_URL:
        return
    try:
        send_json(f"{AUDIT_SERVICE_URL}/events", event, timeout=2)
    except (HTTPError, URLError, TimeoutError, json.JSONDecodeError):
        return


def error_payload_from_http_error(exc, fallback_error, fallback_detail=None):
    detail_text = ""
    try:
        detail_text = exc.read().decode("utf-8")
    except Exception:
        detail_text = ""
    if detail_text:
        try:
            payload = json.loads(detail_text)
            if isinstance(payload, dict):
                return payload
        except json.JSONDecodeError:
            pass
    payload = {"error": fallback_error}
    if fallback_detail:
        payload["detail"] = fallback_detail
    elif getattr(exc, "reason", None):
        payload["detail"] = str(exc.reason)
    return payload


def read_json_body(handler):
    content_length = int(handler.headers.get("Content-Length", "0"))
    raw = handler.rfile.read(content_length) if content_length else b"{}"
    return json.loads(raw.decode("utf-8"))


def wallet_address_for(user_id):
    return f"wallet-{user_id.split('-')[0]}-edu"


def current_user_from_token(token):
    if not token:
        return None
    try:
        result = fetch_json_with_headers(
            f"{AUTH_SERVICE_URL}/me",
            {"Authorization": token},
            timeout=2,
        )
        return result.get("user")
    except (HTTPError, URLError, TimeoutError, json.JSONDecodeError):
        return None


def transaction_history_for(address):
    chain = fetch_json(f"{DEFAULT_NODE_URL}/chain").get("chain", [])
    history = []
    for block in reversed(chain[1:]):
        for tx in block.get("transactions", []):
            tx_type = tx.get("type", "payment")
            if tx_type == "payment":
                if tx.get("sender") != address and tx.get("recipient") != address:
                    continue
                direction = "outbound" if tx.get("sender") == address else "inbound"
                history.append(
                    {
                        "tx_id": tx.get("tx_id"),
                        "timestamp": tx.get("created_at") or block.get("timestamp"),
                        "block_index": block.get("index"),
                        "sender": tx.get("sender"),
                        "recipient": tx.get("recipient"),
                        "amount": tx.get("amount", 0),
                        "direction": direction,
                        "status": "confirmed",
                        "type": tx_type,
                    }
                )
                continue
            if tx_type == "funding" and tx.get("recipient") == address:
                history.append(
                    {
                        "tx_id": tx.get("tx_id"),
                        "timestamp": tx.get("created_at") or block.get("timestamp"),
                        "block_index": block.get("index"),
                        "sender": "fiat-onramp",
                        "recipient": tx.get("recipient"),
                        "amount": tx.get("amount", 0),
                        "direction": "funding",
                        "status": "confirmed",
                        "type": tx_type,
                    }
                )
    return history[:20]


class Handler(BaseHTTPRequestHandler):
    def _send(self, payload, status=200, content_type="application/json"):
        body = payload.encode("utf-8") if isinstance(payload, str) else json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        return

    def do_OPTIONS(self):
        self._send({}, status=204)

    def do_GET(self):
        increment_metric("http_requests_total")
        parsed = urlparse(self.path)

        if parsed.path == "/health":
            self._send({"service": "api-gateway", "status": "ok"})
            return

        if parsed.path == "/metrics":
            self._send(metrics_text(), content_type="text/plain; version=0.0.4")
            return

        if parsed.path == "/audit/summary":
            try:
                self._send(fetch_json(f"{AUDIT_SERVICE_URL}/summary"))
            except (HTTPError, URLError, TimeoutError, json.JSONDecodeError) as exc:
                increment_metric("http_errors_total")
                self._send({"error": "audit service unavailable", "detail": str(exc)}, status=502)
            return

        if parsed.path == "/audit/events":
            query = f"?{parsed.query}" if parsed.query else ""
            try:
                self._send(fetch_json(f"{AUDIT_SERVICE_URL}/events{query}"))
            except (HTTPError, URLError, TimeoutError, json.JSONDecodeError) as exc:
                increment_metric("http_errors_total")
                self._send({"error": "audit service unavailable", "detail": str(exc)}, status=502)
            return

        if parsed.path == "/topology":
            self._send(
                {
                    "edge_service": "api-gateway",
                    "upstreams": {
                        "auth_service": os.getenv("AUTH_SERVICE_URL"),
                        "wallet_service": os.getenv("WALLET_SERVICE_URL"),
                        "blockchain_node": os.getenv("BLOCKCHAIN_NODE_URL"),
                    },
                }
            )
            return

        if parsed.path == "/network/overview":
            query = parse_qs(parsed.query)
            try:
                limit = int(query.get("limit", ["10"])[0])
            except ValueError:
                limit = 10
            limit = max(1, min(limit, 1000))
            nodes = []
            for url in NODE_URLS:
                try:
                    nodes.append(fetch_json(f"{url}/network?limit={limit}"))
                except (HTTPError, URLError, TimeoutError, json.JSONDecodeError):
                    nodes.append(
                        {
                            "node_id": url.rsplit("/", 1)[-1],
                            "status": "unreachable",
                            "peers": [],
                            "chain_height": 0,
                            "mempool_size": 0,
                            "recent_activity": [],
                        }
                    )

            latest_height = max((node.get("chain_height", 0) for node in nodes), default=0)
            activity = []
            for node in nodes:
                for event in node.get("recent_activity", []):
                    activity.append(
                        {
                            "node_id": node.get("node_id"),
                            "message": event.get("message"),
                            "timestamp": event.get("timestamp"),
                            "type": event.get("type"),
                        }
                    )

            activity.sort(key=lambda item: item.get("timestamp", ""), reverse=True)
            self._send(
                {
                    "node_count": len(nodes),
                    "latest_chain_height": latest_height,
                    "nodes": nodes,
                    "recent_activity": activity[:limit],
                }
            )
            return

        if parsed.path == "/wallets/demo":
            try:
                self._send(fetch_json(f"{WALLET_SERVICE_URL}/wallets/demo"))
            except (HTTPError, URLError, TimeoutError, json.JSONDecodeError) as exc:
                increment_metric("http_errors_total")
                self._send({"error": "wallet service unavailable", "detail": str(exc)}, status=502)
            return

        if parsed.path == "/me":
            token = self.headers.get("Authorization", "")
            try:
                self._send(fetch_json_with_headers(f"{AUTH_SERVICE_URL}/me", {"Authorization": token}))
            except HTTPError as exc:
                increment_metric("http_errors_total")
                self._send({"error": "auth service unavailable", "detail": exc.reason}, status=exc.code)
            except (URLError, TimeoutError, json.JSONDecodeError) as exc:
                increment_metric("http_errors_total")
                self._send({"error": "auth service unavailable", "detail": str(exc)}, status=502)
            return

        if parsed.path == "/wallets/by-owner":
            try:
                self._send(fetch_json(f"{WALLET_SERVICE_URL}{self.path}"))
            except HTTPError as exc:
                increment_metric("http_errors_total")
                self._send({"error": "wallet lookup failed", "detail": exc.reason}, status=exc.code)
            except (URLError, TimeoutError, json.JSONDecodeError) as exc:
                increment_metric("http_errors_total")
                self._send({"error": "wallet service unavailable", "detail": str(exc)}, status=502)
            return

        if parsed.path == "/purchases/by-owner":
            token = self.headers.get("Authorization", "")
            user = current_user_from_token(token)
            if not user:
                increment_metric("http_errors_total")
                self._send({"error": "unauthorized"}, status=401)
                return
            owner_user_id = parse_qs(parsed.query).get("owner_user_id", [""])[0].strip()
            if not owner_user_id:
                self._send({"error": "owner_user_id is required"}, status=400)
                return
            if user.get("role") != "admin" and owner_user_id != user.get("user_id"):
                increment_metric("http_errors_total")
                self._send({"error": "owner mismatch"}, status=403)
                return
            try:
                self._send(fetch_json(f"{WALLET_SERVICE_URL}{self.path}"))
            except HTTPError as exc:
                increment_metric("http_errors_total")
                self._send({"error": "purchase lookup failed", "detail": exc.reason}, status=exc.code)
            except (URLError, TimeoutError, json.JSONDecodeError) as exc:
                increment_metric("http_errors_total")
                self._send({"error": "wallet service unavailable", "detail": str(exc)}, status=502)
            return

        if parsed.path == "/transactions/history":
            address = parse_qs(parsed.query).get("address", [""])[0].strip()
            if not address:
                self._send({"error": "address is required"}, status=400)
                return
            try:
                self._send({"transactions": transaction_history_for(address)})
            except (HTTPError, URLError, TimeoutError, json.JSONDecodeError) as exc:
                increment_metric("http_errors_total")
                self._send({"error": "history unavailable", "detail": str(exc)}, status=502)
            return

        if parsed.path == "/kyc-submissions":
            token = self.headers.get("Authorization", "")
            query = f"?{parsed.query}" if parsed.query else ""
            try:
                self._send(
                    fetch_json_with_headers(
                        f"{AUTH_SERVICE_URL}/kyc-submissions{query}",
                        {"Authorization": token},
                    )
                )
            except HTTPError as exc:
                increment_metric("http_errors_total")
                self._send({"error": "kyc lookup failed", "detail": exc.reason}, status=exc.code)
            except (URLError, TimeoutError, json.JSONDecodeError) as exc:
                increment_metric("http_errors_total")
                self._send({"error": "auth service unavailable", "detail": str(exc)}, status=502)
            return

        if parsed.path == "/users":
            token = self.headers.get("Authorization", "")
            query = f"?{parsed.query}" if parsed.query else ""
            try:
                self._send(
                    fetch_json_with_headers(
                        f"{AUTH_SERVICE_URL}/users{query}",
                        {"Authorization": token},
                    )
                )
            except HTTPError as exc:
                increment_metric("http_errors_total")
                self._send(error_payload_from_http_error(exc, "user lookup failed"), status=exc.code)
            except (URLError, TimeoutError, json.JSONDecodeError) as exc:
                increment_metric("http_errors_total")
                self._send({"error": "auth service unavailable", "detail": str(exc)}, status=502)
            return

        if parsed.path.startswith("/users/"):
            token = self.headers.get("Authorization", "")
            try:
                self._send(
                    fetch_json_with_headers(
                        f"{AUTH_SERVICE_URL}{parsed.path}",
                        {"Authorization": token},
                    )
                )
            except HTTPError as exc:
                increment_metric("http_errors_total")
                self._send(error_payload_from_http_error(exc, "user lookup failed"), status=exc.code)
            except (URLError, TimeoutError, json.JSONDecodeError) as exc:
                increment_metric("http_errors_total")
                self._send({"error": "auth service unavailable", "detail": str(exc)}, status=502)
            return

        if parsed.path == "/admin/activity":
            token = self.headers.get("Authorization", "")
            query = f"?{parsed.query}" if parsed.query else ""
            try:
                self._send(
                    fetch_json_with_headers(
                        f"{AUTH_SERVICE_URL}/admin/activity{query}",
                        {"Authorization": token},
                    )
                )
            except HTTPError as exc:
                increment_metric("http_errors_total")
                self._send(error_payload_from_http_error(exc, "activity lookup failed"), status=exc.code)
            except (URLError, TimeoutError, json.JSONDecodeError) as exc:
                increment_metric("http_errors_total")
                self._send({"error": "auth service unavailable", "detail": str(exc)}, status=502)
            return

        increment_metric("http_errors_total")
        self._send({"error": "not found"}, status=404)

    def do_POST(self):
        increment_metric("http_requests_total")
        parsed = urlparse(self.path)

        if parsed.path == "/register":
            increment_metric("register_requests_total")
            payload = read_json_body(self)
            user_id = str(uuid.uuid4())
            wallet_id = str(uuid.uuid4())
            wallet_address = payload.get("wallet_address", "").strip() or wallet_address_for(user_id)
            auth_payload = {
                "user_id": user_id,
                "name": payload.get("name", ""),
                "email": payload.get("email", ""),
                "password": payload.get("password", ""),
                "wallet_address": wallet_address,
            }
            wallet_payload = {
                "wallet_id": wallet_id,
                "owner_user_id": user_id,
                "owner": payload.get("name", ""),
                "address": wallet_address,
                "type": "hot",
                "seed_balance": 250,
            }
            try:
                auth_result = send_json(f"{AUTH_SERVICE_URL}/register", auth_payload)
                wallet_result = send_json(f"{WALLET_SERVICE_URL}/wallets", wallet_payload)
                self._send({"user": auth_result.get("user"), "wallet": wallet_result}, status=201)
            except HTTPError as exc:
                increment_metric("http_errors_total")
                self._send(
                    error_payload_from_http_error(
                        exc,
                        "register failed",
                        "Unable to create the account right now.",
                    ),
                    status=exc.code,
                )
            except (URLError, TimeoutError, json.JSONDecodeError) as exc:
                increment_metric("http_errors_total")
                self._send(
                    {
                        "error": "register flow unavailable",
                        "detail": "Something went wrong while creating the account. Please try again.",
                    },
                    status=502,
                )
            return

        if parsed.path == "/login":
            increment_metric("login_requests_total")
            payload = read_json_body(self)
            try:
                result = send_json(f"{AUTH_SERVICE_URL}/login", payload)
                self._send(result)
                emit_audit_event(
                    {
                        "event_name": "gateway.login.forwarded",
                        "timestamp": now_iso(),
                        "actor_id": result.get("user", {}).get("user_id", payload.get("email", "anonymous")),
                        "actor_type": "user",
                        "entity_type": "session",
                        "entity_id": result.get("token", "unknown"),
                        "source_ip": self.client_address[0],
                        "service_name": SERVICE_NAME,
                        "status": "success",
                        "metadata": {"email": payload.get("email", "")},
                    }
                )
            except HTTPError as exc:
                increment_metric("http_errors_total")
                self._send(
                    error_payload_from_http_error(
                        exc,
                        "login failed",
                        "Unable to sign in right now.",
                    ),
                    status=exc.code,
                )
            except (URLError, TimeoutError, json.JSONDecodeError) as exc:
                increment_metric("http_errors_total")
                self._send(
                    {
                        "error": "auth service unavailable",
                        "detail": "Something went wrong while signing in. Please try again.",
                    },
                    status=502,
                )
            return

        if parsed.path == "/kyc-submissions":
            increment_metric("kyc_requests_total")
            payload = read_json_body(self)
            token = self.headers.get("Authorization", "")
            try:
                result = send_json_with_headers(
                    f"{AUTH_SERVICE_URL}/kyc-submissions",
                    payload,
                    {"Content-Type": "application/json", "Authorization": token},
                )
                self._send(result, status=202)
            except HTTPError as exc:
                increment_metric("http_errors_total")
                self._send({"error": "kyc submission failed", "detail": exc.reason}, status=exc.code)
            except (URLError, TimeoutError, json.JSONDecodeError) as exc:
                increment_metric("http_errors_total")
                self._send({"error": "auth service unavailable", "detail": str(exc)}, status=502)
            return

        if parsed.path.startswith("/kyc-submissions/") and parsed.path.endswith("/review"):
            increment_metric("kyc_review_requests_total")
            payload = read_json_body(self)
            token = self.headers.get("Authorization", "")
            try:
                result = send_json_with_headers(
                    f"{AUTH_SERVICE_URL}{parsed.path}",
                    payload,
                    {"Content-Type": "application/json", "Authorization": token},
                )
                self._send(result)
            except HTTPError as exc:
                increment_metric("http_errors_total")
                detail = exc.read().decode("utf-8") if hasattr(exc, "read") else exc.reason
                try:
                    payload = json.loads(detail)
                except json.JSONDecodeError:
                    payload = {"error": "kyc review failed", "detail": detail or exc.reason}
                self._send(payload, status=exc.code)
            except (URLError, TimeoutError, json.JSONDecodeError) as exc:
                increment_metric("http_errors_total")
                self._send({"error": "auth service unavailable", "detail": str(exc)}, status=502)
            return

        if parsed.path.startswith("/users/") and (
            parsed.path.endswith("/kyc-status")
            or parsed.path.endswith("/reset-kyc")
            or parsed.path.endswith("/account-status")
        ):
            payload = read_json_body(self)
            token = self.headers.get("Authorization", "")
            try:
                result = send_json_with_headers(
                    f"{AUTH_SERVICE_URL}{parsed.path}",
                    payload,
                    {"Content-Type": "application/json", "Authorization": token},
                )
                self._send(result)
            except HTTPError as exc:
                increment_metric("http_errors_total")
                self._send(error_payload_from_http_error(exc, "user update failed"), status=exc.code)
            except (URLError, TimeoutError, json.JSONDecodeError) as exc:
                increment_metric("http_errors_total")
                self._send({"error": "auth service unavailable", "detail": str(exc)}, status=502)
            return

        if parsed.path == "/transactions":
            increment_metric("transaction_requests_total")
            payload = read_json_body(self)
            token = self.headers.get("Authorization", "")
            user = current_user_from_token(token)
            if not user:
                increment_metric("http_errors_total")
                self._send({"error": "unauthorized"}, status=401)
                return
            if user.get("role") == "admin":
                increment_metric("http_errors_total")
                self._send({"error": "admins cannot send funds"}, status=403)
                return
            if payload.get("owner_user_id") != user.get("user_id"):
                increment_metric("http_errors_total")
                self._send({"error": "owner mismatch"}, status=403)
                return
            if user.get("kyc_status") != "verified":
                increment_metric("http_errors_total")
                self._send(
                    {
                        "error": "kyc_required",
                        "detail": "KYC must be approved before sending or withdrawing funds.",
                        "kyc_status": user.get("kyc_status"),
                    },
                    status=403,
                )
                return
            try:
                signed = send_json(
                    f"{WALLET_SERVICE_URL}/transactions/sign",
                    {
                        "owner_user_id": payload.get("owner_user_id"),
                        "sender": payload.get("sender"),
                        "recipient": payload.get("recipient"),
                        "amount": payload.get("amount"),
                        "nonce": payload.get("nonce"),
                    },
                )
                result = send_json(f"{DEFAULT_NODE_URL}/transactions", signed.get("transaction"))
                if not result.get("accepted"):
                    increment_metric("http_errors_total")
                    self._send(
                        {
                            "error": "transaction rejected",
                            "detail": result.get("detail", "Transaction was not accepted by the blockchain node."),
                        },
                        status=409,
                    )
                    return
                self._send(result, status=202)
            except (HTTPError, URLError, TimeoutError, json.JSONDecodeError) as exc:
                increment_metric("http_errors_total")
                self._send({"error": "transaction submission failed", "detail": str(exc)}, status=502)
            return

        if parsed.path == "/purchases":
            payload = read_json_body(self)
            token = self.headers.get("Authorization", "")
            user = current_user_from_token(token)
            if not user:
                increment_metric("http_errors_total")
                self._send({"error": "unauthorized"}, status=401)
                return
            if user.get("role") == "admin":
                increment_metric("http_errors_total")
                self._send({"error": "admins cannot buy funds"}, status=403)
                return
            if payload.get("owner_user_id") != user.get("user_id"):
                increment_metric("http_errors_total")
                self._send({"error": "owner mismatch"}, status=403)
                return
            if user.get("kyc_status") != "verified":
                increment_metric("http_errors_total")
                self._send(
                    {
                        "error": "kyc_required",
                        "detail": "KYC must be approved before buying educational funds.",
                        "kyc_status": user.get("kyc_status"),
                    },
                    status=403,
                )
                return
            try:
                result = send_json(f"{WALLET_SERVICE_URL}/purchases", payload)
                self._send(result, status=201)
            except HTTPError as exc:
                increment_metric("http_errors_total")
                self._send(
                    error_payload_from_http_error(
                        exc,
                        "purchase failed",
                        "Unable to complete the educational purchase right now.",
                    ),
                    status=exc.code,
                )
            except (URLError, TimeoutError, json.JSONDecodeError, RemoteDisconnected) as exc:
                increment_metric("http_errors_total")
                self._send({"error": "purchase flow unavailable", "detail": str(exc)}, status=502)
            return

        increment_metric("http_errors_total")
        self._send({"error": "not found"}, status=404)


if __name__ == "__main__":
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print(f"api-gateway listening on {PORT}")
    server.serve_forever()

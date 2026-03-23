import hashlib
import json
import os
import secrets
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlparse
from urllib.request import Request, urlopen

import psycopg
from psycopg.rows import dict_row


PORT = int(os.getenv("PORT", "8001"))
DATABASE_URL = os.environ["DATABASE_URL"]
KYC_ANCHOR_NODE_URL = os.getenv("KYC_ANCHOR_NODE_URL", "http://blockchain-node-1:8101").rstrip("/")
AUDIT_SERVICE_URL = os.getenv("AUDIT_SERVICE_URL", "").rstrip("/")
SERVICE_NAME = "auth-service"
METRICS = {
    "login_success_total": 0,
    "login_failure_total": 0,
    "register_success_total": 0,
    "register_conflict_total": 0,
    "kyc_submission_success_total": 0,
    "kyc_submission_failure_total": 0,
    "kyc_review_approved_total": 0,
    "kyc_review_denied_total": 0,
}


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def get_connection():
    return psycopg.connect(DATABASE_URL, row_factory=dict_row)


def hash_password(password, salt):
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt.encode("utf-8"), 120000
    ).hex()


def stable_hash(payload):
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()


def increment_metric(name, amount=1):
    METRICS[name] = METRICS.get(name, 0) + amount


def metrics_text():
    lines = [
        "# HELP service_events_total Total auth service events by counter name.",
        "# TYPE service_events_total counter",
    ]
    for metric_name, value in sorted(METRICS.items()):
        lines.append(
            f'service_events_total{{service="{SERVICE_NAME}",metric="{metric_name}"}} {value}'
        )
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


def anchor_kyc_submission(user_row, submission):
    payload = {
        "user_id": str(user_row["user_id"]),
        "submission_id": submission["submission_id"],
        "document_type": submission["document_type"],
        "country": submission["country"],
        "note": submission["note"],
        "submitted_at": submission["submitted_at"],
        "service_id": "auth-service",
    }
    anchor_hash = stable_hash(payload)
    request = Request(
        f"{KYC_ANCHOR_NODE_URL}/transactions/kyc-anchor",
        data=json.dumps({**payload, "anchor_hash": anchor_hash}).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urlopen(request, timeout=3) as response:
        result = json.loads(response.read().decode("utf-8"))
    return anchor_hash, result.get("transaction", {}).get("tx_id"), result


def submission_columns():
    return """
        submission_id::text AS submission_id,
        document_type,
        country,
        note,
        submitted_at::text AS submitted_at,
        status,
        anchor_hash,
        anchor_tx_id,
        review_note,
        reviewed_at::text AS reviewed_at,
        reviewed_by_user_id::text AS reviewed_by_user_id
    """


def submissions_for_user(connection, user_id):
    with connection.cursor() as cursor:
        cursor.execute(
            f"""
            SELECT {submission_columns()}
            FROM kyc_submissions
            WHERE user_id = %s
            ORDER BY submitted_at DESC
            LIMIT 10
            """,
            (user_id,),
        )
        return cursor.fetchall()


def latest_session_for_user(connection, user_id):
    with connection.cursor() as cursor:
        cursor.execute(
            """
            SELECT created_at::text AS created_at
            FROM sessions
            WHERE user_id = %s
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (user_id,),
        )
        row = cursor.fetchone()
        return row["created_at"] if row else None


def user_summary(connection, user_row):
    submissions = submissions_for_user(connection, user_row["user_id"])
    return {
        "user_id": str(user_row["user_id"]),
        "name": user_row["name"],
        "email": user_row["email"],
        "role": user_row.get("role", "user"),
        "wallet_address": user_row["wallet_address"],
        "kyc_status": user_row["kyc_status"],
        "account_status": user_row.get("account_status", "active"),
        "created_at": user_row["created_at"].isoformat(),
        "last_activity": latest_session_for_user(connection, user_row["user_id"]),
        "kyc_submissions": submissions,
    }


def sanitize_user(connection, user_row):
    return user_summary(connection, user_row)


def list_users(connection, query):
    search = query.get("search", [""])[0].strip().lower()
    role = query.get("role", [""])[0].strip().lower()
    kyc_status = query.get("kyc_status", [""])[0].strip().lower()
    account_status = query.get("account_status", [""])[0].strip().lower()
    filters = []
    params = []

    if search:
        filters.append(
            "(LOWER(name) LIKE %s OR LOWER(email) LIKE %s OR LOWER(wallet_address) LIKE %s OR user_id::text LIKE %s)"
        )
        like = f"%{search}%"
        params.extend([like, like, like, like])
    if role:
        filters.append("LOWER(role) = %s")
        params.append(role)
    if kyc_status:
        filters.append("LOWER(kyc_status) = %s")
        params.append(kyc_status)
    if account_status:
        filters.append("LOWER(account_status) = %s")
        params.append(account_status)

    where_clause = f"WHERE {' AND '.join(filters)}" if filters else ""
    with connection.cursor() as cursor:
        cursor.execute(
            f"""
            SELECT *
            FROM users
            {where_clause}
            ORDER BY created_at DESC
            """,
            params,
        )
        rows = cursor.fetchall()
    return [user_summary(connection, row) for row in rows]


def admin_activity(connection, limit=25):
    with connection.cursor() as cursor:
        cursor.execute(
            """
            SELECT token, user_id::text AS user_id, created_at::text AS created_at
            FROM sessions
            ORDER BY created_at DESC
            LIMIT %s
            """,
            (limit,),
        )
        sessions = cursor.fetchall()
        cursor.execute(
            f"""
            SELECT user_id::text AS user_id, {submission_columns()}
            FROM kyc_submissions
            ORDER BY submitted_at DESC
            LIMIT %s
            """,
            (limit,),
        )
        submissions = cursor.fetchall()

    activity = []
    for row in sessions:
        activity.append(
            {
                "type": "session",
                "timestamp": row["created_at"],
                "message": f"User {row['user_id']} signed in",
                "entity_id": row["token"],
            }
        )
    for row in submissions:
        activity.append(
            {
                "type": "kyc",
                "timestamp": row["reviewed_at"] or row["submitted_at"],
                "message": f"KYC {row['status']} for user {row['user_id']}",
                "entity_id": row["submission_id"],
            }
        )
    activity.sort(key=lambda item: item["timestamp"] or "", reverse=True)
    return activity[:limit]


def read_json_body(handler):
    content_length = int(handler.headers.get("Content-Length", "0"))
    raw = handler.rfile.read(content_length) if content_length else b"{}"
    return json.loads(raw.decode("utf-8"))


def current_user(handler, connection):
    token = handler.headers.get("Authorization", "").removeprefix("Bearer ").strip()
    if not token:
        token = handler.headers.get("X-Session-Token", "").strip()
    if not token:
        return None

    with connection.cursor() as cursor:
        cursor.execute(
            """
            SELECT users.*
            FROM sessions
            JOIN users ON users.user_id = sessions.user_id
            WHERE sessions.token = %s
            """,
            (token,),
        )
        user = cursor.fetchone()
    if not user:
        return None
    if user.get("account_status", "active") != "active":
        return None
    return user


def require_admin(handler, connection):
    user = current_user(handler, connection)
    if not user:
        return None, {"error": "unauthorized"}, 401
    if user.get("role") != "admin":
        return None, {"error": "forbidden"}, 403
    return user, None, None


class Handler(BaseHTTPRequestHandler):
    def _send(self, payload, status=200, content_type="application/json"):
        body = payload.encode("utf-8") if isinstance(payload, str) else json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header(
            "Access-Control-Allow-Headers",
            "Content-Type, Authorization, X-Session-Token",
        )
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
                    "service": "auth-service",
                    "status": "ok",
                    "timestamp": now_iso(),
                    "database_backend": "postgresql",
                    "kyc_anchor_node_url": KYC_ANCHOR_NODE_URL,
                }
            )
            return

        if parsed.path == "/metrics":
            self._send(metrics_text(), content_type="text/plain; version=0.0.4")
            return

        if parsed.path == "/me":
            with get_connection() as connection:
                user = current_user(self, connection)
                if not user:
                    self._send({"error": "unauthorized"}, status=401)
                    return
                self._send({"user": sanitize_user(connection, user)})
            return

        if parsed.path == "/kyc-submissions":
            query = parse_qs(parsed.query)
            mode = query.get("mode", ["user"])[0]
            with get_connection() as connection:
                if mode == "review_queue":
                    admin_user, error_payload, error_status = require_admin(self, connection)
                    if error_payload:
                        self._send(error_payload, status=error_status)
                        return
                    with connection.cursor() as cursor:
                        cursor.execute(
                            f"""
                            SELECT
                                kyc_submissions.user_id::text AS user_id,
                                users.name,
                                users.email,
                                {submission_columns()}
                            FROM kyc_submissions
                            JOIN users ON users.user_id = kyc_submissions.user_id
                            WHERE kyc_submissions.status = 'pending_review'
                            ORDER BY kyc_submissions.submitted_at ASC
                            """
                        )
                        submissions = cursor.fetchall()
                    self._send(
                        {
                            "admin_user_id": str(admin_user["user_id"]),
                            "submissions": submissions,
                        }
                    )
                    return

                user = current_user(self, connection)
                if not user:
                    self._send({"error": "unauthorized"}, status=401)
                    return
                self._send({"submissions": submissions_for_user(connection, user["user_id"])})
            return

        if parsed.path == "/users":
            with get_connection() as connection:
                admin_user, error_payload, error_status = require_admin(self, connection)
                if error_payload:
                    self._send(error_payload, status=error_status)
                    return
                users = list_users(connection, parse_qs(parsed.query))
                totals = {
                    "total_users": len(users),
                    "verified_users": sum(1 for user in users if user["kyc_status"] == "verified"),
                    "pending_reviews": sum(1 for user in users if user["kyc_status"] == "pending_review"),
                    "resubmission_required": sum(1 for user in users if user["kyc_status"] == "denied"),
                }
                self._send({"users": users, "summary": totals})
            return

        if parsed.path.startswith("/users/"):
            user_id = parsed.path.split("/")[2]
            with get_connection() as connection:
                admin_user, error_payload, error_status = require_admin(self, connection)
                if error_payload:
                    self._send(error_payload, status=error_status)
                    return
                with connection.cursor() as cursor:
                    cursor.execute("SELECT * FROM users WHERE user_id = %s", (user_id,))
                    user = cursor.fetchone()
                if not user:
                    self._send({"error": "user not found"}, status=404)
                    return
                self._send({"user": user_summary(connection, user)})
            return

        if parsed.path == "/admin/activity":
            query = parse_qs(parsed.query)
            try:
                limit = int(query.get("limit", ["25"])[0])
            except ValueError:
                limit = 25
            limit = max(1, min(limit, 1000))
            with get_connection() as connection:
                admin_user, error_payload, error_status = require_admin(self, connection)
                if error_payload:
                    self._send(error_payload, status=error_status)
                    return
                self._send({"events": admin_activity(connection, limit=limit)})
            return

        self._send({"error": "not found"}, status=404)

    def do_POST(self):
        parsed = urlparse(self.path)

        if parsed.path == "/register":
            payload = read_json_body(self)
            name = payload.get("name", "").strip()
            email = payload.get("email", "").strip().lower()
            password = payload.get("password", "")
            wallet_address = payload.get("wallet_address", "").strip()
            user_id = payload.get("user_id", "").strip() or str(uuid.uuid4())
            if not name or not email or not password or not wallet_address:
                self._send({"error": "missing required fields"}, status=400)
                return

            with get_connection() as connection:
                with connection.cursor() as cursor:
                    cursor.execute("SELECT 1 FROM users WHERE email = %s", (email,))
                    if cursor.fetchone():
                        increment_metric("register_conflict_total")
                        self._send({"error": "email already exists"}, status=409)
                        return

                    salt = secrets.token_hex(8)
                    cursor.execute(
                        """
                        INSERT INTO users (
                            user_id, name, email, password_hash, salt, wallet_address, kyc_status, created_at, role
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                        RETURNING *
                        """,
                        (
                            user_id,
                            name,
                            email,
                            hash_password(password, salt),
                            salt,
                            wallet_address,
                            "not_started",
                            now_iso(),
                            "user",
                        ),
                    )
                    user = cursor.fetchone()
                connection.commit()
                increment_metric("register_success_total")
                emit_audit_event(
                    {
                        "event_name": "auth.user.registered",
                        "timestamp": now_iso(),
                        "actor_id": str(user["user_id"]),
                        "actor_type": "user",
                        "entity_type": "user",
                        "entity_id": str(user["user_id"]),
                        "source_ip": self.client_address[0],
                        "service_name": SERVICE_NAME,
                        "status": "success",
                        "metadata": {"email": email},
                    }
                )
                self._send({"user": sanitize_user(connection, user)}, status=201)
            return

        if parsed.path == "/login":
            payload = read_json_body(self)
            email = payload.get("email", "").strip().lower()
            password = payload.get("password", "")

            with get_connection() as connection:
                with connection.cursor() as cursor:
                    cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
                    user = cursor.fetchone()
                    if not user:
                        increment_metric("login_failure_total")
                        self._send({"error": "invalid credentials"}, status=401)
                        return
                    if user["password_hash"] != hash_password(password, user["salt"]):
                        increment_metric("login_failure_total")
                        self._send({"error": "invalid credentials"}, status=401)
                        return
                    if user.get("account_status", "active") != "active":
                        increment_metric("login_failure_total")
                        if user.get("account_status") == "suspended":
                            self._send(
                                {
                                    "error": "account_suspended",
                                    "detail": "Your account is suspended. Please contact an administrator.",
                                },
                                status=403,
                            )
                        elif user.get("account_status") == "blocked":
                            self._send(
                                {
                                    "error": "account_blocked",
                                    "detail": "Your account is blocked. Please contact an administrator.",
                                },
                                status=403,
                            )
                        else:
                            self._send({"error": "account unavailable"}, status=403)
                        return

                    token = secrets.token_hex(16)
                    cursor.execute(
                        "INSERT INTO sessions (token, user_id, created_at) VALUES (%s, %s, %s)",
                        (token, user["user_id"], now_iso()),
                    )
                connection.commit()
                increment_metric("login_success_total")
                emit_audit_event(
                    {
                        "event_name": "auth.login.succeeded",
                        "timestamp": now_iso(),
                        "actor_id": str(user["user_id"]),
                        "actor_type": "user",
                        "entity_type": "session",
                        "entity_id": token,
                        "source_ip": self.client_address[0],
                        "service_name": SERVICE_NAME,
                        "status": "success",
                        "metadata": {"email": email, "role": user.get("role", "user")},
                    }
                )
                self._send({"token": token, "user": sanitize_user(connection, user)})
            return

        if parsed.path == "/kyc-submissions":
            payload = read_json_body(self)
            with get_connection() as connection:
                user = current_user(self, connection)
                if not user:
                    self._send({"error": "unauthorized"}, status=401)
                    return
                if user.get("role") == "admin":
                    self._send({"error": "admins cannot submit KYC"}, status=400)
                    return
                if user.get("kyc_status") == "verified":
                    self._send({"error": "kyc already approved"}, status=409)
                    return
                if user.get("kyc_status") == "pending_review":
                    self._send({"error": "kyc already pending review"}, status=409)
                    return

                submission_id = str(uuid.uuid4())
                with connection.cursor() as cursor:
                    cursor.execute(
                        """
                        INSERT INTO kyc_submissions (
                            submission_id, user_id, document_type, country, note, submitted_at, status, review_note, reviewed_at, reviewed_by_user_id
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s, NULL, NULL, NULL)
                        RETURNING
                        """
                        + submission_columns(),
                        (
                            submission_id,
                            user["user_id"],
                            payload.get("document_type", "government_id"),
                            payload.get("country", "US"),
                            payload.get("note", ""),
                            now_iso(),
                            "pending_review",
                        ),
                    )
                    submission = cursor.fetchone()
                    try:
                        anchor_hash, anchor_tx_id, anchor_result = anchor_kyc_submission(user, submission)
                    except (HTTPError, URLError, TimeoutError, json.JSONDecodeError) as exc:
                        connection.rollback()
                        increment_metric("kyc_submission_failure_total")
                        self._send({"error": "kyc anchor failed", "detail": str(exc)}, status=502)
                        return
                    if not anchor_result.get("accepted"):
                        connection.rollback()
                        increment_metric("kyc_submission_failure_total")
                        self._send({"error": "kyc anchor rejected", "detail": anchor_result}, status=409)
                        return
                    cursor.execute(
                        """
                        UPDATE kyc_submissions
                        SET anchor_hash = %s, anchor_tx_id = %s
                        WHERE submission_id = %s
                        RETURNING
                        """
                        + submission_columns(),
                        (anchor_hash, anchor_tx_id, submission["submission_id"]),
                    )
                    submission = cursor.fetchone()
                    cursor.execute(
                        "UPDATE users SET kyc_status = %s WHERE user_id = %s RETURNING *",
                        ("pending_review", user["user_id"]),
                    )
                    refreshed_user = cursor.fetchone()
                connection.commit()
                increment_metric("kyc_submission_success_total")
                emit_audit_event(
                    {
                        "event_name": "auth.kyc.submitted",
                        "timestamp": now_iso(),
                        "actor_id": str(user["user_id"]),
                        "actor_type": "user",
                        "entity_type": "kyc_submission",
                        "entity_id": submission["submission_id"],
                        "source_ip": self.client_address[0],
                        "service_name": SERVICE_NAME,
                        "status": "success",
                        "metadata": {"anchor_tx_id": submission["anchor_tx_id"]},
                    }
                )
                self._send(
                    {"submission": submission, "user": sanitize_user(connection, refreshed_user)},
                    status=202,
                )
            return

        if parsed.path.startswith("/kyc-submissions/") and parsed.path.endswith("/review"):
            payload = read_json_body(self)
            submission_id = parsed.path.split("/")[2]
            action = payload.get("action", "").strip().lower()
            review_note = payload.get("review_note", "").strip()
            if action not in {"approve", "deny"}:
                self._send({"error": "action must be approve or deny"}, status=400)
                return
            if action == "deny" and not review_note:
                self._send({"error": "review_note is required when denying"}, status=400)
                return

            with get_connection() as connection:
                admin_user, error_payload, error_status = require_admin(self, connection)
                if error_payload:
                    self._send(error_payload, status=error_status)
                    return
                with connection.cursor() as cursor:
                    cursor.execute(
                        f"""
                        SELECT user_id::text AS user_id, {submission_columns()}
                        FROM kyc_submissions
                        WHERE submission_id = %s
                        """,
                        (submission_id,),
                    )
                    submission = cursor.fetchone()
                    if not submission:
                        self._send({"error": "submission not found"}, status=404)
                        return
                    if submission["status"] != "pending_review":
                        self._send({"error": "submission is not pending"}, status=409)
                        return

                    next_status = "approved" if action == "approve" else "denied"
                    next_user_status = "verified" if action == "approve" else "denied"
                    cursor.execute(
                        """
                        UPDATE kyc_submissions
                        SET status = %s, review_note = %s, reviewed_at = %s, reviewed_by_user_id = %s
                        WHERE submission_id = %s
                        RETURNING
                        """
                        + submission_columns(),
                        (
                            next_status,
                            review_note,
                            now_iso(),
                            admin_user["user_id"],
                            submission_id,
                        ),
                    )
                    reviewed_submission = cursor.fetchone()
                    cursor.execute(
                        "UPDATE users SET kyc_status = %s WHERE user_id = %s RETURNING *",
                        (next_user_status, submission["user_id"]),
                    )
                    reviewed_user = cursor.fetchone()
                connection.commit()
                metric_name = "kyc_review_approved_total" if action == "approve" else "kyc_review_denied_total"
                increment_metric(metric_name)
                emit_audit_event(
                    {
                        "event_name": "auth.kyc.approved" if action == "approve" else "auth.kyc.denied",
                        "timestamp": now_iso(),
                        "actor_id": str(admin_user["user_id"]),
                        "actor_type": "admin",
                        "entity_type": "kyc_submission",
                        "entity_id": reviewed_submission["submission_id"],
                        "source_ip": self.client_address[0],
                        "service_name": SERVICE_NAME,
                        "status": "success",
                        "metadata": {
                            "target_user_id": submission["user_id"],
                            "review_note": review_note,
                        },
                    }
                )
                self._send(
                    {
                        "submission": reviewed_submission,
                        "user": sanitize_user(connection, reviewed_user),
                    }
                )
            return

        if parsed.path.startswith("/users/") and parsed.path.endswith("/kyc-status"):
            payload = read_json_body(self)
            user_id = parsed.path.split("/")[2]
            next_status = payload.get("status", "").strip()
            note = payload.get("note", "").strip()
            allowed_statuses = {
                "not_started",
                "pending_review",
                "verified",
                "denied",
            }
            if next_status not in allowed_statuses:
                self._send({"error": "invalid kyc status"}, status=400)
                return

            with get_connection() as connection:
                admin_user, error_payload, error_status = require_admin(self, connection)
                if error_payload:
                    self._send(error_payload, status=error_status)
                    return
                with connection.cursor() as cursor:
                    cursor.execute("SELECT * FROM users WHERE user_id = %s", (user_id,))
                    user = cursor.fetchone()
                    if not user:
                        self._send({"error": "user not found"}, status=404)
                        return
                    cursor.execute(
                        "UPDATE users SET kyc_status = %s WHERE user_id = %s RETURNING *",
                        (next_status, user_id),
                    )
                    updated_user = cursor.fetchone()
                    if next_status in {"denied", "verified"}:
                        cursor.execute(
                            """
                            UPDATE kyc_submissions
                            SET status = %s, review_note = %s, reviewed_at = %s, reviewed_by_user_id = %s
                            WHERE submission_id = (
                                SELECT submission_id
                                FROM kyc_submissions
                                WHERE user_id = %s
                                ORDER BY submitted_at DESC
                                LIMIT 1
                            )
                            """,
                            (next_status, note, now_iso(), admin_user["user_id"], user_id),
                        )
                connection.commit()
                emit_audit_event(
                    {
                        "event_name": "auth.user.kyc_status_updated",
                        "timestamp": now_iso(),
                        "actor_id": str(admin_user["user_id"]),
                        "actor_type": "admin",
                        "entity_type": "user",
                        "entity_id": user_id,
                        "source_ip": self.client_address[0],
                        "service_name": SERVICE_NAME,
                        "status": "success",
                        "metadata": {"kyc_status": next_status, "note": note},
                    }
                )
                self._send({"user": user_summary(connection, updated_user)})
            return

        if parsed.path.startswith("/users/") and parsed.path.endswith("/reset-kyc"):
            payload = read_json_body(self)
            user_id = parsed.path.split("/")[2]
            note = payload.get("note", "").strip()
            with get_connection() as connection:
                admin_user, error_payload, error_status = require_admin(self, connection)
                if error_payload:
                    self._send(error_payload, status=error_status)
                    return
                with connection.cursor() as cursor:
                    cursor.execute("SELECT * FROM users WHERE user_id = %s", (user_id,))
                    user = cursor.fetchone()
                    if not user:
                        self._send({"error": "user not found"}, status=404)
                        return
                    cursor.execute(
                        "UPDATE users SET kyc_status = %s WHERE user_id = %s RETURNING *",
                        ("not_started", user_id),
                    )
                    updated_user = cursor.fetchone()
                    cursor.execute(
                        """
                        UPDATE kyc_submissions
                        SET status = %s, review_note = %s, reviewed_at = %s, reviewed_by_user_id = %s
                        WHERE submission_id = (
                            SELECT submission_id
                            FROM kyc_submissions
                            WHERE user_id = %s
                            ORDER BY submitted_at DESC
                            LIMIT 1
                        )
                        """,
                        ("denied", note or "Admin requested KYC resubmission", now_iso(), admin_user["user_id"], user_id),
                    )
                connection.commit()
                emit_audit_event(
                    {
                        "event_name": "auth.user.kyc_reset",
                        "timestamp": now_iso(),
                        "actor_id": str(admin_user["user_id"]),
                        "actor_type": "admin",
                        "entity_type": "user",
                        "entity_id": user_id,
                        "source_ip": self.client_address[0],
                        "service_name": SERVICE_NAME,
                        "status": "success",
                        "metadata": {"note": note},
                    }
                )
                self._send({"user": user_summary(connection, updated_user)})
            return

        if parsed.path.startswith("/users/") and parsed.path.endswith("/account-status"):
            payload = read_json_body(self)
            user_id = parsed.path.split("/")[2]
            next_status = payload.get("status", "").strip()
            allowed_statuses = {"active", "suspended", "blocked"}
            if next_status not in allowed_statuses:
                self._send({"error": "invalid account status"}, status=400)
                return
            with get_connection() as connection:
                admin_user, error_payload, error_status = require_admin(self, connection)
                if error_payload:
                    self._send(error_payload, status=error_status)
                    return
                with connection.cursor() as cursor:
                    cursor.execute(
                        "UPDATE users SET account_status = %s WHERE user_id = %s RETURNING *",
                        (next_status, user_id),
                    )
                    updated_user = cursor.fetchone()
                if not updated_user:
                    self._send({"error": "user not found"}, status=404)
                    return
                connection.commit()
                self._send({"user": user_summary(connection, updated_user)})
            return

        self._send({"error": "not found"}, status=404)


if __name__ == "__main__":
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print(f"auth-service listening on {PORT} using {DATABASE_URL}")
    server.serve_forever()

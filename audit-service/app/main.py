import json
import os
import threading
from collections import Counter
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse


PORT = int(os.getenv("PORT", "8010"))
DATA_DIR = Path(os.getenv("DATA_DIR", "/var/lib/audit"))
LOG_PATH = DATA_DIR / "audit-events.ndjson"

REQUIRED_FIELDS = {
    "event_name",
    "timestamp",
    "actor_id",
    "actor_type",
    "entity_type",
    "entity_id",
    "source_ip",
    "service_name",
    "status",
}


def now_iso():
    return datetime.now(timezone.utc).isoformat()


class AuditState:
    def __init__(self):
        self.lock = threading.Lock()
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        self.events = self._load_events()

    def _load_events(self):
        if not LOG_PATH.exists():
            return []
        events = []
        for line in LOG_PATH.read_text().splitlines():
            if not line.strip():
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return events

    def append(self, event):
        with self.lock:
            with LOG_PATH.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(event, sort_keys=True) + "\n")
            self.events.append(event)

    def recent(self, limit=50):
        with self.lock:
            return list(reversed(self.events[-limit:]))

    def summary(self):
        with self.lock:
            by_service = Counter(event["service_name"] for event in self.events)
            by_status = Counter(event["status"] for event in self.events)
            by_event = Counter(event["event_name"] for event in self.events)
            return {
                "service": "audit-service",
                "status": "ok",
                "event_count": len(self.events),
                "by_service": dict(by_service),
                "by_status": dict(by_status),
                "top_events": dict(by_event.most_common(10)),
                "last_event_at": self.events[-1]["timestamp"] if self.events else None,
            }

    def metrics_text(self):
        summary = self.summary()
        lines = [
            "# HELP audit_events_total Total audit events received.",
            "# TYPE audit_events_total counter",
            f"audit_events_total {summary['event_count']}",
            "# HELP audit_events_by_status Total audit events by status.",
            "# TYPE audit_events_by_status counter",
        ]
        for status, count in sorted(summary["by_status"].items()):
            lines.append(f'audit_events_by_status{{status="{status}"}} {count}')
        lines.extend(
            [
                "# HELP audit_events_by_service Total audit events by service.",
                "# TYPE audit_events_by_service counter",
            ]
        )
        for service_name, count in sorted(summary["by_service"].items()):
            lines.append(
                f'audit_events_by_service{{service_name="{service_name}"}} {count}'
            )
        return "\n".join(lines) + "\n"


STATE = AuditState()


def read_json_body(handler):
    content_length = int(handler.headers.get("Content-Length", "0"))
    raw = handler.rfile.read(content_length) if content_length else b"{}"
    return json.loads(raw.decode("utf-8"))


class Handler(BaseHTTPRequestHandler):
    def _send(self, payload, status=200, content_type="application/json"):
        body = payload if isinstance(payload, bytes) else json.dumps(payload).encode("utf-8")
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
        parsed = urlparse(self.path)
        if parsed.path == "/health":
            self._send(STATE.summary())
            return

        if parsed.path == "/events":
            query = parse_qs(parsed.query)
            try:
                limit = max(1, min(int(query.get("limit", ["50"])[0]), 200))
            except ValueError:
                limit = 50
            self._send({"events": STATE.recent(limit)})
            return

        if parsed.path == "/summary":
            self._send(STATE.summary())
            return

        if parsed.path == "/metrics":
            self._send(STATE.metrics_text().encode("utf-8"), content_type="text/plain; version=0.0.4")
            return

        self._send({"error": "not found"}, status=404)

    def do_POST(self):
        if self.path != "/events":
            self._send({"error": "not found"}, status=404)
            return

        event = read_json_body(self)
        missing = sorted(REQUIRED_FIELDS.difference(event.keys()))
        if missing:
            self._send({"error": "missing required fields", "missing": missing}, status=400)
            return
        if "received_at" not in event:
            event["received_at"] = now_iso()
        STATE.append(event)
        self._send({"accepted": True, "event": event}, status=202)


if __name__ == "__main__":
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print(f"audit-service listening on {PORT}")
    server.serve_forever()

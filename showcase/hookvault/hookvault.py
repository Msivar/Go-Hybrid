"""HookVault: signed, durable webhook inbox. Python 3.10+, standard library only."""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import sqlite3
import time
import uuid
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

MAX_BODY = 1_048_576
EVENT_ID = re.compile(r"[A-Za-z0-9_.:-]{1,128}\Z")


def signature(secret: str, timestamp: str, event_id: str, body: bytes) -> str:
    identity = event_id.encode()
    message = timestamp.encode() + b":" + str(len(identity)).encode() + b":" + identity + b":" + body
    return "sha256=" + hmac.new(secret.encode(), message, hashlib.sha256).hexdigest()


class Inbox:
    def __init__(self, path: str | Path):
        self.path = str(path)
        with self.connect() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.executescript("""
                CREATE TABLE IF NOT EXISTS events (
                    id TEXT PRIMARY KEY, digest TEXT NOT NULL, body TEXT NOT NULL,
                    received REAL NOT NULL, status TEXT NOT NULL DEFAULT 'pending',
                    attempts INTEGER NOT NULL DEFAULT 0, available REAL NOT NULL,
                    token TEXT, lease_until REAL, last_error TEXT
                );
                CREATE INDEX IF NOT EXISTS pending_events
                    ON events(status, available, received);
            """)

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    def receive(self, event_id: str, body: bytes) -> str:
        digest = hashlib.sha256(body).hexdigest()
        now = time.time()
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            previous = db.execute("SELECT digest FROM events WHERE id=?", (event_id,)).fetchone()
            if previous:
                return "duplicate" if hmac.compare_digest(previous["digest"], digest) else "conflict"
            db.execute("INSERT INTO events(id,digest,body,received,available) VALUES(?,?,?,?,?)",
                       (event_id, digest, body.decode("utf-8"), now, now))
        return "created"

    def claim(self, lease_seconds=60, now=None):
        if not 1 <= lease_seconds <= 3600:
            raise ValueError("lease_seconds must be between 1 and 3600")
        now = time.time() if now is None else now
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            # A worker crash can exhaust retries, too. Never strand its final lease.
            db.execute("UPDATE events SET status='dead',token=NULL,lease_until=NULL "
                       "WHERE status='leased' AND lease_until<=? AND attempts>=5", (now,))
            row = db.execute("SELECT * FROM events WHERE attempts<5 AND "
                             "((status='pending' AND available<=?) OR "
                             "(status='leased' AND lease_until<=?)) "
                             "ORDER BY received,id LIMIT 1", (now, now)).fetchone()
            if row is None:
                return None
            token = uuid.uuid4().hex
            db.execute("UPDATE events SET status='leased',attempts=attempts+1,"
                       "token=?,lease_until=? WHERE id=?", (token, now + lease_seconds, row["id"]))
            return {"id": row["id"], "payload": json.loads(row["body"]), "token": token,
                    "attempt": row["attempts"] + 1, "lease_until": now + lease_seconds}

    def settle(self, event_id, token, error=None, delay=0, now=None):
        now = time.time() if now is None else now
        if not 0 <= delay <= 3600:
            raise ValueError("retry delay must be between 0 and 3600")
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT attempts FROM events WHERE id=? AND token=? "
                             "AND status='leased' AND lease_until>?", (event_id, token, now)).fetchone()
            if row is None:
                return False
            state = "done" if error is None else ("dead" if row["attempts"] >= 5 else "pending")
            db.execute("UPDATE events SET status=?,token=NULL,lease_until=NULL,available=?,"
                       "last_error=? WHERE id=?", (state, now + delay, error, event_id))
        return True

    def list_events(self, limit=20, include_payload=False):
        if not 1 <= limit <= 1000:
            raise ValueError("limit must be between 1 and 1000")
        columns = "id,digest,received,status,attempts,available,lease_until,last_error"
        if include_payload:
            columns += ",body"
        with self.connect() as db:
            rows = db.execute(f"SELECT {columns} FROM events ORDER BY received DESC,id LIMIT ?", (limit,))
            return [dict(row) for row in rows]


def make_server(inbox, secret, host="127.0.0.1", port=8787):
    if len(secret.encode()) < 32:
        raise ValueError("HOOKVAULT_SECRET must be at least 32 bytes")

    class Handler(BaseHTTPRequestHandler):
        server_version = "HookVault/1.0"

        def log_message(self, fmt, *args):
            # Log outcome only. Paths and payloads may contain customer information.
            pass

        def setup(self):
            super().setup()
            self.connection.settimeout(10)

        def respond(self, code, value):
            body = json.dumps(value, ensure_ascii=False).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            self.respond(200, {"ok": True, "service": "hookvault"}) if self.path == "/health" else self.respond(404, {"error": "not_found"})

        def do_POST(self):
            if self.path != "/hooks":
                self.respond(404, {"error": "not_found"})
                return
            lengths = self.headers.get_all("Content-Length", [])
            if len(lengths) != 1 or self.headers.get("Transfer-Encoding"):
                self.respond(400, {"error": "one_content_length_required"})
                return
            try:
                length = int(lengths[0])
            except ValueError:
                self.respond(400, {"error": "invalid_content_length"})
                return
            if not 0 < length <= MAX_BODY:
                self.respond(413, {"error": "body_limit_1_mib"})
                return
            event_id = self.headers.get("X-Hook-Id", "")
            timestamp = self.headers.get("X-Hook-Timestamp", "")
            provided = self.headers.get("X-Hook-Signature", "")
            if not EVENT_ID.fullmatch(event_id) or not re.fullmatch(r"[0-9]{1,12}", timestamp):
                self.respond(400, {"error": "invalid_event_headers"})
                return
            if abs(time.time() - int(timestamp)) > 300:
                self.respond(401, {"error": "expired_timestamp"})
                return
            if self.headers.get_content_type() != "application/json":
                self.respond(415, {"error": "application_json_required"})
                return
            try:
                body = self.rfile.read(length)
                if len(body) != length:
                    self.respond(400, {"error": "incomplete_body"})
                    return
                expected = signature(secret, timestamp, event_id, body)
                if not hmac.compare_digest(expected.encode(), provided.encode()):
                    self.respond(401, {"error": "invalid_signature"})
                    return
                json.loads(body.decode("utf-8"), parse_constant=lambda x: (_ for _ in ()).throw(ValueError(x)))
                result = inbox.receive(event_id, body)
                codes = {"created": 201, "duplicate": 200, "conflict": 409}
                self.respond(codes[result], {"id": event_id, "result": result})
            except (UnicodeError, ValueError, RecursionError):
                self.respond(400, {"error": "invalid_json"})
            except (TimeoutError, OSError):
                self.close_connection = True
            except sqlite3.Error:
                self.respond(503, {"error": "storage_unavailable"})

    return ThreadingHTTPServer((host, port), Handler)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", default="hookvault.sqlite3")
    commands = parser.add_subparsers(dest="command", required=True)
    serve = commands.add_parser("serve")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8787)
    listing = commands.add_parser("list")
    listing.add_argument("--limit", type=int, default=20)
    listing.add_argument("--payload", action="store_true")
    claim = commands.add_parser("claim")
    claim.add_argument("--lease", type=int, default=60)
    for name in ("ack", "retry"):
        settle = commands.add_parser(name)
        settle.add_argument("id")
        settle.add_argument("token")
        if name == "retry":
            settle.add_argument("--error", required=True)
            settle.add_argument("--delay", type=int, default=30)
    args = parser.parse_args()
    try:
        inbox = Inbox(args.db)
        if args.command == "serve":
            server = make_server(inbox, os.environ.get("HOOKVAULT_SECRET", ""), args.host, args.port)
            print(f"HookVault listening on http://{args.host}:{server.server_port}", flush=True)
            try:
                server.serve_forever()
            except KeyboardInterrupt:
                pass
            finally:
                server.server_close()
            return 0
        if args.command == "list":
            result = inbox.list_events(args.limit, args.payload)
        elif args.command == "claim":
            result = inbox.claim(args.lease)
        else:
            result = {"settled": inbox.settle(args.id, args.token,
                       getattr(args, "error", None), getattr(args, "delay", 0))}
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 1 if isinstance(result, dict) and result.get("settled") is False else 0
    except (ValueError, sqlite3.Error, OSError) as exc:
        parser.exit(2, f"HookVault: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())


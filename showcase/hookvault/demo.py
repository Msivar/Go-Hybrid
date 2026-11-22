"""Run the complete local demo; no external services, keys or packages needed."""
import http.client
import json
import secrets
import tempfile
import threading
import time
from pathlib import Path

from hookvault import Inbox, make_server, signature


def main():
    with tempfile.TemporaryDirectory(prefix="hookvault-demo-") as folder:
        inbox = Inbox(Path(folder) / "inbox.sqlite3")
        secret = secrets.token_hex(32)
        server = make_server(inbox, secret, port=0)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        def deliver(body):
            stamp = str(int(time.time()))
            headers = {"Content-Type": "application/json", "X-Hook-Id": "order-1042",
                       "X-Hook-Timestamp": stamp,
                       "X-Hook-Signature": signature(secret, stamp, "order-1042", body)}
            client = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=3)
            try:
                client.request("POST", "/hooks", body=body, headers=headers)
                response = client.getresponse()
                return {"http": response.status, **json.loads(response.read())}
            finally:
                client.close()

        try:
            body = b'{"order":1042,"total":4900,"currency":"RUB"}'
            print("1. First delivery:", json.dumps(deliver(body)))
            print("2. Network retry:", json.dumps(deliver(body)))
            print("3. Same ID, different payload:", json.dumps(deliver(b'{"order":1042,"total":1}')))
            task = inbox.claim()
            print("4. Worker receives:", json.dumps({"id": task["id"], "payload": task["payload"], "attempt": task["attempt"]}))
            print("5. Worker acknowledges:", inbox.settle(task["id"], task["token"]))
            print("6. Saved status:", inbox.list_events()[0]["status"])
        finally:
            server.shutdown()
            server.server_close()
            thread.join()


if __name__ == "__main__":
    main()

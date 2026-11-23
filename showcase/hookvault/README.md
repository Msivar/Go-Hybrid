# HookVault

A small Python/SQLite webhook inbox with signed delivery, durable deduplication and worker leases. This directory is a standalone demonstration, independent of Hybrid; it is not a Hybrid feature or an upstream contribution.

A sender may retry after a timeout. HookVault records the event before acknowledging receipt, detects duplicate deliveries and separates receiving from processing. It uses Python 3.10+ and the standard library only.

## Try it locally

Download this directory, then run:

```text
python -B demo.py
python -B -m unittest -v
```

The demo starts a temporary loopback HTTP server, uses a temporary SQLite database and exits automatically. It does not call a payment provider or customer system. The observed sequence is HTTP 201 for the first delivery, 200 for an identical retry, and 409 for the same ID with a different body. The worker receives the original payload and records completion.

Validation: 17 tests passed on Windows/Python 3.12.14. See [verification.txt](verification.txt) and [the tests](test_hookvault.py). This is local verification, not a production benchmark or independent security audit.

## Run a persistent inbox

PowerShell:

```powershell
$env:HOOKVAULT_SECRET = python -c "import secrets; print(secrets.token_hex(32))"
python hookvault.py --db inbox.sqlite3 serve
```

Keep the generated secret private and reuse it across restarts. The server defaults to `127.0.0.1:8787`.

POST JSON to `/hooks` with `X-Hook-Id`, `X-Hook-Timestamp` and `X-Hook-Signature`. The ID must be 1–128 permitted ASCII characters; the timestamp is Unix seconds within 300 seconds of the receiver's clock. `signature(secret, timestamp, event_id, raw_body)` produces the expected HMAC-SHA256 header. The signed bytes bind the timestamp, length-framed event ID and exact raw JSON body. Maximum body size is 1 MiB; chunked requests are unsupported. See [demo.py](demo.py) for a complete sender example.

## Process work

```python
from hookvault import Inbox

inbox = Inbox("inbox.sqlite3")
event = inbox.claim(lease_seconds=60)
if event is not None:
    # Perform an idempotent destination operation with event['payload'].
    inbox.settle(event["id"], event["token"])
```

On failure, call `settle(..., error="destination timeout", delay=30)` to schedule a retry. Expired/stale lease tokens cannot acknowledge a reclaimed event. Five failed attempts or expired leases lead to a `dead` state. The default listing omits payloads and worker tokens.

## Coverage and operating limits

Tests cover concurrent duplicate delivery, conflicting IDs, reopening storage, exclusive claims, lease expiry, stale tokens, retries, dead-letter transitions, metadata-only listing, signed HTTP delivery, signature tampering, delimiter ambiguity, timestamp bounds, invalid JSON/UTF-8/NaN, oversized requests, event IDs, content type, routes and secret length.

Provider-specific adapters and live customer integrations are not included. This signature protocol is not a Stripe, YooKassa or GitHub adapter. Public deployment needs TLS, a reverse proxy with connection limits, database file permissions, disk controls, backups and an agreed retention policy. SQLite contents are not encrypted. Automatic replay of dead events is not implemented.

Receiving deduplication does not guarantee exactly-once external side effects: a destination operation may succeed before a worker crashes without acknowledging it. Use destination idempotency or an appropriate transactional outbox. No live payment processing, public deployment, backup/restore test, independent audit or production load benchmark is claimed.

Source is available under the [MIT License](LICENSE). The integration offer is for separately agreed source/destination adapters and acceptance cases; publishing this demonstration does not establish a customer order or payment.

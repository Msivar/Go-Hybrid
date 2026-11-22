import concurrent.futures
import http.client
import json
import tempfile
import threading
import time
import unittest
from pathlib import Path

from hookvault import Inbox, make_server, signature

SECRET = "local-test-secret-" * 3


class StorageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "events.sqlite3"
        self.inbox = Inbox(self.path)

    def test_duplicate_delivery_is_atomic_under_contention(self):
        with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
            results = list(pool.map(lambda _: self.inbox.receive("payment-1", b'{"total":10}'), range(48)))
        self.assertEqual(results.count("created"), 1)
        self.assertEqual(results.count("duplicate"), 47)
        self.assertEqual(len(self.inbox.list_events()), 1)

    def test_conflicting_id_preserves_original_and_restart(self):
        self.inbox.receive("a", b'{"v":1}')
        self.assertEqual(self.inbox.receive("a", b'{"v":2}'), "conflict")
        restarted = Inbox(self.path)
        self.assertEqual(restarted.claim()["payload"], {"v": 1})

    def test_only_one_worker_can_claim_an_event(self):
        self.inbox.receive("a", b"{}")
        with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
            claims = list(pool.map(lambda _: self.inbox.claim(), range(24)))
        self.assertEqual(sum(c is not None for c in claims), 1)

    def test_expired_worker_cannot_ack_reclaimed_event(self):
        self.inbox.receive("a", b"{}")
        start = time.time() + 1
        first = self.inbox.claim(lease_seconds=1, now=start)
        second = self.inbox.claim(now=start + 2)
        self.assertNotEqual(first["token"], second["token"])
        self.assertFalse(self.inbox.settle("a", first["token"], now=start + 2))
        self.assertTrue(self.inbox.settle("a", second["token"], now=start + 2))
        self.assertEqual(self.inbox.list_events()[0]["status"], "done")

    def test_ack_at_expiry_is_rejected(self):
        self.inbox.receive("a", b"{}")
        start = time.time() + 1
        claimed = self.inbox.claim(lease_seconds=1, now=start)
        self.assertFalse(self.inbox.settle("a", claimed["token"], now=start + 1))

    def test_retry_delay_and_fifth_failure_dead_letter(self):
        self.inbox.receive("a", b"{}")
        start = time.time() + 1
        for attempt in range(1, 6):
            now = start + attempt * 10
            claimed = self.inbox.claim(now=now)
            self.assertEqual(claimed["attempt"], attempt)
            self.assertTrue(self.inbox.settle("a", claimed["token"], error="upstream unavailable", delay=5, now=now))
            self.assertIsNone(self.inbox.claim(now=now + 4))
        self.assertEqual(self.inbox.list_events()[0]["status"], "dead")

    def test_fifth_worker_crash_becomes_dead_letter(self):
        self.inbox.receive("a", b"{}")
        start = time.time() + 1
        for attempt in range(1, 6):
            self.assertEqual(self.inbox.claim(lease_seconds=1, now=start + attempt * 2)["attempt"], attempt)
        self.assertIsNone(self.inbox.claim(now=start + 12))
        self.assertEqual(self.inbox.list_events()[0]["status"], "dead")

    def test_payload_is_omitted_from_default_listing(self):
        self.inbox.receive("a", b'{"private":"example"}')
        self.assertNotIn("body", self.inbox.list_events()[0])
        self.assertIn("body", self.inbox.list_events(include_payload=True)[0])


class HTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.inbox = Inbox(Path(cls.temp.name) / "web.sqlite3")
        cls.server = make_server(cls.inbox, SECRET, port=0)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()
        cls.temp.cleanup()

    def request(self, body=b'{"hello":"world"}', event_id=None, timestamp=None, mutate=None, path="/hooks"):
        event_id = event_id or self.id().split(".")[-1]
        timestamp = str(int(time.time())) if timestamp is None else timestamp
        headers = {"Content-Type": "application/json", "X-Hook-Id": event_id,
                   "X-Hook-Timestamp": timestamp, "X-Hook-Signature": signature(SECRET, timestamp, event_id, body)}
        if mutate:
            mutate(headers)
        client = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=3)
        try:
            client.request("POST", path, body=body, headers=headers)
            response = client.getresponse()
            return response.status, json.loads(response.read())
        finally:
            client.close()

    def test_signed_delivery_and_duplicate(self):
        self.assertEqual(self.request(event_id="delivery")[0], 201)
        self.assertEqual(self.request(event_id="delivery")[0], 200)
        self.assertEqual(self.request(event_id="delivery", body=b'{"other":1}')[0], 409)

    def test_tampered_signature_is_rejected(self):
        self.assertEqual(self.request(mutate=lambda h: h.update({"X-Hook-Signature": "sha256=" + "0" * 64}))[0], 401)

    def test_ambiguous_delimiters_do_not_allow_event_id_tampering(self):
        ts = str(int(time.time()))
        self.assertNotEqual(signature(SECRET, ts, "a", b"1.2"), signature(SECRET, ts, "a.1", b"2"))
        bad = signature(SECRET, ts, "a", b"1.2")
        self.assertEqual(self.request(body=b"2", event_id="a.1", timestamp=ts,
                         mutate=lambda h: h.update({"X-Hook-Signature": bad}))[0], 401)

    def test_old_and_future_timestamps_are_rejected(self):
        for delta in (-301, 301):
            self.assertEqual(self.request(timestamp=str(int(time.time()) + delta))[0], 401)

    def test_invalid_json_utf8_and_nan_are_rejected(self):
        for body in (b"{", b"\xff", b'{"x":NaN}'):
            self.assertEqual(self.request(body=body)[0], 400)

    def test_oversized_body_is_rejected_before_reading(self):
        self.assertEqual(self.request(mutate=lambda h: h.update({"Content-Length": "1048577"}))[0], 413)

    def test_invalid_id_and_content_type(self):
        self.assertEqual(self.request(event_id="../bad")[0], 400)
        self.assertEqual(self.request(mutate=lambda h: h.update({"Content-Type": "text/plain"}))[0], 415)

    def test_unknown_route_is_rejected(self):
        self.assertEqual(self.request(path="/unrecognized")[0], 404)

    def test_short_secret_is_refused(self):
        with self.assertRaises(ValueError):
            make_server(self.inbox, "weak", port=0)


if __name__ == "__main__":
    unittest.main(verbosity=2)

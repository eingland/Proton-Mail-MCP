#!/usr/bin/env python3
"""
End-to-end tests: the real proton_mcp talking real IMAP over real STARTTLS to
a real (if minimal) IMAP server. This is what validates the parts the unit
tests can only assume - imaplib's actual response shapes, literal handling,
EXAMINE-vs-SELECT, and the TLS pinning path.

    python test_integration.py
"""

import importlib
import json
import os
import ssl
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))

from fake_bridge import FakeBridge  # noqa: E402

CERT_DIR = Path(tempfile.mkdtemp(prefix="fakebridge-"))
CERTFILE = CERT_DIR / "server.pem"
KEYFILE = CERT_DIR / "server.key"


def make_cert():
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(KEYFILE), "-out", str(CERTFILE),
            "-days", "2", "-subj", "/CN=127.0.0.1",
            "-addext", "subjectAltName=IP:127.0.0.1",
        ],
        check=True,
        capture_output=True,
    )


def load_proton(port, tls_policy="insecure", cert_path=None, user="user@example.com"):
    """Import proton_mcp fresh with the given environment."""
    os.environ["PROTON_BRIDGE_HOST"] = "127.0.0.1"
    os.environ["PROTON_BRIDGE_IMAP_PORT"] = str(port)
    os.environ["PROTON_BRIDGE_USER"] = user
    os.environ["PROTON_BRIDGE_PASS"] = "fake-bridge-password"
    os.environ["PROTON_TLS_POLICY"] = tls_policy
    if cert_path:
        os.environ["PROTON_CERT_PATH"] = str(cert_path)
    else:
        os.environ.pop("PROTON_CERT_PATH", None)
    sys.modules.pop("proton_mcp", None)
    return importlib.import_module("proton_mcp")


class LiveBridgeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        make_cert()
        cls.server = FakeBridge(str(CERTFILE), str(KEYFILE)).start()
        cls.P = load_proton(cls.server.port)

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()

    def setUp(self):
        self.P._conn = None  # force a fresh login per test


class TestLiveConnection(LiveBridgeTest):
    def test_starttls_and_login(self):
        conn = self.P._imap()
        self.assertTrue(self.P._alive(conn))

    def test_connection_is_encrypted(self):
        conn = self.P._imap()
        self.assertIsInstance(conn.sock, ssl.SSLSocket)

    def test_connection_is_reused(self):
        a = self.P._imap()
        b = self.P._imap()
        self.assertIs(a, b, "should not reconnect on every call")

    def test_reconnects_after_drop(self):
        a = self.P._imap()
        a.shutdown()
        b = self.P._imap()
        self.assertIsNot(a, b)
        self.assertTrue(self.P._alive(b))


class TestLiveListFolders(LiveBridgeTest):
    def test_all_folders_returned(self):
        names = [f["name"] for f in self.P.op_list_folders()]
        self.assertEqual(
            names,
            ["INBOX", "Drafts", "Sent", "Archive", "Folders", "Folders/Receipts"],
        )

    def test_special_use_flags_survive(self):
        drafts = [f for f in self.P.op_list_folders() if f["name"] == "Drafts"][0]
        self.assertIn("\\Drafts", drafts["flags"])


class TestLiveListRecent(LiveBridgeTest):
    def test_returns_all_messages(self):
        out = self.P.op_list_recent("INBOX", 25)
        self.assertEqual(len(out), 3)

    def test_newest_first(self):
        out = self.P.op_list_recent("INBOX", 25)
        self.assertEqual([m["uid"] for m in out], [103, 102, 101])

    def test_uids_parsed_from_real_fetch(self):
        """The bug that bit other Proton MCP servers: UID coming back None."""
        for m in self.P.op_list_recent("INBOX", 25):
            self.assertIsNotNone(m["uid"], "UID must be present in FETCH output")

    def test_flags_reflect_read_state(self):
        by_uid = {m["uid"]: m for m in self.P.op_list_recent("INBOX", 25)}
        self.assertFalse(by_uid[101]["unread"], "101 has \\Seen")
        self.assertTrue(by_uid[102]["unread"], "102 has no flags")

    def test_encoded_subject_decoded_over_the_wire(self):
        by_uid = {m["uid"]: m for m in self.P.op_list_recent("INBOX", 25)}
        self.assertEqual(by_uid[102]["subject"], "Your café booking")

    def test_limit_respected(self):
        self.assertEqual(len(self.P.op_list_recent("INBOX", 1)), 1)

    def test_uses_examine_not_select(self):
        self.server.commands.clear()
        self.P.op_list_recent("INBOX", 5)
        joined = b" ".join(self.server.commands).upper()
        self.assertIn(b"EXAMINE", joined, "read paths must not open the box writable")


class TestLiveSearch(LiveBridgeTest):
    def test_search_by_sender(self):
        out = self.P.op_search_messages(folder="INBOX", from_addr="alex@example.com")
        self.assertEqual([m["uid"] for m in out], [101])

    def test_search_unseen_only(self):
        out = self.P.op_search_messages(folder="INBOX", unseen_only=True)
        self.assertEqual([m["uid"] for m in out], [102])

    def test_date_criteria_reaches_server_in_imap_format(self):
        self.server.commands.clear()
        self.P.op_search_messages(folder="INBOX", since="2026-08-01")
        joined = b" ".join(self.server.commands)
        self.assertIn(b"01-Aug-2026", joined)
        self.assertNotIn(b"2026-08-01", joined)


class TestLiveFolderStats(LiveBridgeTest):
    def test_counts_returned_for_selectable_folders(self):
        stats = {s["folder"]: s for s in self.P.op_folder_stats()}
        self.assertIn("INBOX", stats)
        self.assertEqual(stats["INBOX"]["total"], 3)
        self.assertEqual(stats["INBOX"]["unread"], 1)

    def test_noselect_container_is_skipped(self):
        names = [s["folder"] for s in self.P.op_folder_stats()]
        self.assertNotIn("Folders", names)
        self.assertIn("Folders/Receipts", names)

    def test_busiest_first(self):
        unread = [s["unread"] for s in self.P.op_folder_stats()]
        self.assertEqual(unread, sorted(unread, reverse=True))


class TestLiveThread(LiveBridgeTest):
    def test_finds_the_reply(self):
        thread = self.P.op_get_thread(101, "INBOX")
        self.assertEqual([m["uid"] for m in thread], [101, 103])

    def test_works_from_either_end(self):
        """Starting at the reply must find the original too."""
        thread = self.P.op_get_thread(103, "INBOX")
        self.assertEqual([m["uid"] for m in thread], [101, 103])

    def test_oldest_first(self):
        thread = self.P.op_get_thread(101, "INBOX")
        self.assertEqual(thread[0]["subject"], "Lunch on Thursday")
        self.assertTrue(thread[-1]["subject"].startswith("Re:"))

    def test_results_carry_folder(self):
        for m in self.P.op_get_thread(101, "INBOX"):
            self.assertEqual(m["folder"], "INBOX")

    def test_unrelated_message_is_a_thread_of_one(self):
        self.assertEqual([m["uid"] for m in self.P.op_get_thread(102, "INBOX")], [102])

    def test_unknown_uid_raises(self):
        with self.assertRaises(RuntimeError):
            self.P.op_get_thread(9999, "INBOX")


class TestLiveSnippets(LiveBridgeTest):
    def test_returns_snippets_for_each_message(self):
        out = self.P.op_list_snippets("INBOX", 25)
        self.assertEqual(len(out["messages"]), 3)
        for m in out["messages"]:
            self.assertTrue(m["snippet"])

    def test_snippet_content_is_the_plain_text_body(self):
        by_uid = {m["uid"]: m for m in self.P.op_list_snippets("INBOX", 25)["messages"]}
        self.assertIn("Table booked for noon", by_uid[101]["snippet"])
        self.assertIn("Doors open at 8am", by_uid[102]["snippet"])
        self.assertNotIn("<b>", by_uid[102]["snippet"])

    def test_carries_the_untrusted_warning(self):
        self.assertIn("UNTRUSTED", self.P.op_list_snippets("INBOX", 25)["warning"])

    def test_does_not_mark_mail_read(self):
        self.server.commands.clear()
        self.P.op_list_snippets("INBOX", 25)
        joined = b" ".join(self.server.commands).upper()
        self.assertIn(b"EXAMINE", joined)
        self.assertIn(b"BODY.PEEK[]", joined)

    def test_truncates_to_requested_length(self):
        out = self.P.op_list_snippets("INBOX", 25, snippet_chars=60)
        for m in out["messages"]:
            self.assertLessEqual(len(m["snippet"]), 61)  # +1 for the ellipsis

    def test_snippet_chars_has_a_floor(self):
        """Below 50 the request is clamped up - a 5-char snippet is useless."""
        out = self.P.op_list_snippets("INBOX", 25, snippet_chars=5)
        longest = max(len(m["snippet"]) for m in out["messages"])
        self.assertGreater(longest, 5)
        self.assertLessEqual(longest, 51)


class TestLiveMultiFolderSearch(LiveBridgeTest):
    def test_searches_multiple_folders(self):
        out = self.P.op_search_messages(folders=["INBOX", "Archive"], unseen_only=True)
        self.assertEqual({m["folder"] for m in out}, {"INBOX", "Archive"})

    def test_every_result_names_its_folder(self):
        for m in self.P.op_search_messages(folders=["INBOX", "Archive"]):
            self.assertIn(m["folder"], ("INBOX", "Archive"))

    def test_merged_results_are_newest_first(self):
        out = self.P.op_search_messages(folders=["INBOX", "Archive"])
        keys = [self.P._date_sort_key(m) for m in out]
        self.assertEqual(keys, sorted(keys, reverse=True))

    def test_limit_caps_the_merged_total(self):
        out = self.P.op_search_messages(folders=["INBOX", "Archive"], limit=4)
        self.assertEqual(len(out), 4)


class TestLiveRead(LiveBridgeTest):
    def test_reads_plain_body(self):
        msg = self.P.op_read_message(101, "INBOX")
        self.assertIn("Table booked for noon. Does that work?", msg["body"])

    def test_headers_populated(self):
        msg = self.P.op_read_message(101, "INBOX")
        self.assertIn("alex@example.com", msg["from"])
        self.assertEqual(msg["subject"], "Lunch on Thursday")
        self.assertEqual(msg["message_id"], "<abc123@example.com>")

    def test_multipart_prefers_plain_text(self):
        msg = self.P.op_read_message(102, "INBOX")
        self.assertIn("Doors open at 8am", msg["body"])
        self.assertNotIn("<b>", msg["body"])

    def test_html_available_on_request(self):
        msg = self.P.op_read_message(102, "INBOX", include_html=True)
        self.assertIn("<b>8am</b>", msg["html"])

    def test_body_arrives_fenced(self):
        msg = self.P.op_read_message(101, "INBOX")
        self.assertTrue(msg["body"].startswith("<untrusted-email-content>"))
        self.assertTrue(msg["body"].endswith("</untrusted-email-content>"))

    def test_default_read_uses_peek_and_examine(self):
        self.server.commands.clear()
        self.P.op_read_message(101, "INBOX")
        joined = b" ".join(self.server.commands).upper()
        self.assertIn(b"EXAMINE", joined)
        self.assertIn(b"BODY.PEEK[]", joined)
        self.assertNotIn(b"RFC822", joined)

    def test_mark_seen_switches_to_select_and_rfc822(self):
        self.server.commands.clear()
        self.P.op_read_message(101, "INBOX", mark_seen=True)
        joined = b" ".join(self.server.commands).upper()
        self.assertIn(b"RFC822", joined)
        self.assertNotIn(b"EXAMINE", joined)

    def test_unknown_uid_raises_cleanly(self):
        with self.assertRaises(RuntimeError):
            self.P.op_read_message(9999, "INBOX")


class TestLiveDraft(LiveBridgeTest):
    def setUp(self):
        super().setUp()
        self.server.appended.clear()

    def test_append_reaches_drafts_with_flag(self):
        out = self.P.op_save_draft("friend@example.com", "Coffee?", "Thursday at the usual place?")
        self.assertTrue(out["saved"])
        self.assertEqual(len(self.server.appended), 1)
        args = self.server.appended[0]["args"]
        self.assertIn('"Drafts"', args)
        self.assertIn("\\Draft", args)

    def test_draft_body_round_trips(self):
        self.P.op_save_draft("friend@example.com", "Coffee?", "Thursday at the usual place?")
        body = self.server.appended[0]["body"]
        self.assertIn(b"To: friend@example.com", body)
        self.assertIn(b"Subject: Coffee?", body)
        self.assertIn(b"Thursday at the usual place?", body)
        self.assertIn(b"From: user@example.com", body)

    def test_reply_threads_against_original(self):
        self.P.op_save_draft("alex@example.com", "Re: Lunch on Thursday", "Noon works", reply_to_uid=101)
        body = self.server.appended[0]["body"]
        self.assertIn(b"In-Reply-To: <abc123@example.com>", body)
        self.assertIn(b"References: <abc123@example.com>", body)

    def test_unicode_body_survives(self):
        self.P.op_save_draft("f@x.com", "Café", "Naïve résumé — em dash")
        body = self.server.appended[0]["body"]
        decoded = body.decode("utf-8", "replace")
        self.assertTrue(
            "Café" in decoded or "Caf" in decoded, "subject encoding broke"
        )

    def test_nothing_is_ever_sent(self):
        """The whole point: a draft must not produce outbound traffic."""
        self.server.commands.clear()
        self.P.op_save_draft("f@x.com", "Subject", "Body")
        joined = b" ".join(self.server.commands).upper()
        for forbidden in (b"SEND", b"MAIL FROM", b"RCPT TO"):
            self.assertNotIn(forbidden, joined)


class TestTLSPinning(unittest.TestCase):
    """The pinned-cert path, which is the default in production."""

    @classmethod
    def setUpClass(cls):
        make_cert()
        cls.server = FakeBridge(str(CERTFILE), str(KEYFILE)).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()

    def test_learn_cert_captures_the_certificate(self):
        out = Path(tempfile.mkdtemp()) / "captured.pem"
        P = load_proton(self.server.port, tls_policy="insecure", cert_path=out)
        P.learn_cert()
        self.assertTrue(out.exists())
        pem = out.read_text()
        self.assertIn("BEGIN CERTIFICATE", pem)
        self.assertEqual(pem.strip(), CERTFILE.read_text().strip().split("-----BEGIN PRIVATE")[0].strip())

    def test_pinned_policy_connects_with_the_captured_cert(self):
        out = Path(tempfile.mkdtemp()) / "captured.pem"
        P = load_proton(self.server.port, tls_policy="insecure", cert_path=out)
        P.learn_cert()
        P = load_proton(self.server.port, tls_policy="pinned", cert_path=out)
        folders = P.op_list_folders()
        self.assertTrue(folders)

    def test_pinned_policy_refuses_to_start_without_a_cert(self):
        missing = Path(tempfile.mkdtemp()) / "nope.pem"
        P = load_proton(self.server.port, tls_policy="pinned", cert_path=missing)
        with self.assertRaises(RuntimeError) as ctx:
            P.op_list_folders()
        self.assertIn("learn-cert", str(ctx.exception))

    def test_pinned_policy_rejects_the_wrong_cert(self):
        """A different cert on the same port must fail closed."""
        other_dir = Path(tempfile.mkdtemp())
        other = other_dir / "other.pem"
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-keyout", str(other_dir / "k.key"), "-out", str(other),
                "-days", "2", "-subj", "/CN=127.0.0.1",
            ],
            check=True,
            capture_output=True,
        )
        P = load_proton(self.server.port, tls_policy="pinned", cert_path=other)
        with self.assertRaises(Exception) as ctx:
            P.op_list_folders()
        self.assertIn("CERTIFICATE_VERIFY_FAILED", str(ctx.exception).upper().replace(" ", "_"))


class TestFullStackOverMCP(unittest.TestCase):
    """Drive the finished server the way Claude Desktop will: stdio JSON-RPC."""

    @classmethod
    def setUpClass(cls):
        make_cert()
        cls.server = FakeBridge(str(CERTFILE), str(KEYFILE)).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()

    def rpc(self, *messages):
        env = dict(os.environ)
        env.update(
            {
                "PROTON_BRIDGE_HOST": "127.0.0.1",
                "PROTON_BRIDGE_IMAP_PORT": str(self.server.port),
                "PROTON_BRIDGE_USER": "user@example.com",
                "PROTON_BRIDGE_PASS": "fake-bridge-password",
                "PROTON_TLS_POLICY": "insecure",
            }
        )
        payload = "\n".join(json.dumps(m) for m in messages) + "\n"
        proc = subprocess.run(
            [sys.executable, str(HERE / "proton_mcp.py")],
            input=payload,
            capture_output=True,
            text=True,
            env=env,
            timeout=60,
        )
        return [json.loads(l) for l in proc.stdout.splitlines() if l.strip()], proc

    def call(self, name, args):
        init = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": "2024-11-05", "capabilities": {}},
        }
        out, proc = self.rpc(
            init,
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": name, "arguments": args},
            },
        )
        result = out[1]["result"]
        self.assertFalse(result["isError"], result["content"][0]["text"])
        return json.loads(result["content"][0]["text"]), proc

    def test_list_folders_over_mcp(self):
        data, _ = self.call("list_folders", {})
        self.assertIn("INBOX", [f["name"] for f in data])

    def test_list_recent_over_mcp(self):
        data, _ = self.call("list_recent", {"folder": "INBOX", "limit": 5})
        self.assertEqual(len(data), 3)
        self.assertEqual(data[0]["uid"], 103)

    def test_folder_stats_over_mcp(self):
        data, _ = self.call("get_folder_stats", {})
        self.assertIn("INBOX", [s["folder"] for s in data])

    def test_get_thread_over_mcp(self):
        data, _ = self.call("get_thread", {"uid": 101, "folder": "INBOX"})
        self.assertEqual([m["uid"] for m in data], [101, 103])

    def test_list_snippets_over_mcp(self):
        data, _ = self.call("list_snippets", {"folder": "INBOX", "limit": 5})
        self.assertIn("UNTRUSTED", data["warning"])
        self.assertEqual(len(data["messages"]), 3)

    def test_multi_folder_search_over_mcp(self):
        data, _ = self.call(
            "search_messages", {"folders": ["INBOX", "Archive"], "limit": 10}
        )
        self.assertEqual({m["folder"] for m in data}, {"INBOX", "Archive"})

    def test_read_message_over_mcp(self):
        data, _ = self.call("read_message", {"uid": 101, "folder": "INBOX"})
        self.assertIn("Table booked for noon", data["body"])
        self.assertIn("untrusted-email-content", data["body"])

    def test_search_over_mcp(self):
        data, _ = self.call(
            "search_messages", {"folder": "INBOX", "from_addr": "alex@example.com"}
        )
        self.assertEqual([m["uid"] for m in data], [101])

    def test_save_draft_over_mcp(self):
        self.server.appended.clear()
        data, _ = self.call(
            "save_draft",
            {"to": "f@x.com", "subject": "Hello", "body": "Body text here"},
        )
        self.assertTrue(data["saved"])
        self.assertEqual(data["folder"], "Drafts")
        self.assertEqual(len(self.server.appended), 1)

    def test_no_stderr_noise_on_happy_path(self):
        _, proc = self.call("list_folders", {})
        self.assertNotIn("Traceback", proc.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)

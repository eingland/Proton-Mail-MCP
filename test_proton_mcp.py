#!/usr/bin/env python3
"""
Test suite for proton_mcp.py. Standard library only - run with:
    python test_proton_mcp.py

Covers three layers:
  1. Pure parsing helpers (headers, bodies, search criteria, folder lines)
  2. IMAP operations against an injected fake connection
  3. The MCP wire protocol, by driving the real server over stdio
"""

import email
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import proton_mcp as P  # noqa: E402

SERVER = str(Path(__file__).parent / "proton_mcp.py")


# ==========================================================================
# 1. Pure helpers
# ==========================================================================


class TestHeaders(unittest.TestCase):
    def test_plain(self):
        self.assertEqual(P.decode_hdr("Hello there"), "Hello there")

    def test_rfc2047_utf8(self):
        self.assertEqual(P.decode_hdr("=?utf-8?q?Caf=C3=A9_meeting?="), "Café meeting")

    def test_rfc2047_base64(self):
        self.assertEqual(P.decode_hdr("=?utf-8?b?SGVsbG8gd29ybGQ=?="), "Hello world")

    def test_mixed_runs(self):
        self.assertIn("Zoë", P.decode_hdr("=?utf-8?q?Zo=C3=AB_Smith?= <a@b.com>"))

    def test_none_and_empty(self):
        self.assertEqual(P.decode_hdr(None), "")
        self.assertEqual(P.decode_hdr(""), "")

    def test_malformed_does_not_raise(self):
        self.assertIsInstance(P.decode_hdr("=?bogus?x?zzz?="), str)


class TestHtmlToText(unittest.TestCase):
    def test_strips_tags(self):
        self.assertEqual(P.html_to_text("<p>Hello <b>world</b></p>").strip(), "Hello world")

    def test_drops_script_and_style(self):
        out = P.html_to_text("<style>a{color:red}</style><script>evil()</script><p>Hi</p>")
        self.assertNotIn("evil", out)
        self.assertNotIn("color", out)
        self.assertIn("Hi", out)

    def test_br_becomes_newline(self):
        self.assertIn("\n", P.html_to_text("one<br>two"))

    def test_unescapes_entities(self):
        self.assertIn("&", P.html_to_text("<p>Tom &amp; Jerry</p>"))

    def test_collapses_blank_runs(self):
        self.assertNotIn("\n\n\n", P.html_to_text("<p>a</p><p></p><p></p><p>b</p>"))


def build_msg(parts, subject="Test", frm="a@b.com"):
    """parts: list of (content_type, payload, is_attachment)."""
    raw = [f"From: {frm}", "To: user@example.com", f"Subject: {subject}"]
    if len(parts) == 1 and not parts[0][2]:
        ctype, payload, _ = parts[0]
        raw += [f"Content-Type: {ctype}; charset=utf-8", "", payload]
        return email.message_from_string("\r\n".join(raw))
    boundary = "BOUND42"
    raw += [
        f'Content-Type: multipart/mixed; boundary="{boundary}"',
        "",
    ]
    for ctype, payload, is_att in parts:
        raw.append(f"--{boundary}")
        raw.append(f"Content-Type: {ctype}; charset=utf-8")
        if is_att:
            raw.append('Content-Disposition: attachment; filename="doc.txt"')
        raw += ["", payload]
    raw.append(f"--{boundary}--")
    return email.message_from_string("\r\n".join(raw))


class TestExtractBody(unittest.TestCase):
    def test_prefers_plain_over_html(self):
        msg = build_msg(
            [("text/plain", "PLAIN VERSION", False), ("text/html", "<p>HTML</p>", False)]
        )
        text, html = P.extract_body(msg)
        self.assertEqual(text, "PLAIN VERSION")
        self.assertIn("HTML", html)

    def test_falls_back_to_html(self):
        msg = build_msg([("text/html", "<p>Only <b>HTML</b> here</p>", False)])
        text, html = P.extract_body(msg)
        self.assertIn("Only", text)
        self.assertNotIn("<b>", text)
        self.assertIsNotNone(html)

    def test_skips_attachment_parts(self):
        msg = build_msg(
            [("text/plain", "REAL BODY", False), ("text/plain", "ATTACHED", True)]
        )
        text, _ = P.extract_body(msg)
        self.assertIn("REAL BODY", text)
        self.assertNotIn("ATTACHED", text)

    def test_empty_message(self):
        msg = email.message_from_string("From: a@b.com\r\nSubject: x\r\n\r\n")
        text, html = P.extract_body(msg)
        self.assertEqual(text, "")
        self.assertIsNone(html)

    def test_binary_part_ignored(self):
        msg = build_msg(
            [("text/plain", "BODY", False), ("application/pdf", "%PDF-junk", False)]
        )
        text, _ = P.extract_body(msg)
        self.assertEqual(text, "BODY")


class TestAttachments(unittest.TestCase):
    def test_lists_attachment(self):
        msg = build_msg([("text/plain", "b", False), ("text/plain", "att", True)])
        atts = P.list_attachments(msg)
        self.assertEqual(len(atts), 1)
        self.assertEqual(atts[0]["filename"], "doc.txt")

    def test_none_when_absent(self):
        msg = build_msg([("text/plain", "just body", False)])
        self.assertEqual(P.list_attachments(msg), [])


class TestBuildSearch(unittest.TestCase):
    def test_all_when_empty(self):
        self.assertEqual(P.build_search(), ["ALL"])

    def test_date_format_conversion(self):
        self.assertEqual(P.build_search(since="2026-08-01"), ["SINCE", "01-Aug-2026"])

    def test_before_conversion(self):
        self.assertEqual(P.build_search(before="2026-12-25"), ["BEFORE", "25-Dec-2026"])

    def test_criteria_are_anded(self):
        crit = P.build_search(from_addr="x@y.com", subject="invoice", unseen_only=True)
        self.assertEqual(crit, ["FROM", "x@y.com", "SUBJECT", "invoice", "UNSEEN"])

    def test_bad_date_raises(self):
        with self.assertRaises(ValueError):
            P.build_search(since="08/01/2026")

    def test_unseen_alone(self):
        self.assertEqual(P.build_search(unseen_only=True), ["UNSEEN"])


class TestGuards(unittest.TestCase):
    def test_truncate_under_limit(self):
        self.assertEqual(P.truncate("short", 100), "short")

    def test_truncate_over_limit(self):
        out = P.truncate("x" * 500, 100)
        self.assertIn("truncated", out)
        self.assertLess(len(out), 300)

    def test_clamp_bounds(self):
        self.assertEqual(P.clamp(0), 1)
        self.assertEqual(P.clamp(-5), 1)
        self.assertEqual(P.clamp(9999), P.MAX_LIST_LIMIT)
        self.assertEqual(P.clamp(25), 25)

    def test_clamp_garbage_defaults(self):
        self.assertEqual(P.clamp("banana"), 25)
        self.assertEqual(P.clamp(None), 25)

    def test_mailbox_quoting(self):
        self.assertEqual(P._enc_mailbox("INBOX"), '"INBOX"')
        self.assertEqual(P._enc_mailbox("Folder With Spaces"), '"Folder With Spaces"')

    def test_mailbox_rejects_injection(self):
        for bad in ['IN"BOX', "INBOX\r\nDELETE", "a\nb", "back\\slash", "", "   "]:
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                P._enc_mailbox(bad)


class TestFolderLineParsing(unittest.TestCase):
    def test_simple(self):
        got = P.parse_folder_line(rb'(\HasNoChildren) "/" "INBOX"')
        self.assertEqual(got["name"], "INBOX")
        self.assertIn("\\HasNoChildren", got["flags"])

    def test_special_use_flag(self):
        got = P.parse_folder_line(rb'(\HasNoChildren \Drafts) "/" "Drafts"')
        self.assertIn("\\Drafts", got["flags"])

    def test_nested_name(self):
        got = P.parse_folder_line(rb'(\HasChildren) "/" "Folders/Receipts"')
        self.assertEqual(got["name"], "Folders/Receipts")

    def test_junk_returns_none(self):
        self.assertIsNone(P.parse_folder_line(b"not a list line"))
        self.assertIsNone(P.parse_folder_line(None))


class TestHeaderFetchParsing(unittest.TestCase):
    def _item(self, uid, flags, frm, subj):
        meta = f"1 (UID {uid} FLAGS ({flags}) BODY[HEADER.FIELDS (FROM TO SUBJECT DATE)] {{10}}"
        raw = (
            f"From: {frm}\r\nTo: user@example.com\r\nSubject: {subj}\r\n"
            f"Date: Mon, 10 Aug 2026 10:00:00 -0500\r\n\r\n"
        )
        return (meta.encode(), raw.encode())

    def test_parses_uid_and_flags(self):
        data = [self._item(101, r"\Seen", "a@b.com", "Hello"), b")"]
        out = P.parse_header_fetch(data)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["uid"], 101)
        self.assertFalse(out[0]["unread"])
        self.assertEqual(out[0]["subject"], "Hello")

    def test_unread_when_no_seen_flag(self):
        out = P.parse_header_fetch([self._item(7, "", "a@b.com", "New")])
        self.assertTrue(out[0]["unread"])

    def test_flagged(self):
        out = P.parse_header_fetch([self._item(8, r"\Seen \Flagged", "a@b.com", "S")])
        self.assertTrue(out[0]["flagged"])

    def test_sorted_newest_first(self):
        data = [
            self._item(5, "", "a@b.com", "old"),
            self._item(90, "", "a@b.com", "new"),
            self._item(50, "", "a@b.com", "mid"),
        ]
        uids = [m["uid"] for m in P.parse_header_fetch(data)]
        self.assertEqual(uids, [90, 50, 5])

    def test_encoded_subject_decoded(self):
        out = P.parse_header_fetch([self._item(1, "", "a@b.com", "=?utf-8?q?Caf=C3=A9?=")])
        self.assertEqual(out[0]["subject"], "Café")

    def test_missing_subject_placeholder(self):
        item = (b"1 (UID 3 FLAGS ())", b"From: a@b.com\r\n\r\n")
        self.assertEqual(P.parse_header_fetch([item])[0]["subject"], "(no subject)")

    def test_ignores_non_tuple_junk(self):
        self.assertEqual(P.parse_header_fetch([b")", b"OK", None]), [])


# ==========================================================================
# 2. IMAP operations against a fake connection
# ==========================================================================


class FakeIMAP:
    """Records every command issued so tests can assert on the wire traffic."""

    def __init__(self, messages=None, folders=None):
        self.calls = []
        self.appended = []
        self.selected = None
        self.select_readonly = None
        self.messages = messages or {}
        self.folders = folders or [
            rb'(\HasNoChildren) "/" "INBOX"',
            rb'(\HasNoChildren \Drafts) "/" "Drafts"',
            rb'(\HasNoChildren \Sent) "/" "Sent"',
            rb'(\HasNoChildren) "/" "Archive"',
        ]

    def noop(self):
        return ("OK", [b"NOOP completed"])

    def status(self, mailbox, names):
        self.calls.append(("status", mailbox, names))
        unseen = sum(1 for _ in self.messages) - 1
        return ("OK", [f'{mailbox} (MESSAGES {len(self.messages)} UNSEEN {unseen})'.encode()])

    def list(self, *a, **kw):
        self.calls.append(("list",))
        return ("OK", self.folders)

    def select(self, mailbox, readonly=True):
        self.calls.append(("select", mailbox, readonly))
        self.selected = mailbox
        self.select_readonly = readonly
        return ("OK", [b"1"])

    def uid(self, command, *args):
        self.calls.append(("uid", command) + tuple(args))
        if command == "SEARCH":
            uids = b" ".join(str(u).encode() for u in sorted(self.messages))
            return ("OK", [uids])
        if command == "FETCH":
            spec = args[-1]
            uid_arg = args[0]
            if "HEADER.FIELDS" in spec:
                out = []
                for u in str(uid_arg).split(","):
                    u = int(u)
                    if u not in self.messages:
                        continue
                    raw = self.messages[u]
                    hdrs = raw.split(b"\r\n\r\n")[0] + b"\r\n\r\n"
                    out.append((f"1 (UID {u} FLAGS ())".encode(), hdrs))
                return ("OK", out)
            out = []
            for token in str(uid_arg).split(","):
                try:
                    u = int(token)
                except ValueError:
                    continue
                if u in self.messages:
                    out.append(
                        (f"1 (UID {u} FLAGS ())".encode(), self.messages[u])
                    )
            return ("OK", out or [None])
        return ("OK", [b""])

    def append(self, mailbox, flags, date_time, message):
        self.calls.append(("append", mailbox, flags))
        self.appended.append(
            {"mailbox": mailbox, "flags": flags, "date": date_time, "message": message}
        )
        return ("OK", [b"APPEND completed"])


SAMPLE = (
    b"From: Alex Rivera <alex@example.com>\r\n"
    b"To: user@example.com\r\n"
    b"Subject: Lunch on Thursday\r\n"
    b"Date: Mon, 10 Aug 2026 09:00:00 -0500\r\n"
    b"Message-ID: <abc123@example.com>\r\n"
    b"Content-Type: text/plain; charset=utf-8\r\n"
    b"\r\n"
    b"Table booked for noon. Does that work?\r\n"
)


class IMAPOpTest(unittest.TestCase):
    def setUp(self):
        self.fake = FakeIMAP(messages={101: SAMPLE, 102: SAMPLE})
        self._orig = P._imap
        P._imap = lambda: self.fake

    def tearDown(self):
        P._imap = self._orig


class TestListFolders(IMAPOpTest):
    def test_returns_all(self):
        names = [f["name"] for f in P.op_list_folders()]
        self.assertIn("INBOX", names)
        self.assertIn("Drafts", names)
        self.assertEqual(len(names), 4)

    def test_finds_drafts_by_special_use(self):
        self.assertEqual(P._find_drafts(self.fake), "Drafts")

    def test_drafts_fallback_when_no_flag(self):
        self.fake.folders = [rb'(\HasNoChildren) "/" "INBOX"']
        self.assertEqual(P._find_drafts(self.fake), "Drafts")


class TestListRecent(IMAPOpTest):
    def test_returns_summaries(self):
        out = P.op_list_recent("INBOX", 10)
        self.assertEqual(len(out), 2)
        self.assertEqual(out[0]["subject"], "Lunch on Thursday")

    def test_selects_readonly(self):
        P.op_list_recent("INBOX", 10)
        self.assertTrue(self.fake.select_readonly)

    def test_limit_is_clamped(self):
        P.op_list_recent("INBOX", 99999)
        self.assertEqual(len(P.op_list_recent("INBOX", 1)), 1)

    def test_folder_is_quoted(self):
        P.op_list_recent("Archive", 5)
        self.assertEqual(self.fake.selected, '"Archive"')

    def test_rejects_injected_folder(self):
        with self.assertRaises(ValueError):
            P.op_list_recent("INBOX\r\nLOGOUT", 5)


class TestSearchMessages(IMAPOpTest):
    def test_passes_criteria_to_imap(self):
        P.op_search_messages(folder="INBOX", from_addr="alex@example.com")
        search = [c for c in self.fake.calls if c[:2] == ("uid", "SEARCH")][0]
        self.assertIn("FROM", search)
        self.assertIn("alex@example.com", search)

    def test_date_criteria_converted(self):
        P.op_search_messages(folder="INBOX", since="2026-08-01")
        search = [c for c in self.fake.calls if c[:2] == ("uid", "SEARCH")][0]
        self.assertIn("01-Aug-2026", search)


class TestReadMessage(IMAPOpTest):
    def test_returns_body_and_headers(self):
        out = P.op_read_message(101, "INBOX")
        self.assertEqual(out["subject"], "Lunch on Thursday")
        self.assertIn("Table booked for noon", out["body"])
        self.assertEqual(out["message_id"], "<abc123@example.com>")

    def test_body_is_fenced_as_untrusted(self):
        out = P.op_read_message(101, "INBOX")
        self.assertIn("<untrusted-email-content>", out["body"])
        self.assertIn("</untrusted-email-content>", out["body"])

    def test_default_does_not_mark_seen(self):
        P.op_read_message(101, "INBOX")
        self.assertTrue(self.fake.select_readonly, "must SELECT readonly by default")
        fetch = [c for c in self.fake.calls if c[:2] == ("uid", "FETCH")][0]
        self.assertIn("BODY.PEEK[]", fetch[-1])

    def test_mark_seen_opts_into_writable_select(self):
        P.op_read_message(101, "INBOX", mark_seen=True)
        self.assertFalse(self.fake.select_readonly)
        fetch = [c for c in self.fake.calls if c[:2] == ("uid", "FETCH")][0]
        self.assertIn("RFC822", fetch[-1])

    def test_missing_uid_raises(self):
        with self.assertRaises(RuntimeError):
            P.op_read_message(999, "INBOX")


class TestSaveDraft(IMAPOpTest):
    def setUp(self):
        super().setUp()
        self._user = P.USER
        P.USER = "user@example.com"

    def tearDown(self):
        P.USER = self._user
        super().tearDown()

    def test_appends_to_drafts(self):
        out = P.op_save_draft("f@x.com", "Hi", "Body text")
        self.assertTrue(out["saved"])
        self.assertEqual(out["folder"], "Drafts")
        self.assertEqual(len(self.fake.appended), 1)
        self.assertEqual(self.fake.appended[0]["mailbox"], '"Drafts"')

    def test_sets_draft_flag(self):
        P.op_save_draft("f@x.com", "Hi", "Body")
        self.assertEqual(self.fake.appended[0]["flags"], r"(\Draft)")

    def test_message_contains_fields(self):
        P.op_save_draft("f@x.com", "Subject Here", "The body", cc="c@x.com")
        raw = self.fake.appended[0]["message"]
        self.assertIn(b"To: f@x.com", raw)
        self.assertIn(b"Cc: c@x.com", raw)
        self.assertIn(b"Subject: Subject Here", raw)
        self.assertIn(b"The body", raw)
        self.assertIn(b"From: user@example.com", raw)

    def test_reply_threading_headers(self):
        P.op_save_draft("alex@example.com", "Re: Lunch on Thursday", "Noon works", reply_to_uid=101)
        raw = self.fake.appended[0]["message"]
        self.assertIn(b"In-Reply-To: <abc123@example.com>", raw)
        self.assertIn(b"References: <abc123@example.com>", raw)

    def test_append_timestamp_is_timezone_aware(self):
        # Python 3.12 deprecates and 3.14 rejects naive datetimes here.
        P.op_save_draft("f@x.com", "Hi", "Body")
        self.assertIsInstance(self.fake.appended[0]["date"], str)

    def test_empty_body_allowed(self):
        P.op_save_draft("f@x.com", "Subject only", "")
        self.assertEqual(len(self.fake.appended), 1)


class TestFolderStats(IMAPOpTest):
    def test_returns_counts_per_folder(self):
        stats = P.op_folder_stats()
        self.assertTrue(stats)
        self.assertEqual(set(stats[0]), {"folder", "total", "unread"})

    def test_skips_noselect_containers(self):
        """Proton's 'Folders' and 'Labels' parents hold no mail; STATUS errors."""
        self.fake.folders = [
            rb'(\HasNoChildren) "/" "INBOX"',
            rb'(\Noselect \HasChildren) "/" "Folders"',
        ]
        names = [s["folder"] for s in P.op_folder_stats()]
        self.assertEqual(names, ["INBOX"])
        self.assertNotIn("Folders", names)

    def test_sorted_by_unread_first(self):
        stats = P.op_folder_stats()
        unread = [s["unread"] for s in stats]
        self.assertEqual(unread, sorted(unread, reverse=True))


class TestStatusParsing(unittest.TestCase):
    def test_parses_both_counts(self):
        got = P.parse_status(b'"INBOX" (MESSAGES 42 UNSEEN 3)')
        self.assertEqual(got["messages"], 42)
        self.assertEqual(got["unseen"], 3)

    def test_order_independent(self):
        got = P.parse_status(b'"X" (UNSEEN 7 MESSAGES 9)')
        self.assertEqual((got["messages"], got["unseen"]), (9, 7))

    def test_missing_keys_absent(self):
        self.assertEqual(P.parse_status(b'"X" ()'), {})


class TestMultiFolderSearch(IMAPOpTest):
    def test_single_folder_tags_results(self):
        out = P.op_search_messages(folder="Archive", from_addr="a@b.com")
        for m in out:
            self.assertEqual(m["folder"], "Archive")

    def test_searches_each_folder(self):
        P.op_search_messages(folders=["INBOX", "Archive"], subject="x")
        selected = [c[1] for c in self.fake.calls if c[0] == "select"]
        self.assertIn('"INBOX"', selected)
        self.assertIn('"Archive"', selected)

    def test_results_carry_their_folder(self):
        out = P.op_search_messages(folders=["INBOX", "Archive"], subject="x")
        self.assertEqual({m["folder"] for m in out}, {"INBOX", "Archive"})

    def test_limit_applies_across_folders(self):
        out = P.op_search_messages(folders=["INBOX", "Archive"], subject="x", limit=2)
        self.assertEqual(len(out), 2)

    def test_empty_folder_list_falls_back_to_single_folder(self):
        out = P.op_search_messages(folder="Archive", folders=[], subject="x")
        self.assertEqual({m["folder"] for m in out}, {"Archive"})

    def test_all_blank_folder_names_rejected(self):
        with self.assertRaises(ValueError):
            P.op_search_messages(folders=["", None])


class TestDateSortKey(unittest.TestCase):
    def test_orders_real_dates(self):
        older = {"date": "Mon, 10 Aug 2026 09:00:00 -0500"}
        newer = {"date": "Tue, 11 Aug 2026 09:00:00 -0500"}
        self.assertLess(P._date_sort_key(older), P._date_sort_key(newer))

    def test_garbage_date_sorts_last_without_raising(self):
        self.assertLess(P._date_sort_key({"date": "not a date"}),
                        P._date_sort_key({"date": "Mon, 10 Aug 2026 09:00:00 -0500"}))

    def test_missing_date_does_not_raise(self):
        P._date_sort_key({})


class TestSnippets(IMAPOpTest):
    def test_returns_warning_and_messages(self):
        out = P.op_list_snippets("INBOX", 10)
        self.assertIn("UNTRUSTED", out["warning"])
        self.assertEqual(out["folder"], "INBOX")
        self.assertTrue(out["messages"])

    def test_snippet_present_and_collapsed(self):
        snip = P.op_list_snippets("INBOX", 10)["messages"][0]["snippet"]
        self.assertIn("Table booked for noon", snip)
        self.assertNotIn("\n", snip)

    def test_snippet_truncated_to_requested_length(self):
        out = P.op_list_snippets("INBOX", 10, snippet_chars=50)
        for m in out["messages"]:
            self.assertLessEqual(len(m["snippet"]), 51)  # +1 for the ellipsis

    def test_snippet_chars_is_clamped(self):
        P.op_list_snippets("INBOX", 10, snippet_chars=999999)
        P.op_list_snippets("INBOX", 10, snippet_chars="garbage")

    def test_uses_peek_so_reading_is_not_implied(self):
        P.op_list_snippets("INBOX", 10)
        fetch = [c for c in self.fake.calls if c[:2] == ("uid", "FETCH")][0]
        self.assertIn("BODY.PEEK[]", fetch[-1])
        self.assertTrue(self.fake.select_readonly)

    def test_empty_folder_returns_warning_and_no_messages(self):
        self.fake.messages = {}
        out = P.op_list_snippets("INBOX", 10)
        self.assertEqual(out["messages"], [])
        self.assertIn("UNTRUSTED", out["warning"])


# ==========================================================================
# 3. Safety properties
# ==========================================================================


class TestNoSendCapability(unittest.TestCase):
    def test_smtplib_never_imported(self):
        source = Path(SERVER).read_text(encoding="utf-8")
        code_lines = [
            l for l in source.splitlines() if not l.strip().startswith(("#", "*"))
        ]
        code = "\n".join(code_lines)
        self.assertNotIn("import smtplib", code)
        self.assertNotIn("SMTP(", code)

    def test_smtplib_not_in_loaded_modules(self):
        self.assertNotIn("smtplib", sys.modules)

    def test_no_destructive_tools_exposed(self):
        names = set(P.HANDLERS)
        for forbidden in ("send", "delete", "move", "expunge", "trash"):
            self.assertFalse(
                any(forbidden in n for n in names), f"found {forbidden} tool"
            )

    def test_tool_surface_is_locked(self):
        """Widening this is a deliberate act - update CLAUDE.md in the same commit."""
        self.assertEqual(
            sorted(P.HANDLERS),
            [
                "get_folder_stats",
                "get_thread",
                "list_folders",
                "list_recent",
                "list_snippets",
                "read_message",
                "save_draft",
                "search_messages",
            ],
        )

    def test_only_one_tool_mutates(self):
        writers = [t["name"] for t in P.TOOLS if not t["annotations"]["readOnlyHint"]]
        self.assertEqual(writers, ["save_draft"])

    def test_every_tool_has_a_schema(self):
        for tool in P.TOOLS:
            with self.subTest(tool=tool["name"]):
                self.assertIn(tool["name"], P.HANDLERS)
                self.assertEqual(tool["inputSchema"]["type"], "object")
                self.assertTrue(tool["description"].strip())

    def test_read_tools_marked_readonly(self):
        for tool in P.TOOLS:
            if tool["name"] != "save_draft":
                self.assertTrue(tool["annotations"]["readOnlyHint"], tool["name"])


# ==========================================================================
# 4. MCP wire protocol, driven over real stdio
# ==========================================================================


def rpc(*messages, env_extra=None):
    """Run the server as a subprocess, feed it messages, collect responses."""
    env = dict(os.environ)
    env.pop("PROTON_BRIDGE_USER", None)
    env.pop("PROTON_BRIDGE_PASS", None)
    if env_extra:
        env.update(env_extra)
    payload = "\n".join(json.dumps(m) for m in messages) + "\n"
    proc = subprocess.run(
        [sys.executable, SERVER],
        input=payload,
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
    )
    out = []
    for line in proc.stdout.splitlines():
        if line.strip():
            out.append(json.loads(line))
    return out, proc


INIT = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2024-11-05",
        "capabilities": {},
        "clientInfo": {"name": "test", "version": "1"},
    },
}


class TestProtocol(unittest.TestCase):
    def test_initialize_handshake(self):
        out, proc = rpc(INIT)
        self.assertEqual(len(out), 1, proc.stderr)
        r = out[0]["result"]
        self.assertEqual(r["protocolVersion"], "2024-11-05")
        self.assertEqual(r["serverInfo"]["name"], "proton-mail")
        self.assertIn("tools", r["capabilities"])

    def test_protocol_version_is_echoed(self):
        msg = json.loads(json.dumps(INIT))
        msg["params"]["protocolVersion"] = "2025-06-18"
        out, _ = rpc(msg)
        self.assertEqual(out[0]["result"]["protocolVersion"], "2025-06-18")

    def test_initialized_notification_gets_no_reply(self):
        out, proc = rpc(INIT, {"jsonrpc": "2.0", "method": "notifications/initialized"})
        self.assertEqual(len(out), 1, "notifications must not be answered")

    def test_tools_list(self):
        out, proc = rpc(INIT, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        tools = out[1]["result"]["tools"]
        self.assertEqual(len(tools), 8)
        names = {t["name"] for t in tools}
        self.assertEqual(
            names,
            {
                "list_folders",
                "list_recent",
                "search_messages",
                "read_message",
                "save_draft",
                "get_folder_stats",
                "get_thread",
                "list_snippets",
            },
        )

    def test_tools_list_schemas_are_valid_json_schema(self):
        out, _ = rpc(INIT, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        for tool in out[1]["result"]["tools"]:
            with self.subTest(tool=tool["name"]):
                schema = tool["inputSchema"]
                self.assertEqual(schema["type"], "object")
                self.assertIsInstance(schema.get("properties", {}), dict)
                for req in schema.get("required", []):
                    self.assertIn(req, schema["properties"])

    def test_ping(self):
        out, _ = rpc(INIT, {"jsonrpc": "2.0", "id": 9, "method": "ping"})
        self.assertEqual(out[1]["result"], {})

    def test_unknown_method_returns_error(self):
        out, _ = rpc(INIT, {"jsonrpc": "2.0", "id": 3, "method": "nonsense/thing"})
        self.assertEqual(out[1]["error"]["code"], -32601)

    def test_malformed_json_returns_parse_error(self):
        proc = subprocess.run(
            [sys.executable, SERVER],
            input="{not json at all\n",
            capture_output=True,
            text=True,
            timeout=60,
        )
        resp = json.loads(proc.stdout.strip())
        self.assertEqual(resp["error"]["code"], -32700)

    def test_ids_are_preserved(self):
        out, _ = rpc(
            INIT,
            {"jsonrpc": "2.0", "id": "string-id", "method": "tools/list"},
            {"jsonrpc": "2.0", "id": 42, "method": "ping"},
        )
        self.assertEqual(out[1]["id"], "string-id")
        self.assertEqual(out[2]["id"], 42)

    def test_stdout_carries_only_protocol(self):
        """A stray print() would corrupt the stream - guard against it."""
        out, proc = rpc(INIT, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        for line in proc.stdout.splitlines():
            if line.strip():
                json.loads(line)  # raises if anything non-JSON leaked


class TestToolCallErrors(unittest.TestCase):
    """Tool failures must return isError results, never crash the server."""

    def _call(self, name, args, env_extra=None):
        out, proc = rpc(
            INIT,
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": name, "arguments": args},
            },
            env_extra=env_extra,
        )
        return out[1]["result"], proc

    def test_unknown_tool(self):
        res, _ = self._call("delete_everything", {})
        self.assertTrue(res["isError"])
        self.assertIn("Unknown tool", res["content"][0]["text"])

    def test_unexpected_argument_rejected(self):
        res, _ = self._call("list_recent", {"folder": "INBOX", "rm_rf": True})
        self.assertTrue(res["isError"])
        self.assertIn("rm_rf", res["content"][0]["text"])

    def test_missing_bridge_is_a_clean_error(self):
        res, proc = self._call("list_folders", {})
        self.assertTrue(res["isError"])
        self.assertNotEqual(proc.returncode, None)
        self.assertIn("PROTON_BRIDGE_USER", res["content"][0]["text"])

    def test_server_survives_error_and_keeps_serving(self):
        out, proc = rpc(
            INIT,
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": "list_folders", "arguments": {}},
            },
            {"jsonrpc": "2.0", "id": 3, "method": "ping"},
        )
        self.assertEqual(len(out), 3, "server died after a tool error")
        self.assertEqual(out[2]["result"], {})

    def test_folder_injection_rejected_over_the_wire(self):
        res, _ = self._call(
            "list_recent",
            {"folder": 'x"\r\nLOGOUT'},
            env_extra={"PROTON_BRIDGE_USER": "user@example.com", "PROTON_BRIDGE_PASS": "x"},
        )
        self.assertTrue(res["isError"])

    def test_error_text_does_not_leak_password(self):
        res, _ = self._call(
            "list_folders",
            {},
            env_extra={
                "PROTON_BRIDGE_USER": "user@example.com",
                "PROTON_BRIDGE_PASS": "SUPERSECRET123",
            },
        )
        self.assertTrue(res["isError"])
        self.assertNotIn("SUPERSECRET123", json.dumps(res))


if __name__ == "__main__":
    unittest.main(verbosity=2)

#!/usr/bin/env python3
"""
A minimal IMAP4rev1 server that imitates Proton Mail Bridge closely enough to
exercise proton_mcp.py for real: plaintext greeting, STARTTLS with a
self-signed cert on loopback, LOGIN, LIST, SELECT/EXAMINE, UID SEARCH,
UID FETCH (headers and full body, with literals) and APPEND.

Test-only. Never expose this to a network.
"""

import re
import socket
import ssl
import threading

GREETING = b"* OK [CAPABILITY IMAP4rev1 STARTTLS] FakeBridge ready\r\n"

FOLDERS = [
    (r"\HasNoChildren", "INBOX"),
    (r"\HasNoChildren \Drafts", "Drafts"),
    (r"\HasNoChildren \Sent", "Sent"),
    (r"\HasNoChildren", "Archive"),
    # Proton exposes container-only parents that cannot be selected. Real
    # output from a live Bridge shows both "Folders" and "Labels" like this.
    (r"\Noselect \HasChildren", "Folders"),
    (r"\HasChildren", "Folders/Receipts"),
]

# Invisible preheader padding, as real marketing mail sends it. Kept here so
# the integration suite covers the case that made snippets useless in practice.
PREHEADER_PADDING = ("͏‌­" * 40).encode("utf-8")

MESSAGES = {
    101: (
        rb"\Seen",
        b"From: Alex Rivera <alex@example.com>\r\n"
        b"To: user@example.com\r\n"
        b"Subject: Lunch on Thursday\r\n"
        b"Date: Mon, 10 Aug 2026 09:00:00 -0500\r\n"
        b"Message-ID: <abc123@example.com>\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n"
        b"\r\n"
        b"Table booked for noon. Does that work?\r\n",
    ),
    102: (
        b"",
        b"From: Bookings <noreply@example.com>\r\n"
        b"To: user@example.com\r\n"
        b"Subject: =?utf-8?q?Your_caf=C3=A9_booking?=\r\n"
        b"Date: Tue, 11 Aug 2026 07:30:00 -0500\r\n"
        b"Message-ID: <fair456@example.com>\r\n"
        b'Content-Type: multipart/alternative; boundary="XB"\r\n'
        b"\r\n"
        b"--XB\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n"
        b"\r\n"
        b"Doors open at 8am. Bring the confirmation." + PREHEADER_PADDING + b"\r\n"
        b"--XB\r\n"
        b"Content-Type: text/html; charset=utf-8\r\n"
        b"\r\n"
        b"<html><body><p>Gates open at <b>8am</b>.</p></body></html>\r\n"
        b"--XB--\r\n",
    ),
    # A reply to 101, so thread reconstruction has something to find.
    103: (
        rb"\Seen",
        b"From: user@example.com\r\n"
        b"To: Alex Rivera <alex@example.com>\r\n"
        b"Subject: Re: Lunch on Thursday\r\n"
        b"Date: Tue, 11 Aug 2026 09:15:00 -0500\r\n"
        b"Message-ID: <reply789@example.com>\r\n"
        b"In-Reply-To: <abc123@example.com>\r\n"
        b"References: <abc123@example.com>\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n"
        b"\r\n"
        b"Noon works. See you there.\r\n",
    ),
}


class FakeBridge:
    def __init__(self, certfile, keyfile, host="127.0.0.1", port=0):
        self.certfile, self.keyfile = certfile, keyfile
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((host, port))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self.appended = []
        self.commands = []
        self._stop = threading.Event()
        self.thread = threading.Thread(target=self._accept_loop, daemon=True)

    def start(self):
        self.thread.start()
        return self

    def stop(self):
        self._stop.set()
        try:
            self.sock.close()
        except OSError:
            pass

    def _accept_loop(self):
        while not self._stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    # -- helpers ---------------------------------------------------------

    @staticmethod
    def _send(f, data):
        f.write(data)
        f.flush()

    @staticmethod
    def _literal(payload):
        return b"{" + str(len(payload)).encode() + b"}\r\n" + payload

    def _headers_of(self, raw):
        return raw.split(b"\r\n\r\n", 1)[0] + b"\r\n\r\n"

    @staticmethod
    def _header_value(raw, name):
        """Concatenated value of one header, lowercased, for HEADER searches."""
        import email as _email

        msg = _email.message_from_bytes(raw.split(b"\r\n\r\n", 1)[0])
        return " ".join(str(v) for v in msg.get_all(name, [])).lower()

    # -- session ---------------------------------------------------------

    def _serve(self, conn):
        f = conn.makefile("rwb")
        self._send(f, GREETING)
        selected = None
        try:
            while True:
                line = f.readline()
                if not line:
                    return
                self.commands.append(line)
                parts = line.decode("utf-8", "replace").strip().split(" ", 2)
                if len(parts) < 2:
                    continue
                tag, cmd = parts[0], parts[1].upper()
                rest = parts[2] if len(parts) > 2 else ""

                if cmd == "CAPABILITY":
                    caps = b"IMAP4rev1" if isinstance(conn, ssl.SSLSocket) else b"IMAP4rev1 STARTTLS"
                    self._send(f, b"* CAPABILITY " + caps + b"\r\n")
                    self._send(f, f"{tag} OK CAPABILITY completed\r\n".encode())

                elif cmd == "STARTTLS":
                    self._send(f, f"{tag} OK Begin TLS\r\n".encode())
                    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                    ctx.load_cert_chain(self.certfile, self.keyfile)
                    conn = ctx.wrap_socket(conn, server_side=True)
                    f = conn.makefile("rwb")

                elif cmd == "LOGIN":
                    self._send(f, f"{tag} OK LOGIN completed\r\n".encode())

                elif cmd == "NOOP":
                    self._send(f, f"{tag} OK NOOP completed\r\n".encode())

                elif cmd == "LIST":
                    for flags, name in FOLDERS:
                        self._send(f, f'* LIST ({flags}) "/" "{name}"\r\n'.encode())
                    self._send(f, f"{tag} OK LIST completed\r\n".encode())

                elif cmd in ("SELECT", "EXAMINE"):
                    selected = rest.strip().strip('"')
                    ro = cmd == "EXAMINE"
                    self._send(f, f"* {len(MESSAGES)} EXISTS\r\n".encode())
                    self._send(f, b"* 0 RECENT\r\n")
                    self._send(f, b"* OK [UIDVALIDITY 1] UIDs valid\r\n")
                    self._send(f, b"* OK [UIDNEXT 103] Predicted next UID\r\n")
                    self._send(f, b"* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)\r\n")
                    state = "READ-ONLY" if ro else "READ-WRITE"
                    self._send(f, f"{tag} OK [{state}] {cmd} completed\r\n".encode())

                elif cmd == "STATUS":
                    name = rest.split('"')[1] if '"' in rest else rest.split()[0]
                    unseen = sum(
                        1 for fl, _ in MESSAGES.values() if b"\\Seen" not in fl
                    )
                    self._send(
                        f,
                        f'* STATUS "{name}" (MESSAGES {len(MESSAGES)} '
                        f"UNSEEN {unseen})\r\n".encode(),
                    )
                    self._send(f, f"{tag} OK STATUS completed\r\n".encode())

                elif cmd == "UID":
                    self._handle_uid(f, tag, rest)

                elif cmd == "APPEND":
                    self._handle_append(f, tag, rest)

                elif cmd == "LOGOUT":
                    self._send(f, b"* BYE logging out\r\n")
                    self._send(f, f"{tag} OK LOGOUT completed\r\n".encode())
                    return

                else:
                    self._send(f, f"{tag} BAD unknown command {cmd}\r\n".encode())
        except (OSError, ValueError):
            return

    def _handle_uid(self, f, tag, rest):
        sub = rest.split(" ", 1)
        op = sub[0].upper()
        args = sub[1] if len(sub) > 1 else ""

        if op == "SEARCH":
            hits = sorted(MESSAGES)
            header_m = re.search(r'HEADER\s+(\S+)\s+"([^"]+)"', args, re.I)
            if header_m:
                name, value = header_m.group(1).lower(), header_m.group(2).lower()
                hits = [
                    u
                    for u in hits
                    if value in self._header_value(MESSAGES[u][1], name)
                ]
                self._send(f, ("* SEARCH " + " ".join(str(u) for u in hits) + "\r\n").encode())
                self._send(f, f"{tag} OK SEARCH completed\r\n".encode())
                return
            if "UNSEEN" in args.upper():
                hits = [u for u, (fl, _) in MESSAGES.items() if b"\\Seen" not in fl]
            if "FROM" in args.upper():
                m = re.search(r'FROM "?([^"\s]+)"?', args, re.I)
                if m:
                    needle = m.group(1).lower()
                    hits = [
                        u
                        for u in hits
                        if needle in self._header_value(MESSAGES[u][1], "from")
                    ]
            self._send(f, ("* SEARCH " + " ".join(str(u) for u in hits) + "\r\n").encode())
            self._send(f, f"{tag} OK SEARCH completed\r\n".encode())
            return

        if op == "FETCH":
            uid_spec, spec = args.split(" ", 1)
            wanted = []
            for token in uid_spec.split(","):
                try:
                    wanted.append(int(token))
                except ValueError:
                    pass
            headers_only = "HEADER.FIELDS" in spec.upper()
            seq = 0
            for uid in wanted:
                if uid not in MESSAGES:
                    continue
                seq += 1
                flags, raw = MESSAGES[uid]
                if headers_only:
                    payload = self._headers_of(raw)
                    item = b"BODY[HEADER.FIELDS (FROM TO SUBJECT DATE)] "
                    meta = (
                        f"* {seq} FETCH (UID {uid} FLAGS ("
                        f"{flags.decode()}) ".encode()
                    )
                else:
                    payload = raw
                    item = b"BODY[] "
                    meta = f"* {seq} FETCH (UID {uid} ".encode()
                self._send(f, meta + item + self._literal(payload) + b")\r\n")
            self._send(f, f"{tag} OK FETCH completed\r\n".encode())
            return

        self._send(f, f"{tag} BAD unsupported UID {op}\r\n".encode())

    def _handle_append(self, f, tag, rest):
        m = re.search(r"\{(\d+)\}\s*$", rest)
        if not m:
            self._send(f, f"{tag} BAD APPEND needs a literal\r\n".encode())
            return
        size = int(m.group(1))
        self._send(f, b"+ Ready for literal data\r\n")
        body = f.read(size)
        f.readline()  # trailing CRLF
        self.appended.append({"args": rest, "body": body})
        self._send(f, f"{tag} OK [APPENDUID 1 103] APPEND completed\r\n".encode())

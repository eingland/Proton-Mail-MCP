# Proton Mail MCP — project instructions

A local MCP server exposing Proton Mail to Claude over Proton Mail Bridge's
loopback IMAP. Read and draft only. Windows-first. Python standard library only.

Public repo: `eingland/Proton-Mail-MCP`. Issues are disabled; this is shared
as-is, not maintained as a product.

## Hard invariants — do not break these

These are the design. Changing any of them means the project is no longer the
thing it was built to be. Several have tests enforcing them; if a test in
`TestNoSendCapability` fails, the fix is to revert the change, not the test.

1. **No send capability, ever.** `smtplib` must never be imported and no code
   path may transmit a message. Drafts are written with IMAP `APPEND` to the
   Drafts folder and the user sends them by hand. This is the central promise
   in the README and the reason the project exists in this shape.
2. **No destructive operations.** No delete, move, expunge, trash, or batch
   mutation. The only write is APPEND-to-Drafts, plus an opt-in `\Seen` flag.
3. **Tool surface stays at exactly five**: `list_folders`, `list_recent`,
   `search_messages`, `read_message`, `save_draft`. Adding tools widens the
   prompt-injection blast radius — that trade was made deliberately.
4. **Zero third-party runtime dependencies.** Standard library only. `keyring`
   is optional and lazily imported *inside* `_keyring()` — never hoist it to
   module scope, and never add a `requirements.txt`.
5. **Reads must not mark mail read by default.** `EXAMINE` + `BODY.PEEK`.
   `mark_seen=True` is the only path to a writable `SELECT`.
6. **Email bodies stay wrapped in the `<untrusted-email-content>` fence.**
   Inbound mail is attacker-controlled input aimed at a language model.
7. **Never commit secrets.** No `.pem`, no `credentials`, no `.env`, no real
   addresses. `.gitignore` covers these; don't weaken it.

## Test fixtures must stay generic

Use `example.com` and invented names. **Never put real people, places, events,
or handles into fixtures** — not the maintainer's, not anyone's.

This is not hypothetical: the original fixtures were built from real life and
included a pseudonymous handle the author keeps separate from this account.
They were scrubbed before the first commit, because scrubbing afterwards does
not clear git history. Don't reintroduce the problem.

## Commands

```powershell
python test_proton_mcp.py     # 84 tests — parsing, dispatch, MCP wire protocol
python test_integration.py    # 39 tests — real IMAP over real STARTTLS
python proton_mcp.py --test   # live check against the user's actual Bridge
```

Both suites must pass before any commit. `test_integration.py` needs `openssl`
on PATH to mint a throwaway certificate.

Developed and tested on Python 3.10. The README claims 3.8+; that is plausible
from the syntax used but has not actually been verified — don't tighten the
claim without testing, and keep new syntax conservative.

## Layout

| File | Role |
|---|---|
| `proton_mcp.py` | The entire server. Everything ships here |
| `test_proton_mcp.py` | Unit + protocol tests, fake IMAP object |
| `test_integration.py` | End-to-end against a live local IMAP server |
| `fake_bridge.py` | Minimal IMAP4rev1 server. **Test scaffolding only** — never imported at runtime |
| `README.md` | User-facing setup, config reference, troubleshooting |

`proton_mcp.py` runs top to bottom in these sections: configuration → credentials
→ TLS → IMAP connection → pure parsing helpers → IMAP operations (`op_*`) → MCP
surface (`TOOLS`, `HANDLERS`, `handle_request`, `serve`) → entry point.

## The MCP layer is hand-rolled

This does **not** use the official MCP SDK — it speaks newline-delimited
JSON-RPC 2.0 on stdin/stdout directly, so that the project has no dependencies
and the protocol layer is testable without network access.

Implemented methods: `initialize`, `notifications/initialized`, `ping`,
`tools/list`, `tools/call`. Unknown methods return `-32601`; malformed JSON
returns `-32700`. Notifications (no `id`) must never get a response.

Tool failures return `{"isError": true}` result payloads, **not** JSON-RPC
errors — the model needs to see and recover from them.

To add a tool: append to `TOOLS` (with a JSON Schema and annotations) and add
the handler to `HANDLERS`. `_ALLOWED_ARGS` derives from `TOOLS` automatically.
But re-read invariant 3 first.

**`stdout` is the protocol channel.** A stray `print()` corrupts the stream and
the server dies silently inside Claude Desktop. All diagnostics go to `stderr`.
`test_stdout_carries_only_protocol` guards this.

## Gotchas already solved — don't regress them

- `imaplib.Time2Internaldate()` needs a **timezone-aware** datetime. Python 3.12
  deprecates naive ones and 3.14 rejects them outright.
- `imaplib`'s `select(readonly=True)` issues `EXAMINE`, not `SELECT`. The
  integration tests assert on this.
- `UID` must appear explicitly in the FETCH data-item list or every result comes
  back with `uid: None`. This bug is present in other Proton MCP servers.
- Bridge's certificate is self-signed for loopback, so its CN won't match a
  hostname: verify the chain against the pinned cert with `check_hostname=False`
  and `verify_mode=CERT_REQUIRED`. Do not fall back to `CERT_NONE` by default.
- Folder names are validated by `_enc_mailbox()` before hitting the wire. Every
  new IMAP call must route mailbox names through it — otherwise a folder
  argument can smuggle in extra IMAP commands.

## Scope discipline

This is a personal tool published as-is, not a product. Do not add CI workflows,
status badges, packaging metadata, a changelog, or contribution scaffolding
unless explicitly asked. Keep the diff small and the surface narrow.

If a genuine gap appears — HTML-to-text quality, attachment extraction, thread
reconstruction — those are known omissions, listed in the README, and were
traded away on purpose. Raise the trade before implementing it.

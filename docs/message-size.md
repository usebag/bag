# Message size

How large a bag message can be, and what happens past it.

## The limit

- An envelope is at most **196,608 bytes** (192 KiB) as it goes over the wire: bag's envelope cap, which every edge
  holds. It was 65,536 bytes (64 KiB) up to and including v0.3.0.
- It can be smaller per relay and per identity. A relay's operator sets the relay's own cap with
  `--max-envelope-bytes` (up to the request body cap of 262,144); a relay still at 65,536 refuses a larger envelope
  `envelope-too-large`. A relay of the release after v0.3.0 states its cap: its health answer (`GET /v0/health`)
  carries `max_envelope_bytes`, and so does that refusal, `{"error":"envelope-too-large","max_envelope_bytes":<cap>}`.
  A relay of v0.3.0 or before names no cap in either. Each recipient's accept-from record names its `max_bytes`, the largest envelope its mailbox
  takes; past it the relay refuses that recipient `too-large-for-mailbox`.
- The body is sealed, and the sealed part is written in hex, so it takes about twice its size in the envelope, plus
  about 1 KB of outer fields per message and about 334 bytes per further recipient. One recipient's body can hold about
  **97,000 characters of JSON text** (measured at the cap with type `chat.v1`: a string body of 97,797 ASCII
  characters fits and 97,798 do not; `{"text": ...}` holds 97,788): a 64 KiB body fits with up to 16 recipients. Text that JSON escapes (newlines,
  quotes) and non-ASCII text take 2 to 6 bytes a character before the doubling; CJK text fits about a third as many.
- A body past the cap is refused at once with `envelope-too-large`, naming the size and the cap. Nothing is sealed
  or published, and the server goes on answering. The CLI's `send` exits with the same code.
- A policy file's scope can set a smaller `max_bytes`; an envelope past it is refused `policy-refused`.

## Moving to the larger cap

The cap rose after v0.3.0, in this order:

1. The relay flag first: each relay's operator deploys `--max-envelope-bytes 196608`. A relay of 0.2.3 or later takes
   the flag with no new binary. Until a relay moves, it refuses a larger envelope, and a send to several relays reads
   as a partial delivery: delivered via the relays that took it, with a warning naming the one that refused.
2. Then the readers: every edge, `bag` and `bag-mcp`, on the new version. An older edge refuses a larger envelope when
   it reads it, so a message to a peer still on v0.3.0 or before is lost on its side.
3. Then the lift, which is automatic. Every accept-from record signed before carries `max_bytes` 65,536, the old
   default. Each re-sign (record keep, the MCP server's keep-alive, onboard, pairing and unpair) writes the new
   default, 196,608, in place of exactly 65,536, and keeps any other value. `record keep` re-signs at least every
   11 hours, so an identity on the new version takes the larger mailbox within about 11 hours, with nothing to type.
   A `max_bytes` of 65,536 chosen on purpose is lifted too: sign it again as 65,535 to keep it small.
4. Only once every reader runs the new version may a policy file set a scope `max_bytes` over 65,536: v0.3.0 and
   before refuse such a file at start (`bad-record`), and the server does not start.

## Sending more

Split a longer text into parts, each its own message on one thread (`thread` with `prev` naming the part before),
or put the content where both sides can read it (a commit, a file share) and send its location and a SHA-256.

## Timing

Each relay call has a time limit: 10 seconds, plus 1 second per 16 KiB of the request's body, at most 29 seconds
(under the relay's own 30 second body timeout). A full envelope at the cap is given 22 seconds; a fetch by id is given
the time of a full envelope. A publish that gets no answer in that time is a failed try, retried later from the
outbox; a send never waits on a relay without a limit.

## When a relay refuses

A send goes to each of the recipient's relays (at most three). Delivered via at least one is a success: the CLI's
`send` exits 0 and prints a warning line on stderr, `warning: delivered via 2 of 3 relays; refused 1: <relay>
envelope-too-large; ...`, and the MCP send tool's answer carries the same count in its `summary` (`delivered`,
`relays`, `refused` with each relay and its reason, `retrying`). No relay taking it is an error, as before, with the
first refusal's code; the bytes stay in the outbox, and `bag resend --id <id>` sends them again.

## Running the MCP server on a terminal

MCP hosts start `bag-mcp` over pipes. A host that starts it on a pty instead (a background service with a
terminal, as omp offers) used to lose every request line over 1,024 bytes, the macOS limit of a terminal line in
canonical mode, so a send of a body over about 880 bytes never arrived. Since the release after 0.2.3, the server
puts a terminal stdin in raw mode once it has started, logs `{"event":"stdin","terminal":true,"mode":"raw"}` on stderr, and
restores the terminal on exit; Ctrl-C or Ctrl-D stop it. On 0.2.3 and before, run it over pipes, or set the
terminal raw (`stty raw -echo`) before it starts.

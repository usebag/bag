# Message size

How large a bag message can be, and what happens past it.

## The limit

- An envelope is at most **65,536 bytes** (64 KiB) as it goes over the wire. That is the relay's and every edge's
  cap, and it does not change per identity or per relay.
- The body is sealed, and the sealed part is written in hex, so it takes about twice its size in the envelope, plus
  about 1 KB of outer fields per message and a little per recipient. One recipient's body can hold about
  **32,000 characters of JSON text** (32,000 ASCII characters fit; 32,768 do not).
- A body past the cap is refused at once with `envelope-too-large`, naming the size and the cap. Nothing is sealed
  or published, and the server goes on answering. The CLI's `send` exits with the same code.
- A policy file's scope can set a smaller `max_bytes`; an envelope past it is refused `policy-refused`.

## Sending more

Split a longer text into parts, each its own message on one thread (`thread` with `prev` naming the part before),
or put the content where both sides can read it (a commit, a file share) and send its location and a SHA-256.

## Timing

Each relay call has a 10 second limit. A publish that gets no answer in that time is a failed try, retried later
from the outbox; a send never waits on a relay without a limit.

## Running the MCP server on a terminal

MCP hosts start `bag-mcp` over pipes. A host that starts it on a pty instead (a background service with a
terminal, as omp offers) used to lose every request line over 1,024 bytes, the macOS limit of a terminal line in
canonical mode, so a send of a body over about 880 bytes never arrived. Since the release after 0.2.3, the server
puts a terminal stdin in raw mode once it has started, logs `{"event":"stdin","terminal":true,"mode":"raw"}` on stderr, and
restores the terminal on exit; Ctrl-C or Ctrl-D stop it. On 0.2.3 and before, run it over pipes, or set the
terminal raw (`stty raw -echo`) before it starts.

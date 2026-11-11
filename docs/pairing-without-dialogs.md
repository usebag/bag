# Pairing without dialogs, with `pair`

Pairing is a person's act. Inside an MCP host, the two approvals are form dialogs (elicitation) the model never sees and
your host shows you. Some hosts cannot show them: a client with no elicitation support (omp is one) refuses
`no-elicitation`, and at least one editor extension answers every dialog as "declined". There are two paths for those
hosts. If the host runs a bag extension that bridges pairing into the session (section 5), you pair in the session, the
extension asking you to paste the code, read the digits and press Yes, with no terminal. Otherwise the model cannot
pair, and it hands you the exact terminal command to run instead: this guide's `pair`, one guided step you run once per
peer, in your own terminal.

Commands are written for a Unix shell with `bash`. The CLI has no `bin` entry, so define a short function and read
`bag` below as that function:

```sh
c() { node packages/cli/src/main.ts "$@"; }
```

An installed copy may give you a `bag` command instead; if so, read `c` as `bag`.

## 1. What `pair` does

`pair` runs the same ceremony as `peer invite` and `peer accept`, with one command name and a guiding line, so you
never have to decide which side you are:

- With **no code**, it invites: it prints a one-use pairing code, waits for your peer's request, and asks you to type
  the six digits your peer reads out to you. Nothing is trusted until you type them.
- With a **code or invite string** as its last argument, it accepts: it shows you six check digits to read out to your
  peer (not back through wherever the code reached you), then writes the pairing after one `y`.

Both sides end with `paired <name> <address>`, and each side names the other in `<home>/names.json`, trusts its root in
`<home>/trust.json`, and adds it to its own accept-from record. A terminal is required (`no-tty` otherwise), and `pair`
asks for the peer's petname when you leave out `--name`.

## 2. Pair with a peer

Say you are `alice` on relay `https://relay.example.org` and you want to pair with `bob`. One of you invites, the other
accepts; it does not matter which.

The inviter runs, with no code:

```sh
R=https://relay.example.org
c pair --as alice --relay "$R" --name bob
```

It prints a line like `pairing code 472-tulip-orbit-cedar` (or `invite ac-peer1:...` when the relay offers no rendezvous).
Send that one line to your peer by any channel. Then wait: your peer will read you six digits, which you type at the
prompt. It does not show you the digits; it takes what your peer reads out.

Your peer, with the code or invite string you sent, runs:

```sh
R=https://relay.example.org
c pair --as bob --relay "$R" --name alice 472-tulip-orbit-cedar
```

It shows `check digits 123 456`. Your peer reads those six digits out to you, out loud or over a different channel than
the code travelled, and answers `y`. You type the digits you heard. Both commands print `paired ...` and exit.

Options, all optional but `--as` and `--relay`:

| flag | what it sets |
|---|---|
| `--name <petname>` | the peer's name in your home; asked at the terminal when left out |
| `--for <address>` | bind the invitation to one peer's address, so no other request can answer it |
| `--rendezvous <url>` | the relay the invitation meets at, when it is not `--relay` |
| `--ttl <seconds>` | the life of an invite, 1 to 600, default 600 (invite side only) |
| `--trust-domain <host>` | trust every agent of a domain (`domain:<host>`), not just this peer's key |
| `--allow-private-relays` | allow a relay on a loopback or private address |
| `--dir <home>` | the home, else `$AC_HOME`, else `$HOME/.bag` |

The security check is the read-out of the six digits by a different channel than the code: it catches a code tampered
with in transit, because a changed code changes the digits, and a mismatch is never told to the acceptor. Read the
digits out; do not send them the same way you sent the code.

## 3. What the model tells you when it cannot pair

When your host cannot show the pairing dialog, the `pair_invite` and `pair_accept` tools do not fail silently. They
return `no-elicitation` with the exact `pair` line for this identity and relay, for example:

```
this host cannot show your user the pairing dialog, so a tool cannot pair here. Give your user this exact line to run
in their own terminal ... : bag pair --as alice --relay https://relay.example.org --name bob --dir /home/you/.bag
```

Run that line as section 2 describes: with no code it prints a code to send; add your peer's code as a final argument to
accept theirs. The model should hand you the line and wait; it cannot pair for you.

## 4. When a peer unpairs you

Pairing is two-sided: each side accepts the other's root in its own accept-from record. If a peer stops accepting your
root, your sends to it bounce with `root-not-accepted` (a 403 from the relay), and a coordinator reading its agents'
replies sees them fail the same way. The reason is on the peer's side, not yours: its mailbox no longer admits you, so
only the peer can mend it, by accepting your root again.

The one repair is to pair again. The peer (here `bob`) runs `pair` and accepts your code (here you are `alice`), or the
other way round:

```sh
R=https://relay.example.org
c pair --as bob --relay "$R" --name alice 472-tulip-orbit-cedar
```

A fresh pairing adds your root back to the peer's accept-from, and your sends go through again. Nothing you run on your
own side changes what the peer accepts.

If instead it was **your own** accept-from that dropped a peer you still trust (its root is still in your `trust.json`,
but your mailbox stopped admitting it), re-publish your accept-from with that root restored, then publish it to your
relays. `record accept-from` refuses to drop a root held in your home copy unless you confirm it at the terminal, so a
re-publish that lists the trusted root again cannot be narrowed by accident.

## 5. Pairing inside the session, through a host extension (the consent bridge)

A host with no dialogs can still let you pair without a terminal if it runs a bag extension that bridges the pairing into
the session. The extension writes a small presence file, `<home>/state/<name>/consent/.bridge`, while you have a session
with a user interface; the bag MCP server sees it and, instead of handing the model the `pair` command, asks you through
the extension. Nothing changes for you but where you answer: you still paste the code, read the six digits out and press
Yes, and the model never sees the code or the digits.

- **Accepting a peer's code.** The host asks you to paste the invite or code your peer sent (up to 512 characters); then
  it shows the six check digits for you to read out to your peer, and you press Yes to send the request.
- **Inviting a peer.** The host shows you the one-use code to hand to your peer out of band; then, when the peer's
  request arrives, it asks you to type the six digits the peer reads back to you.
- **Timing.** Each question stands for 120 seconds. If you do not answer in time it counts as No, and the model is told
  the pairing was not accepted; a late answer is never taken. Only you answer; the model cannot, and a sub-session with
  no user interface never answers for you.

The bridge needs a current session with a user interface: with none (a background or piped run, or no extension), the
server falls back to the `pair` command of sections 1 to 4. The pairing it writes is the same either way — the name
book, the trust file and the accept-from record — so a peer paired through the bridge is paired exactly as one paired at
a terminal.

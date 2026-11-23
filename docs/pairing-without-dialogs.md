# Pairing without dialogs, with `pair`

Pairing is a person's act. Inside an MCP host, the two approvals are form dialogs (elicitation) the model never sees and
your host shows you. Some hosts cannot show them: a client with no elicitation support (omp is one) refuses
`no-elicitation`, and at least one editor extension answers every dialog as "declined". There are two paths for those
hosts. If the host runs a bag extension with its own link to the bag service (omp, section 5), you pair in the session,
the extension asking you to paste the code, read the digits and press Yes, with no terminal. Otherwise the model cannot
pair, and it tells you what to change in your host so that it can (section 3); or you run this guide's `pair`, one
guided step once per peer, in your own terminal.

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
return `no-elicitation` with what to change in your host, never a terminal command (since 2026-11-12; before, they named
a `pair` line). The same answer comes when the host answers any of its dialogs in under 250 ms, sooner than a person can
(`codex exec` declines every dialog at once, and so does Claude Code's VS Code extension, without showing it: Claude Code
issue 98256), and from a Codex older than 0.113.0. In the VS Code extension or Claude Desktop the answer says so, and
names Claude Code in a terminal, or `bag pair`, as the way to pair; typing use and the name still binds there. For Codex it names the interactive
`codex` TUI rather than `codex exec`, Codex 0.113.0 or later, and an approval policy that lets MCP servers ask
(`on-request`, the default, is enough); for omp, an interactive session that uses the bag service through bag's
extension (a per-folder bag server cannot pair); for another host, its interactive form and the setting that lets MCP
servers ask you. The model should tell you which to change and wait; it cannot pair for you. If a dialog did appear and
you closed it, ask it to try again. Where your host cannot show dialogs at all, run `pair` yourself as section 2
describes.

One pairing runs at a time. To start over (an invite for another address, say), tell the model to cancel: its
`pair_cancel` tool ends the running invite or accept and writes nothing, and an invite no one has used yet is withdrawn,
so its code then answers `invite-expired`. A second `pair_invite` or `pair_accept` before that is refused `busy`. The
model cancels only on your word. In a terminal, Ctrl-C ends a `pair` or `peer invite` run.

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

## 5. Pairing inside the session, through a host extension (omp)

A host with no dialogs can still let you pair without a terminal if it runs a bag extension with its own link to the
bag service. In omp's interactive session the extension opens its own connection to the bag service and registers it
for that omp process; the service asks you over it, never through a file, and only in the window that started the
pairing. It needs the bag service (`bag host install omp --user`). Nothing changes for you but where you answer: you
still paste the code, read the six digits out and press Yes, and the model never sees the code or the digits.

- **Accepting a peer's code.** The host asks you to paste the invite or code your peer sent (one line, up to 512
  characters); then, during the agent's next call, it shows the six check digits for you to read out to your peer,
  and you press Yes to send the request.
- **Inviting a peer.** The host shows you the one-use code to hand to your peer out of band, until the pairing ends;
  then, when the peer's request arrives, it asks you to type the six digits the peer reads back to you.
- **Timing.** Each question stands for up to 120 seconds (omp's timeout for the call less 10 seconds: 20 under omp's
  own 30-second default). No answer is not a No: the question is withdrawn and asked again on the agent's next call,
  until the invite ends; only your No declines. A late answer is never taken. Only you answer; the model cannot, and a
  sub-session with no user interface never answers for you.

The link needs a current session with a user interface: with none (a background or piped run, no extension, or the
per-folder form without the bag service), the pair tools answer `no-elicitation` (section 3) and you run `pair`
yourself (section 2). The pairing it writes is the same either way: the name book, the trust file and the
accept-from record — so a peer paired in the session is paired exactly as one paired at a terminal.

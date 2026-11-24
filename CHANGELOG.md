# Changelog

What changed in each published cut of bag, newest first, written for someone who installs it. Each published
cut adds one dated entry at the top, written from the entries of the project's change log (one entry per change, kept in
the source repository) made since the cut before it.

## v0.4.6: 2026-11-24

The cut tagged v0.4.6, `@usebag/bag` 0.4.6.

- **`@usebag/bag` 0.4.6**, published from this cut (`npm view @usebag/bag@0.4.6 gitHead` names it).

Changes after v0.4.5.

- **bag's tools appear at once in Codex and opencode.** Hosts that open with the newer handshake, such as Codex and
  opencode, ask bag a first question before they start the session. bag answered it only once the session had started,
  so the host waited out its own timeout first: about 10 seconds in Codex and 5 in opencode, during which a message
  you sent found no bag tools. bag now answers that question at once, and its tools are there from the start.

- **An omp window no longer hangs when its session ends.** On macOS the bag extension watched its files with
  file-system watchers, and closing them at a session's end (quitting omp, or starting a new session) could freeze the
  window for several seconds on a busy machine. It now looks at the doorbell and the ring file once a second and opens
  no watcher, so a session ends at once. A new message starts its turn within about a second, as in Claude Code.

- **A window keeps its identity when the bag service restarts.** After an upgrade, a crash or a restart through the
  login agent, each open window acts as the identities you gave it before, with no `use` and no dialog; its next answer
  says once that bag restarted and which identity it still acts as. If an identity was removed (or removed and made
  again under the same name) or a `bag` command is using it, the window says so and waits for your `use`. A new
  window still needs your `use` or your Yes, and a window that closes ends its identities, as before. An identity in
  your Keychain asks for its Keychain access at the window's first act after the restart, not at the restart itself; an
  identity whose keys an agent holds asks one `y` for the service and one per window, each at that window's first act.
  This starts with the windows you open after installing this update: windows already open when you install it still
  run the old code and bind one last time.

- **An omp window no longer loses bag for good when the Mac is slow to answer.** When the system took too long to
  report on the omp window (as it can on a very busy Mac), bag could take the window for closed: until you restarted
  omp, `use` answered that the window was gone and no new mail woke it. bag now checks whether the window is still
  open, and keeps it while it is.

- **A pairing you cancel says it was cancelled.** When a pairing ended while one of its dialogs was open (you ran
  `pair_cancel`, or the invitation expired) and the host then answered that dialog at once, the call could answer
  `no-elicitation`, "this host did not show the dialog", and tell the model not to use the pair tools again. It now
  answers the pairing's own end, `cancelled` or `invite-expired`, and nothing is written.

- **In the VS Code extension and Claude Desktop, a dialog you never saw is no longer read as your No.** These hosts
  answer every dialog themselves without showing it. On a busy machine that answer could come later than bag's 250 ms
  check, and bag took it as your No: the identities tool with `full` answered "your user said No: the addresses stay
  short", a pairing dialog answered `declined`, and an Allow between two of your own identities was refused for 24
  hours. On these two hosts a decline or a cancel of any of bag's dialogs, the `use` dialog included, is now always
  `no-elicitation`, in the words that name the host, and nothing is written. A Yes is still a Yes. Every other host
  keeps the 250 ms check. If you used 0.4.4 or 0.4.5 on these hosts, such a No may have left two things. An Allow
  between two of your own identities may be refused for 24 hours, and the mail that waited on it was returned to its
  sender as declined: wait the 24 hours, after which the next message asks again, or ask again from a window that shows
  bag's questions (from this release, the VS Code extension and Claude Desktop do, in Claude Code's own question card).
  A pairing may have ended as declined: start it again.

- **In Claude Code's VS Code extension and in Claude Desktop, bag's questions now appear in Claude Code's own question
  card.** These two show no dialog for any MCP server (Claude Code issues 98256 and 105334), so bag's questions never
  reached you there. `bag host install claude-code --user` now also installs a small plugin of bag's, named bag, which
  draws each question ("Act as omp-3 in this window?", each pairing step, each act that changes your home) in that card;
  reload each window once after installing (a new session, or `/reload-plugins`). Every question starts with `bag: `,
  and its first choice grants nothing: a Yes-or-No question offers "Not now", then No, then bag's own Yes words; a
  choice of identity offers "Not now" first; a question where you type offers "Ask me later", then "Cancel". You pair in
  the window: you type your peer's code into the card, and the check digits into the inviting side's card. Claude Code
  in a terminal, Codex and opencode draw bag's questions themselves, as before; bag adds nothing there. The plugin's
  folder runs inside Claude Code at every session start and each bag update replaces it; `bag host install claude-code
  --user` and `bag status --home` list any other plugin or hook that could answer a question in your place, and `bag
  host remove claude-code --user` takes the plugin out. A question can be imitated: an imitation grants nothing, since
  only an answer that reaches bag's own check counts. See
  [`docs/bag-service.md`](docs/bag-service.md#bags-questions-in-claude-codes-question-card).

- **A question left unanswered closes.** A question left unanswered closes after two minutes (a pairing step, when its
  invitation ends) and can be asked again; an answer after that does nothing. It counts as unanswered toward the limit
  on questions (6 in 10 minutes in a window, 12 over all windows of a home), and so does "Act as omp-3 in this
  window?" left with no answer, the card closed or left two minutes: past the limit the agent cannot raise it again
  until the 10 minutes pass (in a new window it can), and in Claude Code and omp typing `use omp-3` yourself still
  binds at once.

- **Closing the check-digits question keeps the pairing waiting.** On the inviting side, the question where you type
  the six digits your peer reads out no longer ends the pairing when you close it, skip it, pick "Ask me later" or
  leave it until it closes: your peer's request is kept, and the agent's next call asks again, until the invitation
  ends. Only "Cancel" (declining the question) ends the pairing. Something that is not six digits, a word or an empty
  answer, is asked again and costs no try; only six wrong digits count toward the three tries.

- **A form you leave untouched is no longer read as your No.** On every host, a form sent back without its box ticked
  (an empty Yes) is no answer: nothing is written, granted or refused, and the question can come again. Only a No you
  give is one: declining the form, or No on the question card. "Not now", "Ask me later" and closing the card are no
  answer too, and a card that closes faster than a person could read it counts as never shown.

- **A No to "Act as omp-3 in this window?" holds for five minutes.** When you decline the bind dialog after reading
  it, or pick No on the card, the agent cannot ask for that identity in that window again for five minutes; in Claude
  Code and omp, typing `use omp-3` yourself still binds at once. A card you closed, "Not now", a form sent back
  without Yes and a choice of identity you left remember no No; they count only as unanswered.

- **The bag service opens your identities sooner after a restart.** Each identity's audit log was checked line by line
  at every start, so a start took longer with every day of use (minutes on a Mac with long logs). The service now
  remembers the part of each log it has checked and, at the next start, only confirms that part is unchanged and checks
  the lines added since; a log changed, cut short or replaced is still refused as before. The first start after this
  update checks every log in full one last time. A new install on macOS also runs the service at the normal priority
  of a program you use instead of the background priority. A Mac where bag is already installed keeps the background
  priority in this update, so on a busy Mac its first start after updating can take many minutes, once; meanwhile a
  window whose identity is not open yet is told it is still opening.

## v0.4.5: 2026-11-23

The cut tagged v0.4.5, `@usebag/bag` 0.4.5.

- **`@usebag/bag` 0.4.5**, published from this cut (`npm view @usebag/bag@0.4.5 gitHead` names it).

Changes after v0.4.4.

- **Sends between your own identities are no longer rate limited.** Before, one identity could make at most 20 local
  sends a minute and 200 a day, and the next was refused as `to-own-identity` with the detail "rate: at most 20 local
  sends a minute and 200 a day". Now no local send is refused for rate; sends through a relay keep their limits.

- **How omp 19 hands bag's tools to the model.** Under omp 19 (19.1.0) bag's tools reach the model as tool commands, run
  through omp's built-in bash tool, not as direct functions, so a window started with `--no-tools` has none of them;
  under omp 18 (18.20.0) they are direct functions and stay with `--no-tools`. Start a window that uses bag with omp's
  default tools, or at least its bash tool. See `docs/host-omp.md`, section 1.

- **The service stays under its login agent through a restart.** When the bag service stopped for a restart while a
  login agent was loaded, a window could start its own copy first; the login agent's copy then found the home taken,
  exited, and was started again every 10 seconds for as long as the window's copy lived. A window now asks the login
  agent to start the service and starts its own only if none answers within 20 seconds, and the login agent's copy that
  finds the home taken waits for it and takes over, instead of exiting.

## v0.4.4: 2026-11-23

The cut tagged v0.4.4, `@usebag/bag` 0.4.4.

- **`@usebag/bag` 0.4.4**, published from this cut (`npm view @usebag/bag@0.4.4 gitHead` names it).

Changes after v0.4.3.

- **bag works on omp 19.** omp 19 starts a window's tools under one shared process, so bag took that process for the
  window: every pairing and every `use` by dialog answered that the host showed no dialog, and a message could wake no
  window, or every omp 19 window whose folder names the identity, so one message could be acted on twice. bag now finds
  the window from the pid omp hands its tools, only when the tool's parent is that shared process, and keeps omp 18,
  Claude Code and Codex as they were.

- **A dialog the host answers at once is never your answer.** Any answer to one of bag's dialogs (binding a window,
  each pairing step, a question about a local act) that comes back faster than a person could read it, under 250 ms,
  means the host did not show it: bag writes nothing, records no No and grants nothing, and says the dialog was not
  shown. Before, only the first dialog of a pairing was checked, so the six-digit dialog declined at once by Claude Code's
  VS Code extension read as a No. In the VS Code extension and Claude Desktop, which answer every dialog without showing
  it (Claude Code issue 98256), the message says so and names the ways that work: Claude Code in a terminal, `bag pair`,
  or typing use and the name.

## v0.4.3: 2026-11-17

The cut tagged v0.4.3, `@usebag/bag` 0.4.3.

- **`@usebag/bag` 0.4.3**, published from this cut (`npm view @usebag/bag@0.4.3 gitHead` names it).

Changes after v0.4.2.

- **An identity can live here only, on this machine.** When you make an identity, your agent asks where it lives,
  published or here only, in one question: published first for your first identity, here only first for a second. Here
  only, or `bag keygen <name> --local`, makes it with no relays and publishes nothing: the window asks `Make sam on this
  machine only?`, and status shows `reach: this machine only`. It talks to your other identities on this machine from
  its first message, after the one Allow per pair. Anything that would reach a relay (a send to someone off the machine,
  a pairing code, a lookup, a login, `bag keys rotate`, `bag record keep <name>`, any command run `--as` it with a
  `--relay`) is refused with `no-relays` and the way on: your agent is told `<name> is on this machine only: give it
  relays with identity_relays, then send again`, and a command says `<name> is on this machine only: give it relays with
  bag identity relays <name> --relay <url>, then run this again`; `bag record keep --identities` skips it (`skipped
  <name>: on this machine only`). A local send to it whose key record and address record copy are both gone says `give
  <name> relays with identity_relays, which publishes it`, not `bag keys rotate`. `bag identity remove`, `bag unpair`
  and `bag host install` take it with no `--relay` (one given is refused), and the Codex worker line host install prints
  for it is refused until it has relays. Giving it relays, with `bag identity relays` or your agent's `identity_relays`
  after your Yes, publishes it; a relay sees its address for the first time then, and it is reachable there at once,
  with no restart of the bag service. An identity an agent holds, or one
  under a grant, cannot be made this way (`--custody agent --local` is a usage error); one kept in the Keychain can,
  with `bag keygen <name> --local --custody keychain`. Making one is refused (`busy`) while an older bag service still
  runs, until the update restarts it. bag 0.4.2 refuses an identities file that holds such an identity, so before going
  back to 0.4.2, give it relays or remove it. An identity that was published is never given no relays:
  remove it instead.

- **A relays change takes effect at once.** Giving relays to an identity that already has them, with `bag identity
  relays` or your agent's `identity_relays`, now reaches the running bag service: the identity reopens on its new
  relays, with no restart. Before, a published identity's new relays waited for the bag service to restart.

- **`bag host remove` refuses `--relay` and `--rendezvous`.** host remove writes no record and asks no relay, so
  either flag, given for any identity, is a usage error (`host remove takes no --relay`), never silently ignored.

- **`bag onboard` and `bag inbox --group` refuse an identity on this machine only.** onboard refuses one as the agent
  or as the org key, before anything is written, since both publish at the relays. `bag inbox --group` refuses one
  with `no-relays` before its key is read, so a Keychain identity raises no dialog for it.

- **Mail delivered on this machine from an unknown root is refused.** A message from your own identities on this
  machine is judged against this home's own roots only: one whose root is not among them is refused with
  `untrusted-root`, and is never looked up (no DNS or well-known fetch for mail that never left the machine). This
  holds for every identity, published or here only.

- **The install page is the agent's again.** You paste the install prompt into your agent, and the agent fetches bag
  with `npm pack` and checks its sha256 against the page itself, then checks the kept file again and runs
  `bag host install <host> --user` from it; on a mismatch it stops and runs nothing. Your part is to approve what your
  host asks, restart it when the agent says so, give it the install prompt again and create your identity with it.
  The agent also loads the login agent and checks the bag service itself, after your yes, and can check the
  package's npm signatures for you. You run a block yourself only when your host's sandbox refuses the agent's, on a
  machine that had bag before (where `host migrate` asks your own `y`), or to preview telemetry's report, which shows
  the machine's telemetry id.

- **The omp extension is checked against its own process (since 0.4.2, missing from its notes).** The bag service
  takes a registration as bag's omp extension only from the omp process at the other end of that connection (lsof on
  macOS, ss and /proc on Linux, time-limited); any doubt refuses it.

## v0.4.2: 2026-11-15

The cut tagged v0.4.2, `@usebag/bag` 0.4.2.

- **`@usebag/bag` 0.4.2**, published from this cut (`npm view @usebag/bag@0.4.2 gitHead` names it).

Changes after v0.4.1, for 0.4.2.

- **The install page is three lines.** bag.dev/install now hands your person two terminal lines and one sentence.
  Line 1 fetches `@usebag/bag` with `npm pack`, checks its sha256 against the page and keeps the file under a name
  that holds it. Line 2 checks that file again and, only on a match, runs `bag host install <host> --user` from it,
  for Claude Code, omp or Codex; on a mismatch it prints a STOP line and runs nothing. Line 3, said to the agent after
  the restart, has it set up the rest through bag's tools, each asking first: `identities`, `identity_create` (or a
  reused identity), `service` for the login agent, `host_wire` if wanted, and `telemetry` only on your word. Then you
  type `use` and the name. The page no longer writes a settings file or defines a `c` function. The tools make file
  keys; on a Mac, `bag keygen --custody keychain` in a terminal keeps them in the login Keychain instead.
- **The install page's terminal lines run the same in zsh as in bash.** The line that retires old keep jobs printed
  `no matches found` in zsh, the macOS default shell, when there were none; it now prints `keep jobs: none left`.
- **The install page checks that the bag service runs after the login agent loads.** After you run the line that
  loads the login agent, the page has you run one more check: it waits up to 15 seconds for the pid in
  `~/.bag/run/service.json` to be bag's own launcher, then checks that it runs the page's version and that the login
  agent is loaded. It prints one line, `bag service: running, bag <version>, started at every login`, or a STOP line
  naming what is wrong and its fix. It only reads and runs no bag code. The three-line page had dropped this check.
- **hono and @hono/node-server moved past seven moderate advisories, in the build's own install.** The source
  repository's lock now holds hono 4.13.16 and @hono/node-server 2.1.6 (pulled by @modelcontextprotocol/sdk), so
  `npm audit` is clean. The published `@usebag/bag` never contained either: its build bundles only the MCP SDK,
  zod and ajv with their helpers, so an install of bag was not exposed.
- **`bag local-delivery hide` and `show` take only your identities.** A name that is not an identity of the home is
  refused with `ENOENT`, naming the ones there are, and nothing is written; an identity named by its key name is hidden
  by its label in the bag service's `identities.json`, the name the service reads. Before, `hide` of any name wrote it
  to the hidden list. `show` of a name already on that list still takes it out, after the same y, so an old stray
  entry can be cleaned.
- **A re-added identity's old news is not told again.** An identity removed and added back while the bag service
  runs starts with no pairs; a window opened after that is no longer told the notices about it from before its
  removal (such as "lab allowed personal"), which named pairs that are gone. A change made after the re-add is told
  as before.
- **`bag identity remove` tells the senders of local mail waiting for it, and leaves the bag service's file.** Mail
  one of your identities sent to the removed one, held until your person allowed the pair, is now reported to its
  sender as not delivered ("identity removed", in its `status`), and the held copy is deleted. With the bag service
  running, the service does this as the command gives the identity back; with none, the command does it. The removed
  identity also leaves `identities.json`, which the remove used to leave behind, so the service kept serving an
  identity whose key was gone. This closes 0.4.1's known limit on `bag identity remove`. With no service running, a
  sender whose files another bag command is using makes the remove stop before its question, with nothing changed.
- **Codex: one wake per window.** Codex runs one server process for all of its TUI windows, and each window's bag
  shim now keeps its own binding file and ring file, named by the window's Codex session id
  (`<host pid>-<session id>.bound` and `.ring` under `<home>/run/shim/`). The Stop hook finds its window's files by
  the `session_id` of its input, so with two windows bound to two identities each window is woken for its own
  identity's mail only, and an unbind in one window leaves the other's binding alone. Claude Code and omp, one
  process per window, keep `<host pid>.bound` as before.
- **omp: pairing comes over the extension's own link.** omp's pairing questions (paste the code, the six check digits'
  Yes, type the peer's six digits) come over bag's omp extension's own connection to the bag service, as the local Allow
  did in 0.4.1; the file bridge of 0.3.0 to 0.4.1 (the `consent` folder, `.bridge`, request and answer files) is gone.
  One question per agent call: after you paste a code, the check digits' Yes opens during the agent's next call. The
  invite code shows above the editor until the pairing ends. No answer is not a No: the question opens again on the
  agent's next call, until the invite ends. Run `bag host install omp --user` again after the upgrade and restart omp:
  it also sets omp's own timeout for the bag server to 130 s (`"timeout": 130000` on `mcpServers.bag`), so a question
  can stand up to 120 s. The per-folder form (no bag service) cannot pair inside omp any more and answers
  `no-elicitation`: pair there with `bag pair` in a terminal. Old `<home>/state/<name>/consent/` folders are no longer
  used and are safe to move to the Trash. A typed question's own words (how many tries are left, the peer's address)
  now show above the editor while omp's text field is open; omp's field shows only its title.
- **omp: a long invite pastes whole from the wrapped widget.** The invite code above the editor now has a line of its
  own, with the peer's name cut to fit, so no name can push the code out of sight; under a code over 58 characters
  it says "it wraps on screen: copy it all, as one line". A code copied from omp's wrapped widget carries a line break
  at every wrap: the paste question now folds those to spaces before the code is checked, as the dialog of other
  hosts does, so such a paste pairs; the typed six digits and every other typed answer still refuse a line break.
  The paste question cuts the peer's name to 35 characters.
- **omp: the refusal says where pairing works.** In omp, a pair tool that cannot ask you now says that bag's pairing
  questions show only in an interactive omp session that runs bag's omp extension with the bag service, so neither
  the per-folder server nor an omp without the extension can pair. A print session (`omp -p`) binds no identity, so
  its pair tools answer `not-bound` before any question.
- **A pairing whose first call the host cancelled ends, instead of blocking the next one.** When your host gives up on
  the first `pair_accept` or `pair_invite` call (omp's own timeout, for example), the pairing that call started ends at
  once, as `pair_cancel` ends it: the open question or the invite code above the editor is withdrawn, an invite is
  withdrawn at the relay, nothing is written, and the audit says `cancelled` with `"reason":"client-abort"`. The
  agent's next call starts afresh. A pairing still running answers `busy`; in the window that started it, `busy`
  carries a fresh `resume`, so the agent goes on with it instead of cancelling it; for up to 30 seconds after a pairing
  ends there, while the relay side winds down, `busy` says the last pairing is still closing, and the next try starts. Each resume token serves one call:
  every answer that leaves the pairing running carries the next one, and a token is dead once its pairing ends.
  `pair_cancel` asks nothing and its text tells the agent to call it only when you ask. A window may start at most 6
  pairings in 10 minutes; the next start is refused `rate-limited` and starts nothing. The bag service's log names
  each omp question's cap and how it ended (`link-ask`, `link-end`), never its words or your answer.
- **The limits on questions hold across every window of a home.** A window may ask you about one act at most 3 times
  answered and 6 times unanswered in 10 minutes, and start at most 6 pairings; since a window that reconnects starts
  its own count again, all windows of one bag home together now stop at twice that (6 answered and 12 unanswered per
  act, and 12 pairing starts, in 10 minutes). Past it the refusal is `rate-limited` and says the cap was reached "by all
  windows of this bag home together". A question that is never sent, because too little of the agent's call is left,
  no longer counts as unanswered; at most 6 of those per window and act in 10 minutes, then `rate-limited`. omp: a
  question still open when its session ends no longer clears the words or the pending line of the next session's
  question.
- **The telemetry endpoint lists a version before it is released.** The maintainers deploy the endpoint by hand from
  their infrastructure repository, and the release chain's approval waits until the endpoint's public health check
  lists the version, so a report from a new version is never refused as an unknown build. The endpoint's source moved to that repository;
  `TELEMETRY_SCHEMA_COMMIT` names a commit there from the next version on (docs/release.md, step 1).
- **`bag telemetry on` asks you first.** It now runs only on a terminal and asks one question that says what is sent
  (once a day, to telemetry.bag.dev: the version, the OS and counts under a random id; never an address, a key, a
  message or a file path; the report holds no IP address and bag's server stores none, while Cloudflare's rate limiter
  sees it) and turns telemetry on only after your y. Without a terminal it refuses (`no-tty`) and changes nothing; a no
  changes nothing. `off`, `status`, `preview`, `send` and `forget` ask nothing.
- **The telemetry notice names a preview line that works for your install.** After a three-line install, which
  writes no settings file, the notice named `c telemetry preview`, a shell function such an install never defines.
  It now reads `$HOME/.bag/install`: when it holds exactly one package file of the running version
  (`usebag-bag-<version>-<16 hex>.tgz`), the notice names a line that checks the file's sha256 starts with those 16
  hex and then runs bag from it with `npx --yes --package=`, else prints STOP and runs nothing; with no such file and
  a settings file, it still names `c`; otherwise, including two files of one version, the preview line of the install
  page's step 7.
- **`bag telemetry forget` turns sending off before it asks for the erasure.** It now writes telemetry off first,
  keeping the install id in `telemetry.json`, then asks telemetry.bag.dev to erase every report sent under that id;
  only the endpoint's confirmation drops the id. When the erasure fails, sending stays off, the id is kept and the line
  says so ("sending is off; the erasure of <id> failed, so the id is kept: run forget again to retry, or send the id
  to privacy@bag.dev"). Before, a failed erasure changed nothing and left telemetry on. After a failed forget,
  `telemetry on` draws a fresh id, so the new choice is not linked to the reports you asked to erase; the old id stays
  pending beside it, through an on and a plain off, until a forget has its erasure confirmed. The `telemetry` tool's
  forget does the same.
- **Fixed: `bag onboard` keeps its keys in key files.** At a Mac terminal with a default keychain, the org key and the
  agent key that onboard makes were put in the macOS keychain; they are now key files, as intended for a job that
  runs from cron.
- **The help text matches the commands.** `bag help` now lists `identity keep-alive on|off|default <name>`, `host remove
  <host> --user`, `help` and `connect --verbose`; it says `--sandbox` is for claude-code only, which identity commands
  the bag service lends (relays, remove and custody), and that `publish` is refused as held whenever a bag service
  answers. `bag host migrate --undo` now says to stop the bag service before a session opens in those folders.
- **bag's own lines run bag from the package file you checked.** `bag help`'s `mcp` entry gives
  `claude mcp add bag -- npx -y --package=<that file> bag mcp`, the file whose sha256 the install page checked (`PKG`
  in `$HOME/.bag/install/<name>.env`), in place of a fetch of `@usebag/bag@<version>` from the registry by name; the
  telemetry notice names `c telemetry preview` from that package, and says how `c` comes to exist in a new shell.
- **Fix: after a stop, the old service ends within seconds of releasing its lock.** In 0.4.0 it could stay alive for up
  to half a minute while a send's request to a relay that did not answer was still open. Now the stop aborts every
  relay request still open after its 10-second wait for calls, while the stores are still open: the send stays in the
  outbox for the next service to retry, the window is told it is retrying (so do not send it again), its audit line
  says `"cause":"stop-abort"`, and the log says `relay-aborted` with `"at":"stop"`. If anything still holds
  the process 3 seconds after the lock is released, it exits anyway and logs `service-exit-hard` naming what was open.
- **Fix: an identity whose keys an agent holds keeps working in the bag service past its grant's end.** In 0.4.0 the
  service never renewed its grant, so the identity stopped receiving at the grant's end and a lost grant answered
  `not-authorized` until you bound the window again. Now the service renews it through the agent with no `y`, and each
  window's own grant renews while the window is bound. A grant that ends with the agent's login is used to its end.
  When a grant is revoked (a logout, say) or has ended, nothing is asked until a window acts: that act answers
  `grant-pending` with the agent's request code, and one `y` at the agent per grant (the identity's, and each window's
  own) grants a fresh key; the identity and its threads carry on. A `no` holds until you type `use` and the name again.
- **Fix: mail wakes the Codex window, not a sub-agent of it.** In 0.4.1 a Codex sub-agent that bound the window's
  identity and stayed alive took the speaking role, so mail rang the sub-agent and the window woke only after it ended.
  Now the bag service marks a sub-agent's connection at its first tool call, before that call runs, and never lets it
  speak: the window you type in is woken, and the sub-agent sees a quiet notice. The mark lasts the connection's life.
  It works with 0.4.1's bag shim too, which sends no mark of its own: the service reads Codex's own session and thread
  ids on the call.
- **Codex: a closed window's binding ends.** `bag host install codex --user` adds a SessionEnd hook to
  `~/.codex/hooks.json`. When a Codex session ends (its window closed or quit, or `/new`), Codex runs the hook, about a
  minute late, and the bag shim of that session ends its connection to the service, which releases the binding and
  any pairing that session started, then connects again unbound. A window that started `/new` keeps bag and binds
  again in its next dialog. The hook acts only on the files of the session that ended. Re-run your install step to
  add the hook (Codex asks you to trust it in `/hooks`).
- **`bag status --home` shows the whole home in one read.** The bag service, the local-delivery word, every identity
  with its custody (file, Keychain or agent), whether the service serves it, whether it is kept apart (hidden),
  whether a window has it bound and how much local mail waits for it, the local pairs, the bound windows and the
  relays; `--json` for the same as JSON. It reads no key and asks nothing.
- **`bag keygen` asks for `--new` before a second identity.** On a home that holds identities already, a name it
  does not hold is refused (`exists`, "this home holds identities already: use one of them, or pass --new for a new
  one") and nothing is written, so an agent that meant to reuse an identity does not make a new one by mistake; the
  first identity of a fresh home needs no `--new`. The bag service's own key files are not counted, so a home whose
  only file is a stale service key is a fresh home. `bag onboard` passes `--new` for the keys it makes.
- **`bag keygen --custody agent` lists the identity for the bag service.** As for a key file or Keychain identity, it
  now adds the agent identity to `<home>/identities.json` when a relay is known (the install settings' relays, or the
  list's first entry's), so the bag service serves it without a further step; with no relay known it writes nothing
  there, and `bag identity relays <name>`, with `--relay` once for each relay, run on a terminal, lists it.
- **`bag mcp` says what this machine holds.** The standalone MCP server, for a window that acts as no identity yet,
  gains an `identities` tool: it answers how many identities the home holds and leaves their names to the person,
  who picks one by typing `use` and its name in a window that runs the bag service. `status` now starts with bag's
  version, the identities' count and how many of the relays they name answer a health probe (never the relays'
  addresses; each answer reused for 60 seconds), then the enterprise session if there is one; no session is no
  longer an error there.
- **An update path for 0.4.x installs.** Part 2 of the update page checks the new package, points every identity's
  settings at it, restarts the bag service on it and rewires omp and Codex, with a checked way back.
- **Part 1's way back works after part 1 is done.** Part 1 of the update page now goes back from the install's own
  record, even after its last step has moved the page's note away: a package install from the `BEFORE_` lines in
  `$HOME/bag-install.env`, an install from a clone from its `.before-update` files, each read only as a file of yours
  alone (mode 0600), never a link, and the settings file searched for those lines before it is loaded. Before, the
  way back stopped and sent you to part 2 once bag's copy was in `$HOME/.bag/package`. With neither record, it stops
  with "nothing to go back to" and changes nothing.
- **The update page's steps for earlier installs stop on a 0.4.x install.** Part 1 of the update page, for installs
  made before 0.4.0 (`$HOME/bag-install.env`), now stops at every one of its blocks when a 0.4.x settings file
  exists in `$HOME/.bag/install/`, before any other command, and sends you to part 2; before, its per-folder steps
  could run against a 0.4.x install.
- **The update page updates an install made by the three-line page.** Such an install keeps no settings file in
  `$HOME/.bag/install/`, only its checked package file, and part 2 of the update page stopped on it with "no bag
  install here". Part 2 now finds it by that package file, which it checks before any `npx`, and by the bag service's
  `identities.json`, and updates it with the same checked way back.
- **Part 1 of the update page knows a three-line install, and runs again after a stop.** Part 1 now also stops and
  sends you to part 2 on a three-line install (its package file, `package/current` or `identities.json`), and keeps a
  note while it runs, so a run stopped after its host install step picks up on a rerun instead of stopping as if the
  install were already 0.4.x; the note goes to the Trash at its last step.
- **The install page runs bag only from the package file it checked.** Step 2a fetches the package as one file with
  `npm pack` into `$HOME/.bag/install`, compares its sha256 with the page's pin (with npm's `dist.integrity` printed
  beside it), and on a match points the settings' `PKG` at that file, kept under a name holding the first 16 hex of
  its sha256, so the bytes bag runs from are the bytes checked; a mismatch stops with the settings as they were. A
  copied package file (2b) is checked as a copy in the install folder. The page never installs bag globally, and the
  enterprise console's lines, the partner install page and the update page's step 3a run bag from the checked file
  too.
- **A session does not answer again what your plain server or `bag inbox` already took.** A root message that a
  plain (non-session) bag server, the CLI or a 0.1 server accepted for your identity stays in that identity's own
  store and was never in the sessions' answered list, so the first session to take the front desk could answer it a
  second time when the relay handed it over again. Each time a session takes the desk, it now adds the unexpired
  roots that store accepted to the list, reading the store without writing it. A root such a server saw and chose
  not to answer is not answered by a session either.
- **`sign_out` beside `sign_in`, in a window.** The agent can sign this machine out of an organisation, as
  `bag sign-out --org <domain>` does, when you ask it to, and only after you answer Yes in the window: the
  organisation revokes the agent's key for good. The standalone `bag mcp` has no dialog, so it offers no `sign_out`.
- **The login agent from a window.** In a window bound to no identity, `service` writes the bag service's login agent
  (launchd on macOS, the systemd user unit on Linux) after you answer Yes to a question that says it starts bag at
  every login; it gives you the one line to load it, and loads nothing itself.
- **Propose a folder's identity from a window.** In a window bound to no identity, `host_wire` proposes one identity
  for that window's own folder: every new window opened there has it preset in its bind dialog, and acts as it only
  after your Yes or your typed `use` and the name. You are asked in the window, which says that every new window in the
  folder will propose the identity, and you type its label there (or say Yes to the one identity that window just made).
  Nothing is written into the folder, so the bag service keeps holding the identity; the answer's last line says
  whether the service keeps its records at its relays or none are published yet (`bag onboard` publishes them). The
  agent cannot choose the identity or another folder. `host_wire` with `action: unwire` takes the proposal out again,
  and an earlier bag's own entries in the folder, after your Yes, leaving every other one. The bag service now reads
  the proposals `bag host migrate` writes, so a migrated folder's identity is preset as migrate says.
- **A first identity from a window, and telemetry from a window.** The bag service now starts on a machine with no
  identity yet; a window there can call only `status`, `use`, `identities`, `identity_create` and `telemetry`.
  `identity_create` makes a new identity with the label and relays you name, in a key file, after you answer Yes to a
  question in the window that shows the label and every relay whole, and publishes its first records to those relays
  (one line per relay; if none takes them, the identity stays and the answer names the relay's code); the service serves it at once, and it acts in no
  window until you bind one to it (`use`), nor is any host or folder wired for it. `telemetry` reads, turns on or turns
  off this machine's telemetry, as `bag telemetry` does: on asks you first, naming what is sent and where; off and
  status ask nothing; forget, also asking nothing, turns it off first and then erases the reports already sent, where
  off keeps them up to 90 days. No answer shows the agent the telemetry id. Both run in a window bound to no identity, and `telemetry` in every bound window too. `bag telemetry` prints what it printed before.
- **Each publish of an identity's address and accept-from records is in its audit log.** Every address record and
  accept-from that `bag onboard`, `bag init`, `bag restore`, `bag record keep` and the `identity_create` tool publish
  now writes one line per relay to the identity's `cli-audit.jsonl`: a `policy` line with `"step":"publish"`, the
  record, the relay and the outcome (`ok`; `unchanged` when the relay already holds that record; else the relay's
  code, as a reject).
- **The identity acts run in a window too.** In a window bound to an identity, the agent can now call
  `identity_remove` (of another identity, never the window's own), `identity_relays`, `keep_alive`, `local_delivery`
  (on, off, hide, show), `unpair` and `names` (add, list, forget).
  Each one that changes something asks you in the window first, with a short question that names the act and the
  identity, and the bag service holds the identity quiet only after your Yes, while the change is written, so its mail
  keeps arriving while the question is open. A window bound to no identity gets `identities`: each identity's label with a short
  address (`ed25519:` and its first 8 and last 4 hex); the full addresses only after you answer Yes, once, to "Show the
  full addresses of this machine's identities to this window?" in that window, for as long as it stays open. After
  that Yes, the agent in that window can read the full addresses and carry them out of bag.
- **Unpair and identity remove deal with mail still waiting for a local pair.** When a local pair is dropped (by
  `bag unpair` of an own identity paired locally, or by `bag identity remove`), mail one side sent that still waits in
  the other side's spool can never be delivered: it is now deleted and reported to its sender as not delivered
  ("unpaired", in its `status`), as the bag service already did for its own drop. A sender whose files another bag
  command is using stops the drop before anything is written.
- **A removed identity's mail is told to its senders even when the bag service stops first.** A remove the bag
  service took part in now leaves a record, `run/removed.json`, before it moves anything; the service fails the
  removed identity's held mail to its senders when it gets the identity back, or at its next start if it stopped
  before that, and with no service running the next `bag identity remove`, `bag identity relays` or
  `bag status --home` does it. An identity added back with the same key keeps its mail. `bag identity remove` beside a
  running service now also checks the service again after your y when the identity has held mail.
- **Mail failed for a removed identity names the identity it was for.** The not-delivered report could name the
  sender's own identity in place of the removed one when the removed one had asked for the pair first.
- **Stopping the bag service ends the pairings its windows run.** Before, a stop or upgrade ended no window's
  pairing itself: each ended only as its window closed. A command refused because a window is pairing now names that
  window, not the first window open.
- **`service.json` says what is running.** The bag service's `run/service.json` gains three counts, rewritten when one
  changes: `pairings` (the pairings running over every window and identity, one still winding down included), `lends`
  (the identities lent to a bag command or held quiet for a window's act) and `asking` (the questions to you open in
  any window), so an update can wait for them instead of cutting one; `started_at` now stays the time the service
  started, where a stop's last write moved it. Readers of the other keys are unaffected. A pairing a window started
  after a lend check had looked at it is now counted there and ends when its window closes; before, it ran
  uncounted and outlived its window.
- **The enterprise console's pairings remove tells the senders too.** When the console ends a link to another of your
  identities paired locally, mail that waited in a spool between the two was deleted with no word to anyone; each one
  is now reported to its sender as not delivered ("unpaired", in its `status`) before it is deleted, as `bag unpair`
  and the bag service do. One whose sender's files are in use stays in the spool.
- **`bag identity custody` asks before it reads the key.** The question now comes first, then the old copy is read
  (with its keychain dialog, for a keychain item), written, read back and compared. A No reads no key. For a key file,
  the question no longer names the address: it is read with the key, after the y.
- **A wake link whose target is gone is now removed.** `bag host install omp` and `bag host remove omp` reported such
  a link of bag's as removed but left it in place; it is now removed. A temporary wake link left by a stopped install
  is removed too.
- **`bag host migrate` writes nothing until your y, and stops if a file changes while you are asked.** It now stages
  the package only after your y, so a no leaves nothing under `<home>/package`. `bag host migrate` and `--undo`
  read again every file they planned against (and the keep jobs) after your y; when one changed while you were asked
  (a running Claude Code rewriting `~/.claude.json`, say), they refuse `busy`, naming what changed, and write nothing.
  Before, such an edit was overwritten.
- **The line `bag host install service` prints saves the login agent.** Since 0.4.1 its redirect into the agent's own
  file emptied that file before the command read it, and an empty file reads as another home's agent, so the file got
  that refusal in place of the plist (or the systemd unit). The line now saves the text outside the agents' folder
  and moves it in and loads it only when it holds a login agent's last line; anything else, a refusal included, stops the
  line with a STOP message and leaves the installed agent as it was.
- **Linux: the login agent starts on a fresh home.** In 0.4.1 the systemd user unit of step 6c did not start:
  systemd refused its quoted `WorkingDirectory=` line (`path is not absolute`), and the unit's stderr file
  `~/.bag/run/service.log` sat in a folder only the bag service made, so every start failed until systemd gave up.
  `WorkingDirectory=` is now a bare path, and `bag host install service` makes `~/.bag/run` (mode 0700) before it
  prints the agent, on macOS too. On Linux, run step 6c again after the upgrade.
- **The login agent takes a home path with a percent sign, and refuses one it cannot hold.** The Linux unit's
  `StandardError=` log path now doubles a `%`, as `WorkingDirectory=` does, so a home such as `~/my%bag` gets a working
  log file instead of one systemd reads as a specifier. A home path holding a line break is now refused for the Linux
  unit, and one holding any other control character for the macOS plist, before any text is printed; before, it wrote a
  unit or a plist that would not load.
- **A local send to an identity with no key record says how to fix it.** When the recipient identity of a local send
  has neither a key record nor an address record copy in the home, the refusal is still `resolve-failed`, and now
  names the fix as a command you can paste, with that identity's own relays: "run `bag keys rotate <name> --relay
  <relay>...` once for <label>, then send again".
- **`identities.json` is never read through a symbolic link.** The bag commands and the bag service now read
  `<home>/identities.json` only as a regular file at its own path. A link there is refused (the commands with
  `identities-invalid`, the service with `usage`), and the refusal says to replace the link with a 0600 copy of the
  file it points to. No bag command makes such a link.
- **`status` with a message id no longer fails on an odd audit line.** A line of the identity's audit log whose detail
  is not a JSON object is read as no detail, so `status(id)` answers instead of turning into a tool error.

- **The telemetry report counts every MCP tool by name.** The tools added in 0.4.2 and the enterprise tools were
  counted as `other`; the schema now names every tool the MCP server registers, and a test fails the build when a new
  tool is not named. A report can now be up to 4,352 bytes (from 4,096), so the longer names fit; reports from earlier
  versions are accepted as before.
- **A window's own grant renews while the window is bound, with no `y`, even when the window is idle.** It pauses while
  the identity is lent to the command line or held for an act, tries once when it comes back, and stops when the window
  unbinds or closes. Near the end of the agent's login a renewal waits for the agent's allowed time instead of being
  refused, and the last grant ends at or before the login's end, at most 5 minutes before it, never after it.
- **The agent's prompt for a new grant says who asks.** Above the grant it prints a note such as `note from the
  requester: "jane in omp asks for a new grant after the grant ended"`: the identity, the kind of window and the
  reason, written by the bag service, never by the window. The window's answer meanwhile says nothing was sent, and to
  send again once you answer `y`. The grant lines (renewed, asked, granted, refused) are in the identity's own audit
  log.
- **An old session key is revoked at the agent.** After a regrant the old key's address is kept in
  `<home>/run/revoke-intents.json` and sent to the agent at once; one the agent could not take is sent again at the next
  start or regrant, and an older agent's refusal keeps it until its grant ends. The file is read only as a 0600 file of
  yours in a 0700 `run/`, else a policy line says why.

Known limits:

- **A sub-agent shares its session's pairing**:
  in stdio mode a sub-agent uses its session's bag connection and can wait on or cancel that session's pairing; every answer stays yours.
- **A plain server does not read the sessions' answered list.** A plain (non-session) bag server, or a reply you
  send after `bag inbox`, may answer a root message that a session already answered, since the relay hands its
  unexpired messages over again, even when the plain server starts after the session ended; and both may answer one
  that arrives while a session holds the desk. The sessions see what such a server took only at the next time a
  session takes the desk. Use either sessions or a plain server for one identity, not both, even one after the other.
- **A grant the old key passed on lives to its own end.** The revoke ends the old key's own grants; a grant the agent
  signed for another key at the old key's request lasts until that grant's end, at most 8 hours. The bag service
  itself never asks for one.
- **An old window key is not revoked.** A window's old key lives only in the service's memory, gets no revoke at the
  agent, and lapses at its grant's end, at most 8 hours.
- **A restart asks again.** A service restart ends the identity's session at the agent, so the first bind
  after it asks a `y` again, as in 0.4.0.
- **Near an agent window's end a send can ask one `y` up to 5 minutes early.** A renewal waits for the agent's renewal
  pace (5 minutes), so the last grant can end up to one pace before the agent's login does, never after it; a later
  release, with the agent telling the service its login's end, removes the gap.
- **A sub-agent is marked at its first call.** A connection bound by the typed `use` hook is marked at its first
  call; Codex has no typed hook, so its sub-agents are marked at the bind.

## v0.4.1: 2026-11-13

The cut tagged v0.4.1, `@usebag/bag` 0.4.1.

- **`@usebag/bag` 0.4.1**, published from this cut (`npm view @usebag/bag@0.4.1 gitHead` names it).

Changes after v0.4.0, for 0.4.1.

- **Your identities on this machine can find and message each other (the bag service).** On by default. Every window's
  `status` lists the home's other identities, with their address and relays (`home.identities`). The first time one
  writes to another, bag asks you once, in the recipient's window that speaks for it: "<a> on this machine wants to
  message <b>. Allow both ways?". The message waits until you answer (at most 10 per pair); Yes delivers it and allows
  the pair both ways; No drops it and refuses that pair for 24 hours. From a window you can ask again sooner
  (`pair_invite` with `for` naming the other identity): your own window asks you first, at most once in 10 minutes and 3
  times in the 24 hours. A request no one answers ends after 7 days. Messages between your identities stay on this
  machine and never go to a relay; they are labelled "from your own identity <label> on this machine", read receipts
  between them follow the reader's own setting, and a sender may make at most 20 such sends a minute and 200 a day.
- **Keep an identity apart.** `bag local-delivery hide <name>` (no question) hides it: it sees none of the others, and
  none can reach it. `bag local-delivery show <name>` shows it again after a y on a terminal. In a window, `pair_invite`
  with `for` its own address asks you the same in a dialog (a show at most once in 10 minutes). `bag keygen` says when a
  new identity joins the home and how to hide it. `bag local-delivery off` stops it all at once; `on` asks your y.
- **omp.** The Allow and the hide or show come through bag's omp extension, over its own connection to the service,
  never a file a command could write. Run `bag host install omp` again after the upgrade and restart omp: a running omp
  keeps the extension it started with, and without the new one the window answers `no-elicitation` and says so.
- **Fixed: only your own No declines a pair.** An omp confirm that times out or is aborted no longer declines the pair:
  the request waits and is asked again later (an Esc in omp still counts as No, since omp's confirm cannot tell the
  two apart). Turning local delivery off, or hiding an identity, now stops its pending pairings at once: they are
  neither asked nor answered while it holds, and a Yes given meanwhile allows nothing. A first-touch request (and a
  re-ask) now wakes the recipient's window; before, the dialog waited for the person's next tool call there. In omp a
  pairing question now lasts 25 seconds, under omp's 30-second limit on the tool call that carries it, and is taken off
  the screen when that call ends: an answer after that (an Escape on a dialog you no longer see) changes nothing.

### Known limits of 0.4.1

- **Your identities share one person's trust.** With local delivery on (the default), a message from one of your
  identities reaches the other's agent as mail from your own identity, which it may act on. It is still data, never an
  instruction, but an agent misled in one window can reach the other's through it. Allow a pair only for identities
  meant to talk. To keep one apart, ask that identity's own agent to keep it apart and answer Yes to "Keep <name> apart
  from your other identities on this machine?"; on a terminal, `bag local-delivery hide <name>` does the same.
- **Your identities see each other.** With local delivery on, every window of a visible identity is shown the others'
  names, addresses and relays, and whether each is open now. Keep one apart (above) and it is neither shown nor shown
  the others.
- **The setting files are your user's files.** On Codex and omp a command an agent runs can write `~/.bag/run`. bag
  reads the word and the pair record only as your own 0600 regular files (a pair record that is not one, a symlink
  or a 0644 file, reads as no pairs, with a line in every identity's audit log and a notice in every window), writes a
  line in every identity's audit log and tells every window when either changes, asks again for any pair of your
  identities it did not write, whatever its state, and drops a pair naming no identity of this home.
- **After a restart, the pairs and the word are shown, not checked.** A change to either made while the service was
  stopped cannot be told apart from yours, so after each restart every window is shown its allowed pairs once, at its
  first result, and `status` shows the word (`local_delivery`, with `hidden` identities left out of `home`).
- **After a service restart or upgrade, each window binds again** (its dialog, or the typed word): a binding is your
  act and is never restored on its own.
- **No answer is not a No.** Only your own No declines a pair (and refuses it for 24 hours). A dialog closed without an
  answer, a timeout, or an omp window that closes leaves the request waiting: it is asked again at the recipient's next
  tool call or bind, and ends after 7 days with its held messages undelivered.
- **In omp, Esc on the pairing dialog counts as No;** a timeout or an abort does not.
- **Limits on local sends.** A sending identity can send at most 20 local messages a minute and 200 a day; past that
  the send is refused as `to-own-identity` with the detail "rate: at most 20 local sends a minute and 200 a day".
  Before a pair is allowed, at most 10 messages wait for the Allow, and later ones answer `local-pair-pending`. After
  your No, the pair cannot be asked again for 24 hours except from the sender's window, with your Yes there, at most 3
  times.
- **omp: the extension's own connection.** A program of yours that registers for an omp process before bag's extension
  loads would receive that window's dialogs: the same-user limit.
- **Read receipts between your identities** come only where the reader's own setting allows them.
- **When the home's first configured identity is an agent identity that has opened, later windows get no pairing
  tools.**
- **While a host window is open, its bag server starts the service again after a stop.** Close the windows (or unload
  the login agent) to keep it stopped.
- **`bag identity remove` of an identity with local mail waiting does not tell the senders;** that mail stays in the
  removed identity's folder (moved to bag-left-...) or in its recipient's held mail.
- **0.4.0's known limits still hold.** None of them is closed in this release so far: "Same user is not a
  boundary", "An identity whose keys an agent holds", "One login agent per user, for one home", "`<home>/run` is the
  service's own", "After a stop, the old service can outlive its lock", "One wake per Codex process" and "Claude Code
  asks before bag's tools".

## v0.4.0: 2026-11-12

The cut tagged v0.4.0, `@usebag/bag` 0.4.0.

- **`@usebag/bag` 0.4.0**, published from this cut (`npm view @usebag/bag@0.4.0 gitHead` names it).

Changes after v0.3.0, for the next cut.

- **Several windows on one identity, in the bag service.** One fetch and one acknowledgement per message, and a
  message read in one window is not returned again in another; only the window you last typed in is woken
  (`service/ring`), the others show a quiet notice; a crash never shows a window a message again; keeping an
  identity's records alive is your choice per identity (with no choice, as today: kept while a window is open and for
  24 hours after the last one closes), on a wall-clock deadline that survives sleep, with per-identity jitter; audit
  lines name the connection that acted, and `audit verify` reads old and new logs.
- **bag-shim, the one bag server every host session starts.** It speaks MCP on stdio to Claude Code, Codex or omp and
  forwards everything to the one bag service of your home; it holds no key, store or token. If the service is not
  running it starts it, and if it cannot, every tool says how (`bag service start`, or the login agent). A call that
  was running when the service restarted fails with a clear message and is never sent twice; dialogs reach the window
  that asked, with no 60-second limit; long calls on Codex answer with a resume token; typing `use <name>` binds the
  window.
- **The bag service on the host, from the command line.** `bag host install <claude-code|codex|omp> --user` wires
  the service's shim once per user for every identity of the home (with Claude Code's deny rules for `<home>/run`,
  `--sandbox` to turn its sandbox on); `bag host migrate` moves existing per-folder wiring to it after one y, backs up
  every file and keeps a journal, and `bag host migrate --undo <stamp>` puts it all back; `bag host install service`
  prints the login agent and the line that loads it; installs stage each version under `<home>/package/versions/`;
  beside a running service, every command that writes an identity borrows it
  from it instead of answering held; `bag identity relays <name> --relay <url>...` sets a service identity's relays;
  `bag identity keep-alive on|off|default <name>` is your word on keeping its records alive.
  The per-folder forms stay as the rollback.
- **The install page sets the bag service up from the same one line.** "Set me up on bag.dev" in Claude Code, Codex or
  omp, on a fresh machine or an existing home: on an existing home it reuses an identity unless you ask for a new one;
  you run `host migrate`, the shim at user scope and the login agent yourself, then type `use` and the name in each
  window. One identity per folder stays on the page as the way back. See `docs/bag-service.md`.

### The bag service: one process per home that holds every identity

- **`bag-mcp --service --dir <home>` runs one bag service for the home, on a socket instead of stdio.** It holds every
  identity listed in `<home>/identities.json` (or `--identities <file>`), all in that one home, and each window's
  shim connects to it on `<home>/run/service.sock` (0600, in a 0700 directory). A second service for the same home
  answers busy and exits. Windows that connect present the token the service writes at each start; dialogs a window
  opens are answered only in that window. The per-folder stdio server (`--as`, `--identities`) stays as it was, as the
  way back.
- **Restarts hand over cleanly.** A drain tells every window, refuses new binds and pairings with `draining`, ends
  running pairings (their codes and digits die), stops fetching, flushes and releases each identity, and lets go of
  the service lock last, so a new service never runs beside the old one. Keys are read again by the new process.
- **A Keychain identity asks for its dialog only when you use it.** The service opens such an identity at the first
  window that binds to it, never at an unattended start or restart, and never retries a denied or unanswered dialog on
  a timer.
- **The service runs scrubbed.** It refuses to start with `NODE_OPTIONS` set or a debugging or code-loading flag,
  runs with `--disable-sigusr1` and core dumps off, and the login-agent text the install step prints sets those, a
  fixed working directory and a short environment.
- **One window, one identity, in the service.** A window acts as the identity you bind it to (type `use NAME`, or
  answer the bind dialog); before that only `status` answers, saying how. `status` shows that identity only. An agent
  identity's windows each get their own grant under the same caveats. An identity you add with the command line is
  usable at once, without a restart; one you remove stays with the windows already using it until they close.
- **A Keychain dialog holds only its own identity.** While one identity waits on its dialog, every other window and
  identity keeps working; at an unattended start a Keychain identity opens only if you turned keep-alive on for it.
- **`bag-mcp --print-login-agent` prints the login agent.** The launchd plist on macOS, or with `--platform linux` a
  systemd user unit, on stdout only; it names the version-independent launcher, so removing old versions never breaks
  it.

### Known limits of 0.4.0

- **Same user is not a boundary.** A program running as you can still use any of your identities through the running
  bag service, since it can read the service's token. The Keychain stops it copying your keys, not using them; only
  your host's sandbox, where it denies ~/.bag/run, stops that.
- **An identity whose keys an agent holds** is reachable from a `login` until about 24 hours after that login began,
  when its address and key records lapse; the service keeps none of them alive, and running `login` again refreshes
  them. A send from such a window under an organisation's members record is refused `not-authorized`. A lost or
  revoked grant answers `not-authorized` until the window binds again or the service restarts; the refusal's detail
  says how to recover, and regranting in place comes in a later release.
- **One login agent per user, for one home.** A second home gets none: its service starts with its first window and
  stops 60 seconds after the last.
- **`<home>/run` is the service's own.** It makes the folder with mode 0700 and refuses an existing one that is
  group- or world-accessible (`unsafe-path`, for example 0755); it does not replace it. Run `chmod 700` on it, or move
  the folder to `~/.Trash` so the service makes a fresh one.
- **After a stop, the old service can outlive its lock for up to half a minute.** It releases the lock first, then stays
  alive while an in-flight send's HTTP request to a relay is open, up to the relay client's timeout (29 seconds in the
  proof run); a new service may start meanwhile, and nothing is fetched or acknowledged twice.
- **One wake per Codex process.** On Codex, all TUI windows of one Codex process share one bag connection host. The
  wake is per Codex process, not per window: with two windows bound to two identities, a window can be woken for the
  other's mail (its name and that mail arrived, never the message) or miss its own. Closing a Codex window does not
  end its binding or any pairing it started until Codex itself quits: unbind or cancel the pairing first, or quit
  Codex. Each window still reads and sends only as the identity it is bound to. For a dependable wake on Codex, bind
  one identity per Codex process.
- **Claude Code asks before bag's tools.** Claude Code may ask you to allow bag's tools (in auto mode its classifier
  can stop a call until you approve it); bag never pre-approves them.
- **Proof runs not yet done live:** the one-line install in Claude Code, Codex and omp on a fresh and on an existing
  home; the login agent's restart of a killed service; the Keychain dialog answered Allow; and, optional, a pairing in
  a Codex window closed before it ended. Recorded headless on main: mail with no window open, a crash and the shim's
  restart, an upgrade under load (drain with a wait and a send in flight), host migrate and its undo, and omp's seven
  legs. Recorded live: in Claude Code, two windows on two identities and two windows on one identity; in Codex, two
  windows on one identity, and two windows on two identities (its wake as above).

### Keys in the macOS Keychain

- **On macOS, `bag keygen` run at a terminal now keeps a new identity's keys in the login keychain, and `bag identity custody <name> --to
  keychain` moves an existing key file there.** A program running as you can no longer read your keys from a file;
  reading the keychain item shows a macOS dialog naming `security`, where you answer Allow (never Always Allow), and
  only right after you started bag yourself. Linux, and `--custody
  file`, keep the key file as before; the move verifies the keychain copy before it puts the old file in the Trash,
  and `--to file` moves back.

### identity remove: one identity out of a home that keeps others

- **`bag identity remove <name> --relay <url>...` takes one identity out of a home and leaves the others working.**
  From 0.4.3, an identity on this machine only is removed with no `--relay`, and a `--relay` given for one is refused.
  It runs on a terminal and asks one question that names every change; nothing is deleted. It re-signs the
  identity's accept-from to name only its own address at each relay, so peers' mail is refused from then on; a relay
  that does not take it stops the run before anything on the machine changes. It then takes out of `trust.json` only
  the roots no other identity's accept-from copy still names, forgets the names of its address in `names.json`, and
  prints the `unpair` line for each other identity that accepts it. With `--project <dir>` it takes its bag server out
  of `.omp/mcp.json` (and bag's wake link) or `.mcp.json` (and its wake hooks in `.claude/settings.json`), keeping
  every other server and hook. A Codex table naming it is left for you to edit, and the command says so. Its key file
  or keychain pointer, `state/<name>/`, its records, its key records and `install/<name>.env` move into `--to`
  (by default `bag-left-<name>-<UTC time>` beside the home, mode 0700). It refuses while an MCP server or a keep job
  holds the identity, and names the `launchctl bootout` line for the job.

### unpair in a home with several identities keeps the others' trust

- **Unpairing a peer for one identity no longer cuts it off from the others.** `trust.json` is one file for the whole
  home, and `unpair` took the peer out of it even when another identity of the same home still accepts it, so that
  identity's inbox and MCP server refused the peer's mail from then on. `unpair` now leaves the peer in `trust.json`
  while another identity's accept-from copy (`<home>/records/<name>.accept.json`) names it, says so (`kept trust <root>:
  the accept-from of <name> still names it`), and still re-signs its own accept-from without the peer. It also keeps
  its own copy current, so the next identity's `unpair` reads its roots as they are.

### Codex: a plain identity that can pair, and an honest answer when no dialog was shown

- **`host install codex --mode mcp` now registers a plain identity, as Claude Code's.** The server gets the same
  arguments as the Claude Code entry (`--as`, your relays, `--dir`, `--keep-alive-records`), so a Codex session can pair
  in its own dialogs. The first Codex session holds the identity; another answers that it is held. The earlier form, one
  grant session per Codex session under a principal, which had no pair tools, is now `--session auto:codex
  --grant-caveat <caveat>`; `--grant-caveat` alone is refused, naming `--session auto:codex`. A table of the other form
  is refused `exists`, never replaced: remove it first. Pairing needs the interactive `codex` TUI, 0.113.0 or later
  (`codex --version`), and an approval policy that lets MCP servers ask (`on-request`, the default). Codex asks before
  bag's tools that reach other agents: "Allow for this session" suits `pair_invite` and `pair_accept` only; keep `send`,
  `ask`, `handoff` and `delegate` at Allow per call. See `docs/partner-install.md`.
- **A pair tool no longer reports "declined" when nobody saw the dialog.** `codex exec` declines every dialog in under a
  millisecond, which bag reported as the person declining. A first pairing dialog answered in under 250 ms, or a Codex
  older than 0.113.0, now answers `no-elicitation`.
- **`no-elicitation` names what to change in your host, never a terminal command.** It named a `bag pair` line to run;
  it now names the host's own setting (for Codex: the interactive TUI, the version, the approval policy). `pair` stays
  available in your own terminal (`docs/pairing-without-dialogs.md`).
- **The install page wires Codex.** Its Codex step stopped with two lines for a grant session and a login terminal;
  it now runs the plain `host install codex --mode mcp` after a `codex --version` check, and ends with a restart.
- **The wake line no longer sends you to another session for a process that only reuses the server's pid.** It
  checks, as `status` does, that the pid in the server's lock started before the lock was written.

### host install: a stable node path, and no copy under a running server

- **`host install` writes Homebrew's node link, not the versioned Cellar path.** It wrote the resolved path of the node
  that ran it (for example `/opt/homebrew/Cellar/node/25.8.1_1/bin/node`), which a `brew upgrade` removes, leaving the
  MCP entry and the wake hooks pointing at nothing. When `/opt/homebrew/bin/node` or `/usr/local/bin/node` resolves to
  the same node, that link is written instead; any other node is written as before. Run `host install` again once:
  the entry and hooks an earlier install wrote with the Cellar path are replaced, not refused and not doubled.
- **`record keep --plist` and `--crontab`, and `onboard`'s commands and cron line, name the same link.** They printed
  the Cellar path too. A job or cron line you installed from them before keeps that path: print it again and replace it.
- **`host install` no longer replaces `<home>/package` under a running server.** A second identity's install of
  another version overwrote the copy a running server of the same home had started from. Now each version is staged
  once in `<home>/package/versions/<version>/` and never written again, `<home>/package/current` names the one in use,
  and the four launchers beside it run that one, so nothing runs from files an install changed. A running bag service
  is told: `the running bag service (pid N) moves to bag V at its next drain and restart`. See
  `docs/partner-install.md`.

### The omp wake no longer answers mail on its own

- **An omp agent shows the mail it is woken for and answers only when you ask.** The wake turn said "read it, then
  answer it", so two omp agents paired with each other answered each other without end. It now says to show the mail
  to you and to answer only when you ask, or when the message plainly asks a question you already told the agent to
  answer. When one peer has sent 3 or more messages in ten minutes since you last typed, the wake adds "this looks like
  a loop: show your person and do not answer", with the count and the peer's name. See `docs/host-omp.md`.

### The envelope cap: 196,608 bytes

- **An envelope can be 196,608 bytes (192 KiB), up from 65,536.** One recipient's body now holds about 97,000
  characters of JSON text, up from about 32,000, and a 64 KiB body fits with up to 16 recipients. The request body cap
  (262,144), the record cap (131,072) and the WebSocket frame cap (262,144) do not change. `send`'s description in the
  MCP server derives its figure from the cap. See `docs/message-size.md`.
- **Accept-from records are lifted on their next re-sign.** Every accept-from record signed so far carries `max_bytes`
  65,536, the old default. Each re-sign (`record keep`, the MCP server's keep-alive, `onboard`, a pairing and `unpair`)
  now writes 196,608 in place of exactly 65,536 and keeps any other value. `record keep` re-signs at least every
  11 hours, so an identity on the new version takes the larger mailbox within about 11 hours, with nothing to type. A
  `max_bytes` of 65,536 chosen on purpose is lifted too; sign it as 65,535 to keep it small. `onboard` and the
  organisation client's records default to the cap.
- **The relay call's time limit follows the body.** Each relay call is given 10 seconds plus 1 second per 16 KiB of its
  body, at most 29 seconds, under the relay's 30 second body timeout: 22 seconds for a full envelope, so a full send
  still goes out on a slow uplink (a flat 10 seconds failed it below about 160 kbit/s). A fetch by id is given the time
  of a full envelope.

### A partial delivery

- **`send` reads a partial delivery the same in the CLI and the MCP server.** Delivered via at least one relay is a
  success: the CLI's `send` (and `resend`, `held release` and `group send`) exits 0 with a warning line on stderr,
  `warning: delivered via 2 of 3 relays; refused 1: <relay> envelope-too-large; ...`, where it exited 1 before. The MCP
  send tool's answer gains `summary`: `delivered`, `relays`, `refused` (each relay with its reason), `retrying` and a
  `text` line; it answered a partial delivery as a success before too, with no count. No relay taking it is still an
  error, with the first refusal's code, its bytes kept in the outbox and the `resend --id` hint. A script that read
  exit 1 as "some relay refused" reads the warning line now.

### Pairing: a cancel

- **`pair_cancel` ends a running pairing in the MCP server.** A person who opened an invite and changed their mind
  (for another address, say) met `busy` for up to ten minutes, and an agent could only say to wait or to stop the
  server. The new tool ends the invite or the accept on the person's word and writes nothing. An invitation that no
  request has reached is withdrawn (its one-time invitation identity's address record, never the inviter's own), so its code meets `invite-expired` on the other side; `busy` now names
  `pair_cancel`. The CLI's pairing runs in the foreground with no lock, so it needs none: Ctrl-C ends it.

### Migration: the order

1. The relay flag first, the operator's deploy: `--max-envelope-bytes 196608` at every relay. A relay of 0.2.3 or later
   takes it with no new binary; until it moves it refuses a larger envelope `envelope-too-large`, and the sender reads
   a partial delivery.
2. Then the readers: every `bag` and `bag-mcp` on the new version. v0.3.0 and before refuse a larger envelope when
   they read it, so a message to a peer still on them is lost on its side.
3. Then the lift, automatic, within about 11 hours through `record keep`.
4. Only once every reader runs the new version may a policy file set a scope `max_bytes` over 65,536: v0.3.0 and
   before refuse such a file at start (`bad-record`).

## v0.3.0: 2026-11-11

The cut tagged v0.3.0, `@usebag/bag` 0.3.0.

- **`@usebag/bag` 0.3.0**, published from this cut (`npm view @usebag/bag@0.3.0 gitHead` names it).

### MCP server

- **A `facts` tool: the model's id, session cost and context from the host, never guessed.** The host writes
  `host-facts.json` in the identity's state directory, and `facts` returns each figure with its age, says which ones
  the host did not provide, marks facts over 10 minutes old stale, and says first when the session is a spawned
  sub-session rather than the one that speaks for the identity. `status` carries `model` and `main_session`. See
  `docs/agent-facts.md`. Telemetry counts `facts` calls under the tool `facts`: the telemetry Worker's
  `SCHEMA_COMMIT` and the client's `TELEMETRY_SCHEMA_COMMIT` name the release's schema commit, set at release-bump,
  and the Worker is deployed first (the release runbook's step 4a), since it refuses reports from a schema commit it
  does not know.
- **`facts` and `status` in a held server.** While another session holds the identity, both answer `held: true`,
  `held_by` (pid, start time, folder, host and the lock's `path`), a `note` that this session does not speak for the
  identity, the server's own `pid`, `started_at` and `uptime_s`, `held_since` (null, with `held_from_start`, when it
  was held from its start) and `host_facts: null` with `host_facts_state: "held"`. Neither reads the holder's
  `host-facts.json`.
- **A second copy is not a rejection.** A message that arrives again over another of the identity's relays is counted in
  `status` as `copies_already_received_via_another_relay`, no longer under `rejected` (`duplicate`).
- **`send` says how big a body can be:** about 32,000 characters of JSON text (the envelope cap is 65,536 bytes); past
  it the send is refused `envelope-too-large`.
- **Large sends no longer hang when the server's stdin is a terminal.** A host that runs `bag-mcp` on a pty (an omp
  background service does) wrote each request as one line into a terminal in canonical mode, which passes at most
  1,024 bytes of a line on macOS: a send with a body over about 880 bytes never reached the server and its caller
  waited for good. When stdin is a terminal the server now puts it in raw mode once it has started (one `stdin` line on stderr
  says so), restores it on exit, and stops on Ctrl-C or Ctrl-D. Over pipes, as MCP hosts start it, nothing changes.
  Message size limits: `docs/message-size.md`.
- **Pairing works inside a host that cannot show dialogs, when it runs a bag extension (the consent bridge).** omp has
  no MCP elicitation, so the pair tools could before only hand you the `bag pair` terminal command. Now, when the
  host's extension marks a user-interface session (a presence file in the identity's consent directory), the server
  asks you through files the extension answers: you paste the peer's code, read the six check digits out to the peer and
  press Yes, with no terminal and the model never seeing the code or the digits. A question stands 120 seconds; a
  timeout counts as No. With no such extension (a piped or background run), nothing changes: a host with dialogs uses
  them, and one without keeps getting the `bag pair` command (see `docs/pairing-without-dialogs.md`).

### omp

- **`bag host install omp --as <name> --relay <url>... --project <dir>`** wires an omp folder in one command: the bag
  server in `.omp/mcp.json`, and `.omp/hooks/pre/bag-wake.js`, a link to bag's wake extension in `<home>/package/`.
  The extension starts one turn per delivered message, holds a message that arrives during a turn until the turn
  ends, wakes only the main interactive session, and writes the session's model, cost and context use for the
  `facts` tool. `bag host remove omp` undoes it. See `docs/host-omp.md`.

### Locks

- **A second session in a folder is told who holds the identity.** A bag MCP server that finds the identity held by a
  live server no longer exits (the host showed only "Connection closed"). It stays up: `status` returns `held_by` (pid,
  start time, folder, host) and every other tool answers `bag: the identity NAME is held by another session (pid N,
  started T); close that session or run bag in its own folder`. It tries the lock every three seconds and takes the
  identity over when the holder ends.
- **A server whose host died releases the lock.** Besides the end of stdin, the server checks every two seconds that the
  process that started it is still its parent, and stops, removing `mcp.lock`, when it is not.
- **`mcp.lock` says more.** It now holds `started_at`, `cwd`, `ppid` and, once the client has introduced itself, `host`
  beside `pid`; readers that want the pid alone are unchanged.
- **`bag inbox` beside a running server** stops with `held:` and names the holder instead of the store's lock file, and
  `bag status` prints a `held_by` line. See `docs/one-identity-per-folder.md`.

### Fixes

- **A pairing leaves your records at every relay you name, not the rendezvous alone.** `peer invite`, `peer accept` and
  `pair` now take `--relay` more than once, and a completed pairing publishes the identity's address and accept-from
  records at every relay named, so a later host install does not warn that a second relay is missing them; a relay that
  refuses is a warning line, not a failure of the pairing.
- **The Claude Code and Codex wake hook no longer wakes twice for one burst of mail.** Several messages arriving
  together ring the doorbell several times; the hook now waits 300 ms and remembers the last ring, so the next Stop
  hook stays silent for mail the model has already read.
- **A send to a recipient whose relays moved reaches them.** When every target of a send is given up, as not hosted
  or unreachable, the sender reads its recipients' records again once, forgetting what it had cached, and sends again
  when that read names other relays for a recipient; when nothing changed, the send ends as before.
- **`host install` says when a relay will refuse the identity's mail.** For omp, and for Claude Code with `--project`,
  the install reads the identity's address and accept-from records at each relay it names, and warns, pointing to
  `bag onboard`, when no relay and no copy in the home holds one.
- **`host install` mends a relay that lacks a record another one holds.** When a named relay holds no address or
  accept-from record of the identity but another named relay or the home's copy does, the install publishes the newest
  copy to that relay as it is, with nothing re-signed (the same act as `bag record keep --once`), and a line says so.

## v0.2.3: 2026-11-10

The cut tagged v0.2.3, `@usebag/bag` 0.2.3.

- **`@usebag/bag` 0.2.3**, published from this cut (`npm view @usebag/bag@0.2.3 gitHead` names it).

### Enterprise: pairing and trust

- **A pairing revoked from the console leaves the agent's accept-from at once.** The bag MCP server signs and publishes
  the accept-from again after a console pass that ends a pairing or runs one, as `bag pairings` already did, instead of
  at the next hourly refresh.
- **Read receipts follow the organisation's setting.** While the organisation's instance has read receipts off, the bag
  MCP server's `--receipts-to` answers none; it answers again once the setting is back on. An instance that does not
  send the setting keeps receipts on. The CLI sends no receipts.

### Testing

- **A test zone switch, off by default**, for two bag enterprise instances and their relays on one machine under the
  zone `pilot.bag.dev`. It is on only when `BAG_TEST_ZONE_FILE` names a zone file, and then the CLI and the MCP server
  print one stderr line that says so: TXT lookups in that zone read the file, `BAG_TEST_ZONE_ORIGINS` maps a domain's
  origin to a loopback address, and the relay guard lets loopback relays through. Malformed values print a usage line
  and exit 2. Never for real use; with the variables unset nothing changes.

## v0.2.2: 2026-11-09

The cut tagged v0.2.2, `@usebag/bag` 0.2.2.

- **`@usebag/bag` 0.2.2**, published from this cut (`npm view @usebag/bag@0.2.2 gitHead` names it).

### Enterprise: mail between organisations

- **`bag send --to <label>@<your organisation's domain>`** goes to the organisation's agent of that label, read from
  the organisation's directory, as `--to <label>` does. A label the directory lacks, or a directory that does not
  answer (one line on stderr), takes the public path: the domain's DNS record, its org record and the handle record.
- **`bag send --to <agent>@<partner's domain>`** goes to a partner organisation's agent by the handle record that its
  instance publishes, as for any handle.
- **The agent takes a partner's mail.** The agent's accept-from record now lists the organisation's accept list: its own
  root, and the root of each partner whose agreement covers this agent. The list is read from the instance at each
  refresh, and the record is published again when the list changes. An instance without the list keeps the
  organisation's root alone. A list that names `*`, more roots than a record holds, or something that is not a root is
  refused with one line, and the record keeps the roots it had. inbox trusts a partner's root once the organisation
  grants it, with its partnership named in `trust.json`; the root leaves when the partnership ends.

### Enterprise: pairing started from the console

- **An organisation can pair one of its agents with someone outside it from the console.** The agent's machine runs the
  same pairing as `bag peer invite`, and the code shows in the console. The console's person types the six check digits
  that the other side reads out, with three tries. The pairing ends when the console revokes it or its term ends. The
  bag MCP server picks this up every 15 s, and **`bag pairings [--watch]`** does the same for an agent with no MCP host.
  Both open the pairing at the organisation's first relay, where the agent's records are, even when the MCP server
  was installed with another `--relay`.

### Names and labels

- **A name in the name book and an agent's label in the organisation's directory can be up to 64 characters**
  (previously 32), in the CLI and in the MCP server.

### Fixes

- **Security: the relay's SQLite is 3.54 or later** (RUSTSEC-2026-0459, CVE-2026-119375). The relay's bundled SQLite
  came through `rusqlite` 0.40.2 and `libsqlite3-sys` 0.38.2, and it is now `rusqlite` 0.41.1 and `libsqlite3-sys`
  0.39.1. Older SQLite can return uninitialised memory when it opens a database together with a write-ahead log whose
  page size differs. The relay opens only its own database, which it writes itself. No relay API or behaviour changes.
- **`bag connect` to an instance on a private network** (RFC 1918 or ULA, such as a container network) now works as
  loopback does, with one stderr line naming the addresses. Link-local, multicast and other addresses are still
  refused.

## v0.2.1: 2026-11-07

The cut tagged v0.2.1, `@usebag/bag` 0.2.1.

- **`@usebag/bag` 0.2.1**, published from this cut (`npm view @usebag/bag@0.2.1 gitHead` names it).

### Enterprise: connect proves the path

- **`bag connect` ends with one line, `Connected as <label>; relay round trip <n> ms`.** Once the organisation
  approves, the same command publishes the agent's records at every relay of the organisation, sends the agent one
  envelope from its own session key through the organisation's first relay (the same send path as `bag send`) and
  reads it back on the agent's own subscription, acknowledged so that the agent's inbox does not show it. `<n>` is that
  round trip, on a monotonic clock. Nothing else is to be run before the first send.
- **A step that fails is one line, exit 1, the session kept**: `Connected as <label>, but its records were not
  published at <relay> (<code>): bag status tries again`, or `..., but the relay round trip failed at <relay>
  (<code>): ...`. Each relay step is bounded at 5 s (`timeout`).
- **`--verbose`** prints what connect printed before (`Connecting to <domain> at <origin>`, `Approved: agent
  <fingerprint>`) and each relay's records; without it no fingerprint, key or address is printed. The line
  `relay <relay>: records not published (<code>)` is replaced by the failure line above.
- **`bag status`** (with no `--as`), for a live session, adds the same line from one probe that sends nothing (the
  agent's address record read back from the first relay), or the failure line with exit 1.
- **The MCP tools** `connect` and `status` (and `enterprise_status` of `bag-mcp`) return the same lines.
- **Where the check message can show once.** When the organisation has more than one relay, the check envelope also
  reaches the agent's other relays, up to three, and an inbox read at one of those shows it once. When older mail waits
  ahead of it at the first relay, as after a reconnect with the same keys, connect leaves that mail alone, and the
  agent's inbox shows the check message once after it.

### Enterprise: the code's label

- **A connect code carries the agent's label.** `bag connect` sends no label unless `--label` is given; `Connected as
  <label>` prints the label the organisation returns (the code's, such as `example-com-1`, or the next free number
  when that one is held), and the session keeps it for `bag status`. A `--label` that a live agent of the
  organisation already holds exits 1 with `label_taken`, naming the label, and leaves the code unused. The MCP
  `connect` tools return the same lines.

### Enterprise: one profile per organisation

- **Connecting to a second organisation keeps the first.** `bag connect` and `bag sign-in` on a home already signed in
  to another organisation add the new one beside it and revoke nothing: no sign-out is asked for and no key is
  revoked. The line names both: `Connected as <label> (<domain>); relay round trip <n> ms; also signed in to <other>:
  bag status --org <other>`.
- **`--org <domain>`** picks the organisation for `bag status` and `bag sign-out`. With one it is implied. With
  several, `status` shows the most recently connected and names it and the others in one line on stderr, and refreshes
  them all; `sign-out` without `--org` removes nothing and exits 2 with the list. `bag sign-out --org <domain>` revokes
  that one only. The MCP `status` and `enterprise_status` tools take an optional `org`.
- **The home's layout.** Each organisation's session files now live in `<home>/orgs/<domain>/enterprise/`;
  `<home>/enterprise/current.json` names the most recently connected. A home of the older shape is moved into its
  organisation's profile the first time it is read, with nothing to do. The chain file a session prints moves with it:
  `bag status` names the new path.

### Enterprise: send and inbox with no flags

- **`bag send` and `bag inbox` after `bag connect`, with no other flag.** With a live enterprise session,
  `bag send --to <name|label|address> --type <type> --body <json>` and `bag inbox --once` take the relay, the sender,
  the chain and the trust root from the session; a flag given still wins, and with no session nothing changes. The
  trust root is the organisation's root address, so receiving never waits on a DNS lookup, and `--trust-root
  <domain>` for the session's own domain reads as that address. A `--to` the name book lacks is looked up as an
  agent's label in the organisation's directory. `bag inbox --once` ends 200 ms after the relay admits it and its
  backlog is delivered, instead of after a fixed second: about 0.45 s end to end on this machine, where it was 1.25 s.
  With several organisations in the home, both take `--org <domain>`, and without it name the organisation they use on
  stderr; the directory's copy is kept per organisation.
- **`bag inbox` says when a message is kept, not refused.** A message refused for a cause that can pass prints
  `waiting <id> resolve-failed: kept; the next read after the trust root is fixed delivers it` (or `future-ts`, `...
  after its timestamp is past ...`) instead of `reject <id> <code>`, and the next read delivers it with no resend.
  `reject` is kept for final verdicts.
- **`bag send` needs no `--type`.** Without one the message's type is `chat.v1`; a `--type` given wins.
- **`bag send --body @-` and `--body @<path>`.** The JSON body from stdin, read whole, or from a regular file (no
  symbolic link followed), each at most 65,536 bytes: text from elsewhere never has to be quoted into the command line,
  for example `printf '%s' "$text" | jq -c '{text: .}' | bag send --to <name> --body @-`.

## v0.2.0: 2026-11-07

The cut tagged v0.2.0, `@usebag/bag` 0.2.0.

- **`@usebag/bag` 0.2.0**, published from this cut (`npm view @usebag/bag@0.2.0 gitHead` names it).

### The enterprise client: one public client

- **`bag connect`.** Connects this machine's agent to its organisation with the one-time code a person copies from
  their organisation's bag console. The code is read from `BAG_ORG_CODE` or from one line of stdin ("Paste the code"),
  never from the command line. The code names the instance and the organisation, so nothing else is typed: the
  instance it names is pinned (no discovery), https or http on this machine only, the private-address guard runs
  before any call, and no call follows a redirect. It prints `Connecting to <domain> at <origin>`, `Approved: agent
  <fingerprint>` and `Connected as <label>`; exit 4 while the organisation's signer is still to sign. No key, token or
  code is printed.
- **`bag sign-in <domain> --instance <origin> [--no-wait]`.** The same session without a code: the device flow a
  person approves in the console. It prints the link to open, the user code and the key's fingerprint, and with
  `--no-wait` exits 4 while the approval waits; the same line run again resumes it. `--instance` pins the console origin
  as a code does. Without `--instance`, the instance comes from `BAG_ENTERPRISE_INSTANCES`, the organisation's
  `.well-known/bag/enterprise.json` record, or `BAG_ENTERPRISE_URL`.
- **`bag status`** (with no `--as`) shows the enterprise session after one refresh tick: the organisation, the agent's
  address, its state, the token, the org hop and the local hop, the generation; `--chain` prints the chain for an MCP
  server's `--chain-cmd`; `--plist` and `--crontab` print the hourly refresh job. `bag sign-out` ends the session.
  Exits: 0 done, 1 refused or failed, 2 usage, 3 ended or none, 4 waiting on a person or the signer.
- **The agent's records.** After the grant, and again before they lapse, the agent publishes its address record and
  its accept-from record at each relay the organisation names, signed by its own key on this machine; a relay that did
  not take them is one line, `relay <relay>: records not published (<code>)`, and every tick tries again.
- **The MCP tools.** `bag mcp` serves `connect`, `sign_in` and `status` over stdio to an MCP host, for an agent with
  no identity yet: `claude mcp add bag -- npx -y @usebag/bag@<version> mcp`, then the person pastes the code into the
  chat. The identity server, `bag-mcp`, lists the same three as `connect`, `sign_in` and `enterprise_status` beside
  its other tools. Every result holds only the lines the commands print, scrubbed of the code, the device code and
  the token.
- **The home.** The session lives in `<home>/enterprise/` of bag's own home (`AC_HOME`, else `~/.bag`), 0700 with 0600
  files; a home of another user is refused, and every run holds the home to its owner.

## v0.1.2: 2026-11-04

The cut tagged v0.1.2, `@usebag/bag` 0.1.2.

- **`@usebag/bag` 0.1.2**, published from this cut (`npm view @usebag/bag@0.1.2 gitHead` names it), and the first
  release with a tag, `v0.1.2`, and a GitHub Release. 0.1.0 and 0.1.1 are not tagged.

### Telemetry

- **The daily report names the package version.** A report's `build` is the package's npm version when the telemetry
  service lists it (0.1.0, 0.1.1 and 0.1.2), else `other`. Until now every report's build was `other`, though the
  notice said the version was sent; 0.1.0 and 0.1.1 were built before the change and still send `other`. `bag version`
  and `bag --version` are counted as the command `version`, no longer as `other`.
- **The notice names a command that lasts.** Run from the package, the telemetry notice prints
  `npx --yes --package=@usebag/bag@<version> bag telemetry preview`, not a file in npm's cache, which npm may clear.
- **A day's counts reach that day's report.** A long-running process, such as the MCP server or the A2A bridge, that
  counted in a day's last minute and then went quiet held that count until its next one, and the day's report went
  without it. It now writes held counts a minute after a count.

### Security

- **`SECURITY.md` says more.** The two public relays, `relay1.bag.dev` and `relay2.bag.dev`, are run by the project
  and in scope for good-faith testing, with no load, availability or volume testing, no one else's data and no social
  engineering. Reports about the project's other services (the site, its install guide, the `.well-known` and handle
  records, the telemetry endpoint) are welcome, but active testing against them is out of scope. There is no bounty;
  reporters are credited by consent in `docs/thanks.md`. A safe harbour: good-faith research within the policy is not
  reported to law enforcement or pursued by us.
- **A known limitation, stated.** The install guide checks the package's version and the commit that the registry and
  `bag --version` name, which whoever controls the registry's answers could also serve; it does not verify the
  package's provenance. Its step 2a gives the check by hand, `npm audit signatures`, which checks the provenance's
  signature but not who signed it.

### Documentation

- **`docs/partner-install.md` offers two routes**: the npm package (section 1a: the `npx` command, its `--version`
  and `npm view ... gitHead` checked against each other, the three programs) and from source (section 1b). The later
  sections hold for both: section 3 names the public relays and the relay image for the package route, section 5c
  wires the MCP server through `host install`, and section 6 marks the handle script source-only.
- **`packages/mcp/README.md`, "Install"**, gains the package route: `bag host install` run from the package copies it
  to `<home>/package/` and registers `node <home>/package/bag-mcp.js`.
- **`docs/release.md`** says how a release is made: the version change, the cut, the staged publish and its approval
  on npm, the read-backs, the relay image, the tag and the GitHub Release, and the rollbacks.
- **The pinned install lines name 0.1.2**, in `README.md`, `docs/partner-install.md`, `packages/mcp/README.md` and the
  package's own `README.md`.

## v0.1.1: 2026-11-03

The cut 3c343d65, `@usebag/bag` 0.1.1.

- **`@usebag/bag` 0.1.1**, published from this cut (`npm view @usebag/bag@0.1.1 gitHead` names it). No code changed
  from 0.1.0: the version, the package's home page (`https://bag.dev`) and the version its README names.
- **The package is staged, then approved.** The publish workflow stages each version by npm's trusted publishing
  (OIDC, no token) and checks npm's answer against the packed file; a maintainer approves the staged version on npm,
  with two-factor authentication, before anyone can install it. The token path is gone.

## v0.1.0: 2026-11-03

The cut 58400aaf, `@usebag/bag` 0.1.0. The cut bc212d8c of the same evening carried the same, but for one fix to the
package's build test; no package was published from it.

- **bag is an npm package, `@usebag/bag`.** One bundle with no dependency and no install script holds the command
  line (`bag`), the MCP server (`bag-mcp`) and the A2A bridge (`bag-a2a`); it needs Node 24 or later, and
  `npx --yes --package=@usebag/bag@0.1.0 bag` runs it without a global install. `bag --version` prints the version
  and the commit it was built from. The package is published from that commit by a workflow with npm provenance, and
  `npm view @usebag/bag@0.1.0 gitHead` names it. The relay is not in the package (`README.md`, "Quick start", and its
  new section "From source").
- **The wiring outlives npm's cache.** Run from the package, `host install`, `record keep --plist` or `--crontab` and
  `onboard` first copy the package to `<home>/package/` and write that path, so a cleared npm cache does not break
  them.
- **The relay image can be pulled.** `docs/self-host.md`, "Run it with Docker", gains "Or pull the published image":
  `ghcr.io/usebag/relay:<commit>`, tagged by commit with no `latest`, with the checks of its platforms, provenance and
  SBOM, and a compose override you write that names the image by commit and digest.

## 2026-11-03: the cut cc4f25dd

New since the cut 635a89b2 of the same morning.

### Security

- **The A2A bridge listens on the loopback only.** `--host` (and `A2aBridgeOptions.host`) now accept a 127.0.0.0/8
  address, `::1` or `localhost` and refuse anything else before the bridge listens, with exit 2 and the line "the
  bridge listens on loopback only; it has no caller authentication". Before this change `--host 0.0.0.0` or a LAN
  address let every machine that could reach the port send as the bridge's identity, since the Host and Origin
  checks stop browsers, not programs. The default, 127.0.0.1, was already safe. Any local process can still call the
  bridge, the same trust as the command line on the same home; a caller token is a later option (`packages/a2a/README.md`).

### New

- **Telemetry can send, once a person turns it on.** It stays off until then. While it is on, each finished UTC day's
  report goes once to `telemetry.bag.dev`, from 01:05 UTC the next day; `c telemetry status`, `preview`, `on`, `off`
  and `forget` (`README.md`, "Telemetry"). The report gains the family `pairs`: the machine's trusted peers counted
  by age (under 7 days, or more), and of those, the ones it sent to in the last 7 days. It needs consent version 2, so
  a yes given to version 1 reads as off and is asked again. Earlier cuts send nothing.
- **The clients go through a company proxy.** The command line, the MCP server and the bridge honour `HTTPS_PROXY`,
  `HTTP_PROXY` and `NO_PROXY`: when a proxy is set, each restarts itself once with Node's `NODE_USE_ENV_PROXY=1`, and
  `status` shows the network it uses. A fallback for a proxy that cuts WebSockets is not built.
- **The relay as a container.** `deploy/docker/` builds the relay into a small image with no shell that runs as a
  non-root user, with a compose file for one relay on the host's loopback and a Caddy TLS front
  (`docs/self-host.md`, "Run it with Docker"). The image of this cut is published as
  `ghcr.io/usebag/relay:cc4f25dd22448ae066cc99c2195eb9491d6ca24a`. The self-host guide's Linux steps and systemd unit
  were run on Ubuntu.
- **`docs/inside-a-company.md`**, a guide to using bag inside a company: the security team first, your own relays,
  company identities and an allow-list of writers, telemetry off, the public relays only with approval, and the proxy.
- **The relay counts first subscribes**, `ac_relay_first_subscribes_total`: a fresh mailbox's subscription, once a UTC
  day, with nothing new stored (`docs/self-host.md`).
- **The spec says what the code does**, with no wire change: the pairing invite string and request are written out
  (`spec/SPEC.md` section 2.4, section 8.10), pair/open takes 1 to 64 relays, a nameplate's `ttl` is required, 1 to 600 seconds
  (Appendix B, item 89), and section 7.2 states the relay URL form once, as every record reader checks it.
  `spec/vectors/pair-code.json` gains the check digits, the request MAC, the invite string and pair/open.

## 2026-11-01: the first public cut

The first public release: version 0 of the wire format, a security preview (`README.md`, "Status"), under
Apache-2.0. Earlier cuts were private previews, handed out as git bundles; the last two were e4c2c7c9 and e109553c,
both of 2026-10-31.

### What it is

- **The specification**, `spec/SPEC.md`, with its test vectors and adversarial cases, and three implementations that
  the vectors bind: the TypeScript reference (`packages/`), the Rust verification crate and reference relay
  (`crates/`), and a participant in Python written from the spec alone (`examples/python-join`).
- **An identity** is an Ed25519 key pair, and its address is its public key. It publishes signed records: an address
  record with its relays and its sealing key, and an accept-from record naming the roots it takes mail from.
- **A message** is a signed, sealed, threaded envelope. A relay sees who writes to whom and when, never the type, the
  thread or the body (`SECURITY.md`). The sender publishes it to up to three of the relays its recipient lists, which
  keep it for up to 7 days, and the recipient reads every relay it lists.
- **Pairing** joins two identities with a one-use code and six check digits that the two people check against each
  other, through a rendezvous relay (`spec/SPEC.md` section 8.10).
- **The tools**: the command line (`packages/cli`: keys, records and `record keep`, `send`, `inbox`, `resend`, `peer
  invite` and `peer accept`, `unpair`, `host install`, `audit verify`); an MCP server that gives an agent in an MCP
  host an address and a mailbox, up to 64 identities in one server, with pairing as tools (`packages/mcp`); and an A2A
  1.0 binding through a local bridge (`packages/a2a`).

### New since the preview cut e109553c

- **The relay limits what one address can load on it.** Each client address may fetch 6,000 times a minute, counted
  before any signature is checked, under a relay-wide ceiling of 30,000 fetches a minute, and may store 100 MB of
  envelopes a UTC day; past either, the relay answers 429 `rate-limited` with `Retry-After` (`--fetch-per-ip`,
  `--fetch-global-per-minute`, `--bytes-per-ip-per-day`). On IPv6 the rates and quotas count per /56 and the
  connection cap per /64. A full store also refuses records from signers it does not yet hold, while a signer it holds
  may still update its records.
- **The relay keeps answering under that load.** The expiry sweep runs off the async worker thread, at most 256 rows of
  each kind a transaction. An acknowledgement at or below the last one costs no store call, and a subscription stores
  its latest acknowledgement at most once a second. A pending envelope's domain lookups are bounded: at most eight
  domains a row and 64 a pass. A subscriber that cannot take a frame within the idle timeout is closed with 4003. A
  domain root's grant comes from the newest valid record of the key the relay holds, so a stale copy from the host rolls
  back no revoked list.
- **Pairing and resolving follow three new rules** (`spec/SPEC.md` section 8.10 and section 9 item 4). A pairing binds to the peer's
  address when it is known (`--for` on the terminal, an address field in the MCP dialogs), and the open invitation is
  for first contact only. A frame that is not a well-formed request no longer ends a pairing or counts against its
  tries, and `leaked` now means a second good request from another requester. The resolver keeps the record with the
  greatest `iat` across the relays that answered, so a lagging relay cannot serve an older epoch key or revoked list,
  and a relay that does not answer never blocks a read. The spec also states the relay limits above (section 8.2 to section 8.4,
  section 8.9).
- **The MCP server after its first real run.** `pair_invite` answers `paired` in the call that took the right digits,
  where it answered pending; each pairing dialog takes the peer's address; a session probes its grant on a thread
  drawn at random, not one any sender could name; after a logout, a session's new grant goes to a new key, not to the
  revoked one.
- **The CLI.** The keep job that `record keep --crontab` or `--plist` prints draws its minute on each machine, so
  machines no longer reach the relays in the same minute; `inbox` takes every `--relay` and subscribes at each, as the
  Codex worker's line needs; `unpair`, `onboard` and a publish that revokes go on past one relay down and name it.
- **`docs/partner-install.md`.** Section 5b pairs with `--for` when the peer's address is known, quotes `pairing code
  <code>`, and says the digits go by another way than the code; section 7 says two public relays run.
- `record keep` offers the key record only to a relay that does not read it back as holding it.

### Already in e109553c, new since e4c2c7c9

- **A relay that is down no longer stops a pairing or a key rotation** (`spec/SPEC.md` Appendix B, item 110). Records
  are offered to every listed relay, and the edge names each relay that did not take one (`failed <kind> <address>
  <relay> <code>` in the CLI); `record keep` and the MCP server's keeper carry the rest later. A pairing needs the
  rendezvous relay, which now also holds the invitation, and one listed relay. A record with a revoked list that a
  listed relay has not taken is reported as an incomplete revocation, naming that relay, until every listed relay holds
  it: `keys rotate` exits 3, and the MCP server reports `incomplete-revocation`.
- **Mail survives a relay restored from an older copy.** The edge decides delivery by envelope id, not by the relay's
  cursor, and resumes each subscription with cursor null (`spec/SPEC.md` section 9, items 2 and 10). An edge's inbox store
  from an earlier cut is rebuilt once when it opens, its rows kept. The reference relay notices that its database came
  from another volume and raises every mailbox's cursors, logging `cursors-raised` (Appendix B, item 102).
- **The keepers carry the key record too.** `record keep` and the MCP server's keeper offer an identity's key record to
  its listed relays, the MCP keeper only to a relay that does not read it back as holding it. The MCP keeper does the
  same for the address and accept-from records and retries a lagging relay early, after 60 seconds, doubling up to an
  hour, so a cycle in which every relay holds every record publishes nothing.
- **ac-relay holds an idle subscription in about 10 KiB of memory**, against about 133 KiB before, measured natively:
  each WebSocket read buffer is 4 KiB.
- **A load generator for the relay**, in `packages/e2e/bench`, the one used to measure the relay's load.
- `THIRD-PARTY.md` names Litestream, which the project's relay image carries.

### Already in e4c2c7c9, new since the cut before it (d1b4b5dc)

- `pair_invite`'s first result tells the agent that its person does not see tool results, so the agent writes the
  pairing code out, alone in a code block.
- A message refused because the peer unpaired you now says so, in the MCP server and the CLI, in place of "ask them to
  add your root".
- Behind a proxy, a subscription past the per-address cap is refused `rate-limited` and closed 1013, as it is for a
  direct client, in place of a close with no answer, which read as an unreachable relay.

### New with the public release

- The public files: `LICENSE` (Apache-2.0), `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md` and `AUTHORS`; the
  README's "Limits"; and this file.

### Outside this repository

- The project runs a second public relay, in Amsterdam beside Paris. The install guide it serves lists both relays and has
  a section "Unpair and leave": unpairing, leaving in order, and adding or moving a relay. Its step 4 now pairs in the
  new order: each side's dialog offers the peer's address, the inviting agent stops after showing the code, and the
  digits dialog opens once the person says the peer has the code.

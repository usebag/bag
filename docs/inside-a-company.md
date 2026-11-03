# Using bag inside a company

A short guide for someone who wants to use bag, the bag.dev protocol, behind a company network with a security team
and a strict VPN or proxy. It says what to settle first, how to keep company mail on company machines, how to limit
who can write to a company mailbox, and how to run behind the company's proxy. The README, `SECURITY.md` and
`spec/SPEC.md` are the authority on what the protocol does; `docs/self-host.md` is the guide to running a relay.

## 1. Talk to your security team first

bag is a security preview of version 0 of its wire format: no outside cryptographic review has signed, the audit
package is public, and nothing is supported or stable yet (`README.md`, "Status"; `SECURITY.md`). Bring them the
threat model (`docs/audit/threat-model.md`), the two review rounds (`docs/audit/stream-10-review.md`) and the one
paragraph of `SECURITY.md` that says what a relay sees. What a relay sees is who talks to whom, when, how big and
from which IP address; it never sees the message type, the thread or the body (`README.md`, "How it works"). That is
enough for a security team to decide where a relay may run and what may pass through it.

## 2. Run your own relays inside the network

The reference relay, `ac-relay`, builds from source and runs on a machine you control, or in a container built from
this repository with Docker Compose (`docs/self-host.md`, "Run it with Docker", which adds a Caddy TLS front with a
certificate from its own local authority for a network that cannot reach a public one); `docs/self-host.md` takes it
from build to a TLS front, backups, limits, metrics and logs. With your own relays:

- Mail to your identities passes only through the relays their signed address records list. If those are yours, no
  other relay holds your incoming mail or sees who writes to you (`docs/self-host.md`, section 1).
- Mail from your identities goes to the relays each recipient lists. Running a relay does not change that: a
  colleague's mail stays inside only when every colleague lists company relays (`docs/self-host.md`, section 1).
- Pairing goes through a rendezvous relay. Use your own as the rendezvous and it is yours that sees the opened
  invitation and both sides' IP addresses, never the code's words or the check digits (`docs/self-host.md`, sections
  1 and 10).
- A relay makes outbound calls only to resolve `domain:` roots named in records published to it, by DNS and HTTPS to
  the host named; it needs no other outbound access (`docs/self-host.md`, sections 1 and 13).
- A sender's edge refuses a recipient's relay on a private, loopback or link-local address unless the sender names it
  as its own `--relay` or passes `--allow-private-relays`; a relay that other companies send to needs a public address
  (`docs/self-host.md`, section 2). Inside one network, list the relays on every identity and the flag is not needed
  for them.

List two relays on each identity: a message goes to up to three of the relays its recipient lists, and a recipient
reads every relay it lists, so one relay down loses nothing (`docs/self-host.md`, section 11).

## 3. Company identities, and an allow-list of who may write

A mailbox's owner decides who may write to it. A signed accept-from record names the roots the mailbox takes mail
from, and a relay refuses mail under any other root before it stores it (`README.md`, "Why"). Three ways to keep that
list to colleagues:

- **An organisation root at your domain.** `onboard` anchors an org root at your domain and names agents under it as
  handles such as `jane@example.org`; its `--accept` list says whose messages the agent's mailbox takes: a domain
  (`domain:example.net`), an address, or `*` for anyone, which you would not use here (`docs/onboarding.md`,
  section 2). Colleagues' agents under the same domain admit the domain once, not each other one by one.
- **Addresses one by one.** `c record accept-from <name> --root <address>` and `c publish` name the roots a mailbox
  takes, and `c inbox --trust-root <address or domain>` names whose messages an edge accepts; with no trusted root
  an edge trusts no one (`docs/partner-install.md`, sections 4 and 5; `docs/self-host.md`, section 4).
- **Pairing.** A pairing writes the peer into the name book and the trust file and publishes an accept-from record
  that admits it, in dialogs only a person answers (`README.md`, "Pairing with another installation").

Mail from an unlisted root is refused at the relay as `root-not-accepted` and at the edge as `untrusted-root`
(`docs/self-host.md`, section 15; `docs/partner-install.md`, section 5b).

## 4. Keep telemetry off

Telemetry is off until a person turns it on, and a choice is one per machine (`README.md`, "Telemetry"). To keep it
off whatever anyone chooses, set any one of these in the environment of every agent and command line:

- `AC_TELEMETRY=off`;
- `DO_NOT_TRACK`, set to any value but empty, `0`, `false`, `no` or `off`;
- `CI`, the same.

While it is on, one report a day goes to `telemetry.bag.dev`; `c telemetry status` says on or off and what decided
it, and `c telemetry preview` prints the exact report (`README.md`, "Telemetry").

## 5. Never route company data through the public relays without approval

The two public relays, `relay1.bag.dev` and `relay2.bag.dev`, are a free service in a security preview, with no
promise of availability or support, run by the project on single machines outside your network (`README.md`,
"Public relays" and "Limits"). The install guide an agent follows lists them by default. Until your security team
has approved them, point every company identity at company relays only (section 2), and do not list a public relay
in a company identity's address record.

## 6. Behind a company proxy

Where every outbound connection must go through an HTTP proxy, set it in the environment that runs the command
line, the MCP server (the environment the host, such as Claude Code, starts with) and the A2A bridge
(`packages/cli/README.md`, "Behind a proxy"):

```sh
export HTTPS_PROXY=http://proxy.example.corp:3128
export HTTP_PROXY=http://proxy.example.corp:3128
export NO_PROXY=localhost,127.0.0.1,.example.corp
```

- **What goes through it.** `HTTPS_PROXY` carries `https:` and `wss:` relays, `HTTP_PROXY` the `http:` and `ws:`
  ones: the relay calls, the subscription WebSocket, record lookups at relays and telemetry, by CONNECT. Each entry
  point runs itself again once, in the same process, with `NODE_USE_ENV_PROXY=1`, which is what makes Node's fetch
  and WebSocket read the variables; on Windows the command line prints one line asking you to set it yourself. A
  proxy that needs a user and password takes them in its URL (Basic); one that needs NTLM or Kerberos needs a local
  forwarding proxy that speaks it.
- **`NO_PROXY`** is read as Node reads it: `*` for every host; a name or an address for itself only; `.example.corp`
  or `*.example.corp` for its subdomains, not the name itself; `name:port` for that port only; entries split by commas
  or spaces. Company relays on the internal network go in it.
- **A proxy that inspects TLS** presents its own certificates. Give Node the company's root certificate, a PEM file
  from your IT, with `export NODE_EXTRA_CA_CERTS=/path/to/company-root.pem`. Never turn certificate checks off:
  `NODE_TLS_REJECT_UNAUTHORIZED=0` would let anyone on the path read and change what the client sends and gets.
- **What shows it.** `c status --as <name>` prints `network proxy https=<scheme://host:port|none> http=<...>
  no_proxy=<list|none> active=<yes|no: set NODE_USE_ENV_PROXY=1>` when a proxy is set; the MCP server's `status`
  tool has the same under `network`, and its log a `network` line at start. Each names the proxy's scheme, host and
  port, never its user or password. The `NO_PROXY` list appears as written, so it may name internal domains; it stays
  on the machine unless the host's MCP log is sent elsewhere.
- **The one limit.** An organisation's well-known record (an address on its own domain, section 3) is fetched by a
  CONNECT to the address the private-address guard checked, never to the name, so that the guard's pinning holds.
  Many proxies refuse a CONNECT to a bare address; then that lookup fails closed, `resolve-failed: the proxy ...
  refused CONNECT to <address>:443: 403`, and never falls back to the name. Mail under address roots, and under
  domain roots the relay has already resolved, is not affected.
- **A proxy that cuts long WebSockets.** The subscription reconnects with the edge's backoff and resumes from the
  acknowledgement the relay stores; there is no polling fallback.

The install guide an agent follows has the same in its section "Behind a company proxy": the person sets the
variables in the terminal they start Claude Code from, then starts it again in the working folder.

## What this guide does not cover

Approving a relay, a network path or a data flow is your security team's decision, not this guide's. It does not
say which categories a web filter should put bag.dev's hosts in, and it makes no claim about any vendor's product.

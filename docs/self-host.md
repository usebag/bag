# Running your own relay

A guide for running the bag reference relay, `ac-relay`, on a machine you control, and pointing your identities and
agents at it. It is for someone who wants to host and check every service their mail passes through. You do not need a
relay of your own to use bag: two public relays run, and either stands in for one as `--relay` (`README.md`, "Public
relays"). The README, `SECURITY.md` and `spec/SPEC.md` are the authority on what the protocol does; this guide says how
to run this one relay.

How this guide was checked: every command below was run on macOS (Apple silicon) against relays built from this
repository and bound to 127.0.0.1, and its output is quoted as it came, shortened where it says so. The build, the
run and the systemd unit were run again on Linux (section 2 names the machine), and the container route under Docker.
The runs kept their files under a scratch directory, and where a command names a public relay,
`https://relay.example.org` or `https://relay1.example.org`, they used a local one: `http://127.0.0.1:7777`,
`http://127.0.0.1:7778`, or a test TLS name, `https://localhost:9443` (section 5). A step that was not run says
**Not verified**, and why, and a statement taken from the code without a run says *read from the code*.
Run everything from the root of this directory, with the `c` function of `README.md`:

```sh
c() { node packages/cli/src/main.ts "$@"; }
```

`c help` prints every command with its flags, and so does `--help` after any command (read from the code,
`packages/cli/src/cli.ts`).

## Run it with Docker

The shortest way to a relay of your own, for example inside a network whose machines cannot reach the public relays:
build the image from this repository, or pull the published one ("Or pull the published image", below), and start it
with Docker Compose. The host needs Docker with Compose and a clone of this repository (section 3, its first block); no
Rust and no Node. From the root of the clone:

```sh
AC_REV="$(git rev-parse HEAD)" docker compose -f deploy/docker/compose.yml up -d --build
docker compose -f deploy/docker/compose.yml ps
curl -s http://127.0.0.1:7777/v0/health
```

```
 Image bag-relay:local Built
 Volume bag-relay_relay-data Created
 Container bag-relay-relay-1 Started
NAME                STATUS                   PORTS
bag-relay-relay-1   Up 8 seconds (healthy)   127.0.0.1:7777->7701/tcp
{"now":1793709387,"ok":true,"url":"http://127.0.0.1:7777","version":"0.0.0"}
```

(Shortened.) It builds `deploy/docker/Dockerfile`: the relay built with `--release --locked` by the pinned Rust image,
in a distroless image with no shell that runs as a non-root user (65532), about 48 MB, for the platform the build runs
on. `AC_REV` stamps the build with its commit (section 3); left out, it reads `unknown`. The store is the volume
`bag-relay_relay-data`, kept across `down` and `up`: a record published before `docker compose ... down` was served
again after `up -d`. The relay's port is published on this host's loopback only, `127.0.0.1:7777`. The health check is
the relay's own `ac-relay probe` against its port: health, then an envelope from the probe's key to itself, published
and fetched back, once a minute (the key in the volume as `probe.key`). `docker compose ... logs -f relay` follows the
log, and `down` stops and removes the container and keeps the volume.

Point identities and agents at it as section 10 says, with `http://127.0.0.1:7777` as the relay. Section 4's block,
with `R=http://127.0.0.1:7777`, ran from this host against the container: `c health` printed `ok`, the records were
published, and bob read alice's message (`ok 6 lines` from `audit verify`).

For other machines, put a TLS front in front of it. `deploy/docker/compose.tls.yml` adds one, Caddy, with a certificate
from Caddy's own local authority (`tls internal` in `deploy/docker/Caddyfile`), for a network that cannot reach a public
one. With it the relay's port is published nowhere, and the relay trusts Caddy alone as its proxy (section 5):

```sh
export BAG_RELAY_HOST=relay.internal.example BAG_RELAY_URL=https://relay.internal.example
docker compose -f deploy/docker/compose.yml -f deploy/docker/compose.tls.yml up -d --build
docker compose -f deploy/docker/compose.yml -f deploy/docker/compose.tls.yml cp \
  caddy:/data/caddy/pki/authorities/local/root.crt ./bag-relay-root.crt
```

`BAG_RELAY_URL` is the URL your identities' records list, byte for byte (section 5, `--advertise`). Every client must
trust the local authority's root: for the CLI and the MCP server, `NODE_EXTRA_CA_CERTS=<path of bag-relay-root.crt>`
in their environment. Run here with `BAG_RELAY_HOST=localhost`, `BAG_RELAY_URL=https://localhost:18443` and
`BAG_RELAY_TLS_PORT=18443` (port 443 by default): health answered with that URL, section 4's block ran through
`https://localhost:18443`, the subscription included, and a request carrying `X-Forwarded-For: 203.0.113.9` was logged
with the address Caddy saw, never `203.0.113.0/24`.

Inside a network of your own the relay usually has a private address. A sender's edge accepts such a relay when it is
one of its own `--relay` URLs (section 2), so every identity there lists this relay as its own relay, and as its
`--rendezvous` for pairing (section 10).

### Or pull the published image

Instead of building, you can pull the image built from your commit: `ghcr.io/usebag/relay:<commit>`, tagged with the
full 40-hex commit of this repository's main that it was built from. The repository's workflow
`.github/workflows/relay-image.yml` builds it. It is started by hand with one commit of main, builds `linux/amd64` and
`linux/arm64` on GitHub's runners, and attaches build provenance and an SBOM. There is no `latest` tag. Pull by the
exact commit, and use the commit you were given and checked out (section 3), so that the image and the compose files
beside it come from one commit. If `imagetools inspect` answers `not found` for your commit, no image was published for
it: build it as above. The package is public, so none of this needs a login.

```sh
CUT="$(git rev-parse HEAD)"                # the commit you were given, checked out (section 3)
I="ghcr.io/usebag/relay:$CUT"
docker buildx imagetools inspect "$I"
docker buildx imagetools inspect "$I" --format \
  '{{range $p, $v := .Provenance}}{{$p}} {{$v.SLSA.runDetails.metadata.buildkit_metadata.vcs.source}} {{$v.SLSA.runDetails.metadata.buildkit_metadata.vcs.revision}} {{$v.SLSA.buildDefinition.internalParameters.github_workflow_ref}}{{"\n"}}{{end}}'
docker buildx imagetools inspect "$I" --format \
  '{{range $p, $v := .SBOM}}{{$p}} {{$v.SPDX.spdxVersion}} {{len $v.SPDX.packages}} packages{{"\n"}}{{end}}'
docker pull "$I"
```

```
Name:      ghcr.io/usebag/relay:cc4f25dd22448ae066cc99c2195eb9491d6ca24a
MediaType: application/vnd.oci.image.index.v1+json
Digest:    sha256:55bf4f09efd9f7b5b531668d21540c403a99ea16c56cd0df6dc59d2bdd79efe2
  Platform:    linux/amd64
    vnd.docker.reference.type:   attestation-manifest
  Platform:    linux/arm64
    vnd.docker.reference.type:   attestation-manifest
linux/amd64 https://github.com/usebag/bag cc4f25dd22448ae066cc99c2195eb9491d6ca24a usebag/bag/.github/workflows/relay-image.yml@refs/heads/main
linux/arm64 https://github.com/usebag/bag cc4f25dd22448ae066cc99c2195eb9491d6ca24a usebag/bag/.github/workflows/relay-image.yml@refs/heads/main
linux/amd64 SPDX-2.3 15 packages
linux/arm64 SPDX-2.3 15 packages
Digest: sha256:55bf4f09efd9f7b5b531668d21540c403a99ea16c56cd0df6dc59d2bdd79efe2
Status: Downloaded newer image for ghcr.io/usebag/relay:cc4f25dd22448ae066cc99c2195eb9491d6ca24a
```

(Shortened.) What to check:

- **The platforms.** The first command lists each platform's image and its attestation manifest.
- **The provenance.** The provenance line for each platform names the repository, the commit and the workflow that
  built it. The commit must be your `$CUT`. The provenance also records the build argument `AC_REV` as that commit,
  which the relay reports in its metrics (section 8).
- **The SBOM.** It lists the base image's Debian packages: 14 of them, and an entry for the SBOM itself. The relay's
  Rust crates are not in it, and neither is the SQLite compiled into the binary. Those are in `Cargo.lock` at the same
  commit.
- **The digest.** The `Digest:` of the index is what to pin. Whoever can push to the package can move a tag, but not a
  digest.

Compose takes the pulled image through a file you write beside `compose.yml`. It names the image by commit and digest
and removes the build:

```sh
D="$(docker buildx imagetools inspect "$I" --format '{{.Manifest.Digest}}')"
printf 'services:\n  relay:\n    image: %s\n    pull_policy: missing\n    build: !reset null\n' "$I@$D" \
  > deploy/docker/compose.pull.yml
cat deploy/docker/compose.pull.yml
docker compose -f deploy/docker/compose.yml -f deploy/docker/compose.pull.yml up -d
docker compose -f deploy/docker/compose.yml -f deploy/docker/compose.pull.yml ps
curl -s http://127.0.0.1:7777/v0/health
```

```
services:
  relay:
    image: ghcr.io/usebag/relay:cc4f25dd22448ae066cc99c2195eb9491d6ca24a@sha256:55bf4f09efd9f7b5b531668d21540c403a99ea16c56cd0df6dc59d2bdd79efe2
    pull_policy: missing
    build: !reset null
 Container bag-relay-relay-1 Started
NAME                IMAGE                                                                                                                                   ...   STATUS                                     PORTS
bag-relay-relay-1   ghcr.io/usebag/relay:cc4f25dd22448ae066cc99c2195eb9491d6ca24a@sha256:55bf4f09efd9f7b5b531668d21540c403a99ea16c56cd0df6dc59d2bdd79efe2   ...   Up Less than a second (health: starting)   127.0.0.1:7777->7701/tcp
{"now":1793725284,"ok":true,"url":"http://127.0.0.1:7777","version":"0.0.0"}
```

(Shortened.) `ps` showed `healthy` a few seconds later, after the first probe passed.

Every other command in this section works the same way: add `-f deploy/docker/compose.pull.yml` after the other files
and leave out `--build`. With the TLS front, that is
`docker compose -f deploy/docker/compose.yml -f deploy/docker/compose.tls.yml -f deploy/docker/compose.pull.yml up -d`.
`!reset` needs Compose 2.24 or later, as `compose.tls.yml` does. The file is yours: git lists it as untracked. To
upgrade, check out the new commit, set `CUT` and `I` again, pull, write the file again and run `up -d`.

Checked with Docker Engine 29.8.2 and Compose 5.5.0 (OrbStack 2.2.5 on macOS, Apple silicon), which built a
`linux/arm64` image in 2 minutes. The pull route ran with the image of cc4f25dd22448ae066cc99c2195eb9491d6ca24a, the
first one published, from a Docker configuration with no login:

- both platforms and both attestations were listed, and `latest` answered `not found`;
- the `linux/arm64` image pulled (48.1 MB) and printed `ac-relay 0.0.0` for `--version`;
- the relay with the file above came up healthy;
- with `compose.tls.yml` added, `docker compose ... config` showed the pulled image, no build, no published relay port
  and the trusted Caddy address.

**Not verified:**

- a `linux/amd64` build or run here: the base images are multi-platform, and the published amd64 image was listed but
  not run;
- the TLS front started with the pulled image;
- a Linux Docker host;
- clients on other machines;
- a certificate of your own or from a public authority in the front;
- a request that reaches the relay's container address without passing Caddy (the run could not reach it).

For an upgrade, check out the new commit and run the same `up -d --build`; the store migrates forward (section 6).
**Not verified:** an upgrade across commits with this image.

## 1. What your own relay gives you, and what it still sees

A relay stores sealed envelopes and signed records and holds a mailbox open for a subscriber. It cannot read or forge
what passes through it, whoever runs it: the content is sealed to the recipient, and every envelope and record is
signed (`README.md`, "Why"). What changes when you run it is who holds the outer parts and the logs.

| a relay sees | a relay never sees |
|---|---|
| the version, id, sender and recipient addresses, the authority chain (every hop's keys, caveats and expiry), the cipher suite, the timestamp, sizes, timing and the client's IP address | the message type, the thread and the body |

That table is the README's ("How it works"), and `spec/SPEC.md` §10, "Metadata", is its source. With your own relay:

- **Mail to you passes through your relay.** A sender publishes to the relays your signed address record lists. If
  that is only yours, no one else's relay holds your incoming mail, sees who writes to you, or sees their IP addresses.
- **Mail from you does not.** You publish to the relays your recipient lists. Those relays see your address, your IP
  address and the timing, as before. Running a relay does not change that.
- **Pairing goes through a rendezvous relay** (section 10). It sees the opened invitation (a number, the inviter's
  address, the invitation key and the inviter's relays) and both sides' IP addresses, never the code's words or the six
  check digits. Use your own relay as the rendezvous, and it is yours that sees this.
- **Your relay makes outbound calls for domain roots only.** When an accept-from record published to your relay names a
  `domain:` root, your relay looks up the TXT record `_bag.<host>` through the name servers of `/etc/resolv.conf` and
  fetches `https://<host>/.well-known/bag/address.json`. Those hosts and your DNS resolver see your relay's IP address.
  Besides those it calls out only to read Litestream's metrics on the same host, when you pass
  `--metrics-litestream`: no telemetry, no update check (`crates/ac-relay/src/dns.rs`,
  `crates/ac-relay/src/resolver.rs`, `crates/ac-relay/src/metrics.rs`).
- **You set the retention, the limits and the logs.** How long mail is kept (`--ttl`), how much one client may load on
  it (section 7), and whether the log names client addresses at all (`--log-ip none`, section 8).

## 2. What you need

| need | for | notes |
|---|---|---|
| a clone of this repository at the commit you were given, with `npm ci` run in it | the build, and every `c` command: the CLI and the MCP server run from the clone | section 3; Node 24 or later first in `PATH`, and the network once |
| `rustup`, Rust 1.95.0 | building the relay | pinned in `rust-toolchain.toml`; rustup installs it on the first `cargo` call |
| a C compiler | building the relay | SQLite is compiled into the binary from source (`rusqlite` with `bundled`, `crates/ac-relay/Cargo.toml`) |
| `sqlite3` | backups (section 6) | the checks here used `sqlite3` 3.43.2, the one macOS ships |
| Node 24 or later | the CLI and the MCP server | on the machines your identities run on, not on the relay host |
| a public address, a DNS name and a TLS front | a relay that other people reach | section 5; a relay only you reach needs none of these |
| Docker with Compose | the container route, instead of rustup and a C compiler on the relay host | "Run it with Docker", above |

Checked on macOS (Apple silicon), and on Linux: Ubuntu 26.04.1 LTS on arm64, a fresh virtual machine (OrbStack) with
`build-essential`, `git` and `curl` from apt (gcc 15.2.0, git 2.53.0) and Node 24.4.1 from nodejs.org, where sections 3
and 4 were run again from a clone of the public repository. **Not verified:** Linux on x86-64, and other
distributions. Windows is untested (`README.md`, "Limits").

A sender's edge refuses a recipient's relay whose host is a loopback, link-local, private (RFC 1918), unique-local,
multicast or unspecified address, unless it is one of the sender's own `--relay` URLs or the sender passes
`--allow-private-relays` (`packages/edge/src/net.ts`). So a relay that other people send to must have a public
address. A relay on your laptop or your LAN works for you and for peers who pass that flag.

## 3. Build

There is no installer. The relay's packaged form is its container image ("Run it with Docker"); otherwise you build
the relay from source. The CLI and the MCP server run from the npm package `@usebag/bag` through `npx`, or from the
clone (`README.md`, "Quick start" and "From source"); nothing installs them on your `PATH`.

Get the code at the commit you were given, and install the CLI's dependencies. Every `c` command in this guide runs
from this clone (`README.md`, "Quick start", steps 1 and 2, has the git bundle route too):

```sh
git clone https://github.com/usebag/bag bag
cd bag
CUT='PUT THE COMMIT HERE'                  # the 40-hex commit you were given
git checkout --detach "$CUT"
[ "$(git rev-parse HEAD)" = "$CUT" ] && echo "at $CUT"
npm ci                                     # Node 24 or later first in PATH
```

On Linux the block ran as it stands, from a clone of the public repository at its published commit: it printed
`at <the commit>`, and `npm ci` printed `added 201 packages`. On macOS, in a checkout already at its commit, `npm ci`
printed `added 170 packages`.

Then build the relay:

```sh
cargo build --release --locked -p ac-relay
target/release/ac-relay --version          # prints: ac-relay 0.0.0
target/release/ac-relay --help             # every flag, with its default
```

`--locked` builds with the exact crate versions of `Cargo.lock`. The binary is `target/release/ac-relay`; on macOS it
links only the system's own libraries (`otool -L` lists `libiconv` and `libSystem`), and on Linux only glibc's (`ldd`
lists `libc`, `libm` and `libgcc_s`), so you can copy it to where it runs. Build on the machine that runs it, or on one
with the same operating system, CPU and a glibc no older. On the Linux machine, where rustup had no toolchain yet, the
first `cargo` call installed 1.95.0 itself (`the missing active toolchain ... has been auto-installed`), and the build
took 1 minute.

To stamp the build with its commit, set `AC_REV` at build time. The relay then reports it in its metrics as
`ac_relay_build_info{rev="<commit>"}` (section 8), which tells you which cut a running relay was built from; without it
the label reads `unknown` (`crates/ac-relay/src/metrics.rs`):

```sh
AC_REV="$(git rev-parse HEAD)" cargo build --release --locked -p ac-relay
```

## 4. Run

```sh
mkdir -p -m 700 "$HOME/bag-relay"
target/release/ac-relay --port 7777 --db "$HOME/bag-relay/relay.sqlite" 2>>"$HOME/bag-relay/relay.log"
```

Once it listens it prints exactly one line to stdout, and nothing else ever goes there:

```
AC_RELAY_URL=http://127.0.0.1:7777
```

Its log goes to stderr, one JSON object a line. The first line, `listening`, names every setting in force (shortened):

```
{"timestamp":"2026-11-03T00:53:22.884141Z","level":"INFO","fields":{"event":"listening","bind":"127.0.0.1","port":7777,
"url":"http://127.0.0.1:7777","accept_bases":"","db":"...","ttl":604800,"skew":300,"max_envelope_bytes":65536,...,
"connections_per_ip":79,"subscriptions_per_ip":69,...,"log_ip":"prefix","domain_publishes_per_day":10000,
"max_store_bytes":0,...,"txt":"dns"},"target":"ac_relay"}
```

- `--db` is required. The file is created when missing; its directory must exist, or the relay stops at once with a
  `fatal` line naming the file (exit 1). Beside it the relay keeps `relay.sqlite-wal` and `relay.sqlite-shm` while it
  runs, and an empty marker file, `relay.sqlite.volume` (section 6). After a clean stop only `relay.sqlite` and the
  marker remain. The files are created with your umask (`-rw-r--r--` under the usual 022), so keep them in a
  directory of mode 0700, as above.
- `--port 0` picks a free port, which the URL line names. `--bind` defaults to `127.0.0.1`: only this machine can
  reach the relay until you say otherwise (section 5).
- Ctrl-C (SIGINT) or SIGTERM stops it cleanly: it stops accepting, finishes the requests in flight, closes subscribers
  (waiting up to 5 seconds), logs `stopped` and exits 0. Stop it by its process id, `kill -TERM <pid>`, not by name: a
  name also matches other relays on the machine.
- Exit status: 0 after a clean stop; 2 for a bad flag (the message names it); 1 when it cannot start, after a `fatal`
  line, for example a database it cannot open, a port in use (`cannot listen on 127.0.0.1:7777: Address already in use`)
  or a setting out of range (`--ttl must be at least 1 second`).

Check it from a CLI, and with any HTTP client:

```sh
R=http://127.0.0.1:7777
c health "$R"                # prints: ok
curl -s "$R/v0/health"       # {"now":1793667211,"ok":true,"url":"http://127.0.0.1:7777","version":"0.0.0"}
```

`url` is the URL the relay announces (section 5). Then one message through it, as in the README's quick start, with
the identities' keys in a home of their own:

```sh
export AC_HOME="$HOME/bag-test-home"
c keygen alice && c keygen bob                       # each prints the address only
c record address bob --relay "$R" --sealing-key --out "$AC_HOME/bob.json" && c publish "$R" "$AC_HOME/bob.json"
c record accept-from bob --root "$(c address alice)" --max-bytes 65536 --ttl 604800 \
  --out "$AC_HOME/bob.accept.json" && c publish "$R" "$AC_HOME/bob.accept.json"
c send --as alice --to "$(c address bob)" --relay "$R" --type chat.v1 --body '{"text":"hi"}'
c inbox --as bob --relay "$R" --once --trust-root "$(c address alice)"
c audit verify "$AC_HOME/state/bob/audit.jsonl"
```

```
ok address ed25519:741dc969...
ok accept-from ed25519:741dc969...
66370f86d0ff3ea729f125a5399855f3859e10b161500b93317be1a3987c3a24
published http://127.0.0.1:7777 tries=1
accept 66370f86... ed25519:6dd50106... ed25519:6dd50106... chat.v1 {"text":"hi"}
ok 6 lines
```

The relay logged one `publish-record` line per record, a `publish` line for the envelope (its id, `from`, `root`,
`duplicate`, `delivered` and the client's address as `127.0.0.0/24`), and `subscribe` and `subscribe-closed` lines for
bob's read.

### Keeping it running

The repository ships no service file. A supervisor you already use can run the command above.

A systemd unit for a relay behind a TLS front on the same host (section 5), run as its own user with its state in
`/var/lib/bag-relay`. Make the user first (`useradd --system bag-relay`), put the binary at `/usr/local/bin/ac-relay`
(`install -m 0755 target/release/ac-relay /usr/local/bin/ac-relay`), write the unit to
`/etc/systemd/system/bag-relay.service`, then `systemctl daemon-reload` and `systemctl enable --now bag-relay`:

```ini
[Unit]
Description=bag relay
After=network-online.target
Wants=network-online.target

[Service]
User=bag-relay
StateDirectory=bag-relay
StateDirectoryMode=0700
ExecStart=/usr/local/bin/ac-relay --bind 127.0.0.1 --port 7777 --db /var/lib/bag-relay/relay.sqlite --advertise https://relay.example.org --trust-proxy 127.0.0.1 --client-ip-header x-forwarded-for
Restart=on-failure
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
```

systemd sends SIGTERM to stop a service, which the relay handles as above, and the journal keeps its stdout and stderr.
The unit ran as written on the Linux machine of section 2 (systemd 259). systemd made `/var/lib/bag-relay` with mode
0700, owned by `bag-relay`; `curl -s http://127.0.0.1:7777/v0/health` answered with `"url":"https://relay.example.org"`;
and `journalctl -u bag-relay` held the `AC_RELAY_URL=` line and the JSON log. Section 4's block, with
`R=http://127.0.0.1:7777`, ran against it, and again through the Caddy front of section 5. `systemctl stop bag-relay`
logged `stopped`, systemd recorded exit status 0, and only `relay.sqlite` and its marker were left. The first start
came about two minutes after `enable --now`, the wait for `network-online.target` on that machine; a restart took a
second.

## 5. A name, TLS, and the proxy in front

The relay speaks plain HTTP and WebSocket on one port and has no TLS of its own. For a relay others reach, put a TLS
front in front of it (a reverse proxy, a load balancer, a tunnel) that forwards to the relay's port and passes WebSocket
upgrades on `/v0/subscribe`. Keep the relay bound to `127.0.0.1` (or the private interface the front reaches it on),
so no client can reach it around the front.

Clients on a company network may reach the relay through their own outbound proxy (`HTTPS_PROXY`, by CONNECT; the
clients' side is in `packages/cli/README.md`, "Behind a proxy"). The relay needs nothing for them. A proxy that
inspects TLS and does not pass WebSocket upgrades stops their subscription: they can still publish and fetch, but they
receive nothing until their proxy passes `/v0/subscribe`.

Three flags tell the relay about its front:

- **`--advertise <url>`**: the URL the relay prints and `/v0/health` answers, `http://<host>[:<port>]` or
  `https://<host>[:<port>]`. A port written in it is kept; without one, `https` is announced with none and `http`
  with the listening port. It is also the base a fetch proof must name: an identity's client signs the relay URL as its
  address record lists it, and the relay compares that byte for byte with `--advertise` and each `--accept-base`, never
  with a `Host` or forwarded header (`spec/SPEC.md` §8.3, Appendix B item 17; read from the code: no CLI command
  fetches by id, so a mismatch was not run). So write it exactly as your records list the relay: lower case, no
  `:443`, no trailing slash, `https://relay.example.org`.
- **`--accept-base <url>`**: another base a fetch proof may name, for a relay's second name while it moves; repeatable.
  It must be a `relays` entry (a lower-case host, no default port, no path), or the relay exits 2: that ran here, and
  `https://Relay.example.org` and `https://relay.example.org:443` were each refused with exit 2. Give each name to one
  relay only: a base two relays both accept would let a proof made for one be replayed to the other.
- **`--trust-proxy <cidr>`** and **`--client-ip-header <name>`**: a request whose TCP peer is inside a trusted network
  counts and logs as the client the header names. The header's values are read from the right, trusted addresses
  skipped, so with `x-forwarded-for` the client is the right-most address that is not a trusted proxy's; a value that
  is not an address leaves the proxy as the client. Without `--trust-proxy` no header is read, and every client
  behind the front shares one set of per-address limits. The default header is `cf-connecting-ip`, the one
  Cloudflare's tunnel sets; `--client-ip-header` without `--trust-proxy` exits 2 (`crates/ac-relay/src/net.rs`).
  Trust only the address your front connects from.
- **The front must set that header itself on every request.** It overwrites or strips any value a client sent, or,
  with `x-forwarded-for`, adds the address it saw as the last entry, so that the right-most entry is its own (read
  from the code). The relay believes whatever a trusted peer passes on, so a front that forwards a client's own header
  lets any client choose the address it is counted and logged as, which defeats the per-address limits. Run here
  with `--trust-proxy 127.0.0.1` and the default header: a request from `127.0.0.1` carrying
  `cf-connecting-ip: 203.0.113.9` was logged as `"ip":"203.0.113.0/24"`.

Checked here with a test TLS terminator on `127.0.0.1:9443` (a few lines of Node that pass the bytes to the relay;
it is not part of this repository) and a self-signed certificate for `localhost`, given to the CLI with
`NODE_EXTRA_CA_CERTS`:

```sh
target/release/ac-relay --port 7780 --db "$HOME/bag-relay/relay.sqlite" --advertise https://localhost:9443 \
  --trust-proxy 127.0.0.1 --client-ip-header x-forwarded-for
# prints: AC_RELAY_URL=https://localhost:9443
```

`c health https://localhost:9443` printed `ok`. Records were published, and a message sent and read, through
`https://localhost:9443` as in section 4, the subscription going over the TLS front too. A request from `127.0.0.1` with
`x-forwarded-for: 198.51.100.7` was logged with `"ip":"198.51.100.0/24"`, and one without the header as
`"ip":"127.0.0.0/24"`.

A production proxy, for example Caddy, which obtains a certificate for the name, sets `X-Forwarded-For` and passes
WebSocket upgrades in its `reverse_proxy`:

```
relay.example.org {
	reverse_proxy 127.0.0.1:7777
}
```

with the relay started as in the systemd unit above. On the Linux machine of section 2 this ran with Ubuntu's `caddy`
package (2.6.2) and one line added inside the block, `tls internal`, since `relay.example.org` cannot get a public
certificate: an `/etc/hosts` line sent the name to 127.0.0.1, and the CLI trusted Caddy's local root through
`NODE_EXTRA_CA_CERTS`. `c health https://relay.example.org` printed `ok`, section 4's block ran through it, the
subscription included, and a request carrying `X-Forwarded-For: 203.0.113.9` was logged as `"ip":"127.0.0.0/24"`, the
address Caddy saw: Caddy did not pass the client's value on. The container route ("Run it with Docker") ran Caddy 2.11.6
the same way. **Not verified:** a certificate from a public authority, and any other proxy; check in your front's own
documentation that it replaces or appends to a client's `X-Forwarded-For` as above.

Whatever the front, the relay pings each subscriber every 30
seconds (`--ping-interval`), so the front must keep an idle WebSocket open longer than that. It must answer at the
relay's URL itself, never with a redirect: no edge follows a redirect from a relay.

## 6. Storage, backups and restore

The store is one SQLite file in WAL mode, schema version 5 (`PRAGMA user_version`), with SQLite compiled into the
relay (`crates/ac-relay/src/store/sqlite.rs`). It holds envelopes, mailbox rows and cursors, acknowledgements,
records, tombstones of swept ids, pending rows, revoked lists and domain pins. An envelope expires 7 days after it
arrives by default (`--ttl`), or sooner when its recipient's accept-from record says so; reading it does not delete it.
The sweep removes what expired every 60 seconds (`--sweep-interval`). A restart keeps the whole store; it loses only
what lives in memory: the rate counters, the open pairing codes and the push to live subscribers, who reconnect
(`spec/SPEC.md` Appendix B item 102).

Opening an older database migrates it forward. A database whose schema is newer than the relay's is refused, so an
older relay never writes one it does not understand:

```
{"level":"ERROR","fields":{"event":"fatal","error":"store: the database's schema is version 6, newer than this
relay's 5: run the ac-relay that wrote it, or a newer one (...)"}}
```

### Backup

Copy a running relay's database with SQLite's own backup, never with `cp`: until a checkpoint, recent writes are in
`relay.sqlite-wal`, not in `relay.sqlite`.

```sh
DB="$HOME/bag-relay/relay.sqlite"
mkdir -p -m 700 "$HOME/bag-relay-backups"
BK="$HOME/bag-relay-backups/relay-$(date -u +%Y%m%dT%H%M%SZ).sqlite"
sqlite3 "$DB" ".backup '$BK'"
sqlite3 "$BK" 'PRAGMA integrity_check; PRAGMA user_version;'      # prints: ok, then 5
```

This ran against a live relay. The backup holds sealed mail and records, the same as the relay: keep it as you keep
the relay's disk. Opening the copy leaves an empty `-wal` and a `-shm` file beside it; the `.sqlite` file is the backup.

Two settings live beside the database, not in it: the blocklist file (`--blocklist`, section 9) and any queued pin
resets (`<db>.pin-resets`). Back them up too.

**Not verified:** continuous replication. The project's public relays stream their database to object storage with
Litestream (`README.md`, "Limits"); `--metrics-litestream` passes Litestream's metrics on (section 8). This guide does
not cover it.

### Restore

Stop the relay, move the old database, its `-wal`, `-shm` and `.volume` files out of the way, copy the backup in,
and start the relay with the same flags:

```sh
kill -TERM "$RELAY_PID"                     # the running relay's process id
mkdir -p -m 700 "$HOME/bag-relay/replaced"
for f in "$DB" "$DB-wal" "$DB-shm" "$DB.volume"; do [ -e "$f" ] && mv "$f" "$HOME/bag-relay/replaced/"; done
cp "$BK" "$DB"
target/release/ac-relay --port 7777 --db "$DB" 2>>"$HOME/bag-relay/relay.log"
```

The relay noticed the restore and logged:

```
{"level":"WARN","fields":{"event":"cursors-raised","mailboxes":3,"by":1048576}}
```

A message sent before the backup and never read was then read with `c inbox --once`, a new message went through, and
`audit verify` printed `ok 18 lines`.

How it notices: on its first start the relay marks the database (its `application_id`, which a copy keeps) and the
volume (the empty `.volume` file, which a copy leaves behind). A marked database with no marker beside it is a restore,
and on that start the relay raises every mailbox's next cursor by 2^20 (1,048,576), past any number it may already
have handed out. This is defence only: an edge decides delivery by envelope id, not by cursor. A restore in place that
keeps the old `.volume` file is not noticed, which is why the steps above move it; a second raise loses nothing.

What a restore loses: the mail the relay took after the backup. It still reaches a recipient who lists a second
relay that took it (section 11). A sender keeps the exact bytes of an envelope in its outbox until a relay takes
it, so mail that no relay took is published again by the sender's edge.

## 7. Limits

Each limit is a flag; the defaults are the reference relay's and the public relays'. A rate or a quota counts per
client: an IPv4 address, or an IPv6 /56. The connection caps count per IPv4 address or IPv6 /64. Behind a trusted
proxy the client is the one its header names (section 5), the proxy's own connections are not counted, and each
client's WebSockets are. Counters live in memory and start empty at every start.

| flag | default | what it bounds |
|---|---|---|
| `--rate-window` | 60 | the length in seconds of the fixed windows that the three publish rates and `--fetch-per-ip` count in |
| `--rate-per-from` | 120 | envelopes one `from` key may publish in a window, and records one signer may |
| `--rate-per-root` | 1,200 | envelopes published under one root in a window |
| `--rate-per-ip` | 600 | publishes one client may make in a window, counted before any signature is checked |
| `--fetch-per-ip` | 6,000 | fetches of envelopes and records one client may make in a window |
| `--fetch-global-per-minute` | 30,000 | fetches from all clients together in a minute; 0 turns it off |
| `--record-signers-per-day` | 100 | new record signers (keys the relay holds no record of) one client may bring in a UTC day |
| `--bytes-per-ip-per-day` | 100,000,000 | bytes of envelopes one client may store in a UTC day; 0 turns it off |
| `--domain-publishes-per-day` | 10,000 | envelopes one sender domain may publish in a UTC day; 0 turns it off |
| `--connections-per-ip` | 79 | connections one client may hold open at once |
| `--connection-reserve-permille` | 125 | the share of that cap a direct client's subscriptions may not take, kept for its calls (69 subscriptions at the defaults) |
| `--max-store-bytes` | 0 (no bound) | the live bytes of the store from which a new envelope, or a record of a signer the relay holds none of, is refused |
| `--max-envelope-bytes` | 65,536 | the largest envelope, at most 262,144 |

Past a rate or a quota the relay answers 429 `rate-limited` with `Retry-After`, and logs `rate-limited` with the
`limit` it hit: `from`, `root`, `ip`, `fetch`, `fetch-global`, `record-signers`, `bytes`, `domain` or `pairing`. With
`--rate-per-from 2`, the third envelope from one key within the minute:

```
retry http://127.0.0.1:7779 tries=1 reason=rate-limited next_at=1793667480
bag: rate-limited: http://127.0.0.1:7779 retry; the bytes stay in the outbox, and resend --id 415704ea... sends them
```

```
{"fields":{"event":"rate-limited","limit":"from","from":"ed25519:7e48848a...","root":"ed25519:7e48848a...",
"size":1023,"ip":"127.0.0.0/24","retry_after":9}}
{"fields":{"event":"publish-refused","status":429,"code":"rate-limited","ip":"127.0.0.0/24"}}
```

At `--max-store-bytes` the relay refuses new envelopes from everyone, and records from signers it does not yet hold,
with 503 `store-full` and a `Retry-After` of one sweep interval (`--sweep-interval`), until mail expires or you raise
the bound; a signer it holds may still update its records, and fetch, subscribe and the sweep go on. The bound counts
the pages in use, not the file, which keeps its largest size.
Leave room on the disk for the write-ahead log: the flag's help suggests 900000000 on a volume of 1 GB. With
`--max-store-bytes 50000` on a store of 90,112 live bytes:

```
retry http://127.0.0.1:7779 tries=1 reason=store-full next_at=1793667544
{"level":"WARN","fields":{"event":"store-full","live":90112,"max":50000,"retry_after":60}}
```

Past `--connections-per-ip`, a direct client's next connection is closed as soon as the relay accepts it, before any
request is read, so it gets no HTTP answer: the CLI reports that as `unreachable`. The relay logs `connection-refused`
with `reason` `connections-per-ip` and `open`, the cap. A subscription is refused after its WebSocket upgrade instead,
with the error frame `{"t":"error","error":"rate-limited"}` and the close code 1013 (try again later): a direct
client's subscription past the cap less the share `--connection-reserve-permille` keeps for its calls (69 at the
defaults; `reason` `subscriptions-per-ip`), or, behind a trusted proxy, a client's WebSocket past
`--connections-per-ip` (`reason` `connections-per-ip`). Both count in `ac_relay_connections_refused_total` by
`reason` (read from the code: `crates/ac-relay/src/server.rs`, `crates/ac-relay/src/ws.rs`,
`packages/edge/src/adapters/http-relay.ts`). Behind a front that is not in `--trust-proxy`, every connection counts as
the front's own, so at the default of 79 the front's 80th open connection is closed this way.

Fixed in the code, not flags: a request body is at most 262,144 bytes and a record at most 131,072
(`crates/ac-relay/src/config.rs`); a subscription has at most 32 envelopes sent and not yet acknowledged; one publish
resolves at most 8 domains; a pairing code lives at most 600 seconds, a client may hold 16 open and the relay 10,000,
and a client may claim 5 a second, 10 at once (`crates/ac-relay/src/pair.rs`).

## 8. Health, metrics and logs

**Health.** `GET /v0/health` answers 200 with `ok`, `version`, `now` and `url`, as in section 4. It says the process
answers, not that a message goes through. For that, the relay has its own probe:

```sh
target/release/ac-relay probe https://relay.example.org --key "$HOME/bag-relay-probe.key"
```

It makes the key file (mode 0600) when it is missing, publishes the probe's accept-from record when the relay holds
none, sends one envelope to itself and fetches it back, each call within 5 seconds, and prints `probe ok <id>` with
exit 0, or `probe: <step>: <what>` with exit 1. The key has no authority; use one per relay you watch. Its fetch names
the URL that health answers, so it passes whatever name you probe by: it does not check that your records' URL
matches `--advertise`; compare health's `url` with your records for that. Against the test relay:

```
probe ok 8cd57459f747a3545b8b33d8425d5f296798b79b504264d0cfe193f9e53041ee
probe: health: io: Connection refused (os error 61)        # against a port with no relay: exit 1
```

**Metrics.** `--metrics-port <port>` opens a second listener that answers `GET /metrics` in Prometheus's text format,
and nothing else; on `--metrics-bind`, `127.0.0.1` by default. The relay's own port answers `/metrics` with 404.
With `--metrics-port 9464`:

```sh
curl -s http://127.0.0.1:9464/metrics
```

One scrape, taken just after a restart, served these families: `ac_relay_publishes_total`, `ac_relay_fetches_total`, `ac_relay_record_fetches_total`,
`ac_relay_subscribes_total`, `ac_relay_deliveries_total`, `ac_relay_rate_limited_total`,
`ac_relay_connections_refused_total`, `ac_relay_connections_accepted_total`, `ac_relay_connections_open`,
`ac_relay_subscriptions_open`, `ac_relay_signature_failures_total`, `ac_relay_new_signers_total`,
`ac_relay_first_subscribes_total`, `ac_relay_blocked_total`, `ac_relay_blocklist_invalid_total`,
`ac_relay_domain_resolutions_total`,
`ac_relay_resolutions_capped_total`, `ac_relay_pending_dropped_total`, `ac_relay_proxy_header_ignored_total`,
`ac_relay_pair_opens_total`, `ac_relay_pair_claims_total`, `ac_relay_nameplates_open`, `ac_relay_store_errors_total`,
`ac_relay_store_full_total`, `ac_relay_store_corrupt_total`, `ac_relay_store_bytes`, `ac_relay_store_live_bytes`,
`ac_relay_store_envelopes`, `ac_relay_store_mailbox_rows`, `ac_relay_store_records`, `ac_relay_store_domain_pins`,
`ac_relay_sweeps_total`, `ac_relay_swept_total`, `ac_relay_sweep_last_duration_microseconds`,
`ac_relay_mailboxes_subscribed_today`, `ac_relay_client_networks_today`, `ac_relay_limit` (one series per limit in
force), `ac_relay_build_info`, `process_start_time_seconds`, and after the first requests
`http_server_request_duration_seconds` by route and status. A label is always a route, a code, a limit, a reason or a
status from a closed set, never an address, an id or an IP address; the two `_today` gauges count distinct mailboxes and
client networks through a hash under a key that lives in memory for one UTC day (`crates/ac-relay/src/metrics.rs`).
`ac_relay_first_subscribes_total` counts subscriptions answered `ok` to a mailbox that no envelope has reached at this
relay, each mailbox once a UTC day through the same kind of hash, with no mark of any mailbox stored: setups whose
agent host is wired and started. Four things make it differ from installs: a fresh install that receives nothing
counts once on each day it subscribes, and again after a relay restart that day; a relay that is a pairing rendezvous
also counts each invitation's mailbox, so a relay that is not one gives the clean count; a relay restored from a copy
that lacks a mailbox's cursor row counts that mailbox again, since its last cursor reads 0 there; and a mailbox that a
peer wrote to before its first subscribe never counts. The count is per relay: a mailbox subscribes at each relay it
lists, so never add two relays' counts. Whoever reads `/metrics` as a known mailbox subscribes can tell whether
anything had reached that mailbox at this relay; only the metrics listener's network reaches it, and the store already
holds that fact.
The counts start at 0 with the process. That list is a snapshot of one run: some families appear only after their
first event, among them `ac_relay_connection_timeouts_total` and `ac_relay_subscriptions_closed_total`, each by
`reason`, and with `--metrics-litestream` the relay adds `ac_relay_litestream_up` (1, or 0 when the read failed) and
Litestream's own `litestream_*` lines (read from the code: `crates/ac-relay/src/server.rs`, `crates/ac-relay/src/ws.rs`,
`crates/ac-relay/src/metrics.rs`).

**Logs.** One JSON object a line on stderr: `timestamp`, `level`, `target`, and `fields` with an `event`. The relay does
not rotate or delete its log; keep it as long as your own rules say. `docs/partner-install.md`, section 3, "What the
relay logs", lists the events you will see first. Besides those, this guide's runs logged `store-size` (the store's
bytes and row counts, after the first sweep and then every 60 sweeps, hourly at the default interval), `sweep`,
`cursors-raised`, `store-full`, `blocklist`, `blocked` and `pair-open`.

Six of those events are the ones an operator acts on, with what each names (read from the code:
`crates/ac-relay/src/http.rs`, `crates/ac-relay/src/ws.rs`, `crates/ac-relay/src/server.rs`,
`crates/ac-relay/src/main.rs`):

| event | level | what it means |
|---|---|---|
| `fetch` | INFO | an envelope was fetched by its id: the `id` and the `signer` of the proof |
| `fetch-refused` | INFO | a fetch by id was refused: the `id`, the `status`, the `code` and the `signer`; a `bad-auth` here can be the URL check of section 5 |
| `subscribe-refused` | INFO | a subscriber's auth frame was refused: the `code` and the client's `ip`; the subscriber got an error frame with the code and the close code 4001 |
| `connection-refused` | INFO | a connection or a subscription over its cap was closed: the client's `ip`, `open` (the cap) and the `reason`, `connections-per-ip` or `subscriptions-per-ip` (section 7) |
| `fatal` | ERROR | the relay stopped on an error, at its start (the database, the port, a setting, a newer schema) or when its listener failed: `error` names it, and the exit status is 1 |
| `stopped` | INFO | a clean stop finished, after SIGINT, SIGTERM or, with `--exit-on-stdin-eof`, the end of stdin: the last line, and the exit status is 0 |

What a line names: envelope ids, addresses (public keys), mailboxes, record kinds, codes, cursors, and the client's
address. What no line holds: a message body, a plaintext, a record's bytes or a key. `--log-ip` sets how the client's
address is written:

| `--log-ip` | written as |
|---|---|
| `prefix` (the default) | its /24 for IPv4, its /48 for IPv6: `127.0.0.0/24` |
| `full` | the whole address |
| `none` | `-` |

With `--log-ip none` a refused publish was logged as `{"event":"publish-refused","status":400,"code":"bad-shape",
"ip":"-"}`. The relay still uses the address in memory to count its limits.

## 9. Abuse controls

`--abuse-contact <uri>` is what `GET /v0/abuse` answers; without it that call is 404 `not-found`. With
`--abuse-contact mailto:abuse@example.org` it answered `{"contact":"mailto:abuse@example.org"}`.

`--blocklist <file>` names a file of one `ed25519:<64 hex>` address or `domain:<host>` root a line (`#` starts a
comment). Edit it with `ac-relay block`, which writes the file whole and renames it into place, so the relay never
reads half a file; the relay reads it again on the next publish after it changes, with no restart:

```sh
target/release/ac-relay block "$HOME/bag-relay/blocklist.txt" +ed25519:3c777790...   # add; prints the list
target/release/ac-relay block "$HOME/bag-relay/blocklist.txt" -ed25519:3c777790...   # remove
target/release/ac-relay block "$HOME/bag-relay/blocklist.txt"                        # list; writes nothing
```

After the first edit, that sender's next envelope was refused 403 `not-authorized`, and the relay logged
`{"event":"blocklist","entries":1,...}` and `{"event":"blocked","key":"ed25519:3c777790..."}`. A listed key's
envelopes, chains and records are refused; mail to a listed key is not. A `domain:` entry works only once the relay has
resolved that domain, so list the domain's key as well (`docs/audit/threat-model.md`, R11). A file that stops
parsing keeps the last good list and logs `blocklist-invalid`.

## 10. Pointing your identities and agents at it

An identity uses a relay once its signed records name it and sit on it. The steps below set up a new identity on your
relays. **Not verified:** moving an identity whose records already list other relays.

### With the command line

Use the home this identity will live in. With no `--dir` and no `AC_HOME`, the CLI uses `$HOME/.bag`, the home the
install page uses too (`packages/cli/src/home.ts`). If you exported `AC_HOME` for the test in section 4, unset it
first. Make the identity, then publish its first key record and its address record at each of your relays:

```sh
unset AC_HOME                              # back to $HOME/.bag; the run used a scratch home instead
R1=https://relay1.example.org
R2=https://relay2.example.org
c keygen me
c keys rotate me --relay "$R1" --relay "$R2"
```

```
published key ed25519:7459099a... http://127.0.0.1:7777
published key ed25519:7459099a... http://127.0.0.1:7778
published address ed25519:7459099a... http://127.0.0.1:7777
published address ed25519:7459099a... http://127.0.0.1:7778
epoch 1 ed25519:7459099a... until 2026-11-04T00:56:02Z
```

(The run used two local relays, as the output shows.) `keys rotate` publishes no accept-from record. Until one is
published at a relay, by pairing (below) or by `c record accept-from` and `c publish` as in section 4, that relay
refuses mail to the identity with 403 `not-hosted` (section 15). A send to this identity at that point printed:

```
failed http://127.0.0.1:7777 tries=1 reason=not-hosted
```

The records must be signed again before they lapse. The key record lives a day, and a new one is made once the newest
is 12 hours old; the address record lives a day at most. So run `c record keep --once` at least every 11 hours
(`packages/cli/src/cli.ts`, `keys rotate`), or leave `c record keep` running (`docs/partner-install.md`, section 4).
The MCP server below does the same while it runs, with `--keep-alive-records`; beside it, `record keep` stands aside
and prints `held session-open`. For the hours the server does not run, `--crontab` prints a crontab line that runs
`record keep --once` four times a day, 6 hours apart, and writes nothing:

```sh
c record keep --as me --relay "$R1" --relay "$R2" --crontab
```

```
49 2,8,14,20 * * * <node> <repo>/packages/cli/src/main.ts record keep --as me --relay https://relay1.example.org
--relay https://relay2.example.org --dir <home> --once >> <home>/keep.log 2>&1
```

(One line, shortened here; the minute is drawn at random.) To install it:
`(crontab -l 2>/dev/null; c record keep --as me --relay "$R1" --relay "$R2" --crontab) | crontab -`. On macOS,
`--plist` prints a launchd job instead (read from the code, `packages/cli/src/commands/keep-schedule.ts`). **Not
verified:** installing the line or the job; the run only printed the line, to leave this machine's crontab alone. Cron
skips a run the machine sleeps through.

### Claude Code: `host install`

```sh
PROJECT="$HOME/bag-work"                    # the folder you start Claude Code in; it must exist
c host install claude-code --as me --relay "$R1" --relay "$R2" --rendezvous "$R1" --project "$PROJECT"
```

```
wrote <project dir>/.mcp.json
  {"bag":{"command":"<node>","args":["<repo>/packages/mcp/src/main.ts","--as","me","--relay","http://127.0.0.1:7777",
  "--relay","http://127.0.0.1:7778","--rendezvous","http://127.0.0.1:7777","--dir","<home>","--keep-alive-records"]}}
wrote <project dir>/.claude/settings.json
  {"SessionStart":[{"hooks":[{"type":"command","command":"<node> <repo>/packages/cli/src/main.ts wake-hook --as me
  --dir <home>","timeout":3600,"asyncRewake":true}]}],"Stop":[...the same hook...]}
```

That run predates the day-long wait: the hook `host install` writes now ends `--dir <home> --max 86000` and has
`"timeout":86400`, so an idle session gets one wake a day instead of one an hour, and goes deaf after about two days of
silence instead of two hours (read from the code, not run here; `packages/cli/README.md`, "Waking a session"). An
earlier install keeps 3600 until you run the same `host install` command again, which replaces that hook and prints it
as `removed`; then restart Claude Code in the project.

A second run printed `unchanged` for both files and `nothing to change`. What it writes, read from
`packages/cli/src/commands/host-install.ts` and checked by listing the files that changed: `$PROJECT/.mcp.json`,
`$PROJECT/.claude/settings.json`, and once per machine the empty file `$HOME/.bag/telemetry-noticed-2`, when it
prints the telemetry notice. Nothing it writes holds a key. The run used an empty home directory and a scratch
project, so no real Claude Code configuration was touched.

**Not verified:** Claude Code itself was not started, to keep the check isolated. Instead the server that
`.mcp.json` names was started by hand with those arguments, over stdio: it listed its tools, and its `status` tool
showed both relays with `"state":"subscribed"`. In Claude Code, start a session in the project directory, approve
the bag server, and ask for the bag status.

### The agent install and `bag-install.env`

The install page at [bag.dev/install](https://bag.dev/install), which a coding agent follows, writes a settings file,
`$HOME/bag-install.env`, in its step 2, and every later step reads it. Two of its lines choose the relays:

```sh
RELAYS="https://relay1.example.org https://relay2.example.org"
RENDEZVOUS="https://relay1.example.org"
```

`RELAYS` is every relay the identity lists, passed to each command as `--relay` by the file's `relays` function;
`RENDEZVOUS` is the relay pairing codes meet at, passed to `host install` as `--rendezvous`. The page writes the two
public relays there and tells the agent to use only those. To install against your own relays, change the two lines
after step 2 writes the file and before step 3 makes the identity, and run the page's commands yourself, or use the
command-line route above. With a settings file naming two local relays, the page's commands for steps 2c (`c health`
on each relay), 3 (`c keygen`, `c keys rotate`) and 6 (`c host install ... $(relays) --rendezvous "$RENDEZVOUS"`) ran
and printed what this section shows. **Not verified:** an agent following the page with the changed file.

### The rendezvous relay, for pairing

Pairing (`README.md`, "Pairing with another installation") opens an invitation at a rendezvous relay and claims it
there. Every reference relay serves it (`POST /v0/pair/open`, `GET /v0/pair/claim/{n}`). Which relay is the rendezvous:

- `c peer invite` and `c peer accept`: `--rendezvous`, else the `--relay` given (`packages/cli/src/commands/peer.ts`).
- The MCP server's `pair_invite` and `pair_accept`: `--rendezvous`, else its first `--relay`
  (`packages/mcp/src/config.ts`); `host install --rendezvous` passes it on.
- Both sides must use the same one. When they do not, the side that accepts writes the inviter's rendezvous after the
  code, `<code>@<host>` or `<code>@<host>:<port>`, and the code is claimed at `https://<host>`
  (`packages/edge/src/pair-code.ts`).

Both ways ran here. Two identities in two homes paired through the test relay as their rendezvous, then sent each other
mail by petname. And an inviter on the TLS-fronted relay of section 5 paired with an acceptor whose own relay was
another one, the acceptor typing the code as `<code>@localhost:9443`; that acceptor also passed
`--allow-private-relays`, needed only because `localhost` is a loopback name. In the first pairing the inviter's side
printed:

```
pairing code <code>
one request until 2026-11-03T01:04:45Z; the other side reads you six digits, and you type them here
request ed25519:5a187ecb...
to pair with it as ben, type the six digits the other side reads you
paired ben ed25519:5a187ecb...
```

and the acceptor's:

```
inviter ed25519:a28d281d... at http://127.0.0.1:7777
check digits <six digits>
read them out now, not where the code was sent, before you answer: that is the security check
pair with it as ana? [y/N] y
requested; waiting until 2026-11-03T01:04:45Z for the inviter's answer
paired ana ed25519:a28d281d...
```

Open codes live in the relay's memory for at most 600 seconds, so a restart of the rendezvous relay drops them, and a
code claimed after that is 404 `no-nameplate`. Do not restart or upgrade the rendezvous while someone pairs.

### Records at your origin

An organisation can have its agents trusted by its domain rather than address by address. It serves its signed
address record, the org record, at `https://<host>/.well-known/bag/address.json`, and a recipient names
`domain:<host>` as a root in its accept-from record (`c record accept-from ... --root domain:<host>`) or in its inbox
(`--trust-root <host>`). A relay that holds such a record fetches the org record and pins its key (section 1). Two
more pieces are optional: one DNS TXT record at `_bag.<host>`, `v=ac1; key=<org key>` (with `; host=bag` when the
files are served at `https://bag.<host>` instead), which names the key the org record must carry; and handle records at
`/.well-known/bag/handles/<local>.json`, which give agents names such as `jane@example.org`. `docs/onboarding.md` does
all of this with one command, `onboard`, and says what to serve and what to add to DNS; `docs/partner-install.md`,
section 6, does it by hand.

What `docs/onboarding.md` leaves out (read from the code, not run here):

- **What a reader fetches.** Your relay, and a sender's edge, read the org record over HTTPS only, from a host whose
  every address is public, and follow no redirect: any status but 200 fails, a 3xx included. They read at most 262,144
  bytes (256 KiB), within 10 seconds by default; at the relay that is `--well-known-timeout`, which the TXT lookup and
  the fetch share. A domain has at most one TXT record that starts `v=ac1`: two, or a malformed one, fail the
  resolution, and other TXT records at that name are ignored. The relay remembers a failed resolution for 60 seconds
  (`crates/ac-relay/src/resolver.rs`, `packages/edge/src/adapters/well-known.ts`, `packages/core/src/discovery.ts`).
- **Checking it from outside.** `c lookup domain:<host> --as <name> --relay <url>` resolves the domain as a sender's
  edge does. It prints a `cache` line, then one line for the TXT record and one for the org record at the origin,
  `<source> <found|none|refused|error> kind=<k> ...` (`packages/cli/src/commands/lookup.ts`).
- **Sending under the domain.** The org key signs one hop to the agent's address with `delegate`, and the agent sends
  under that chain with `send --auth`. With an org key named `org`, an agent named `agent` and a recipient's handle:

  ```sh
  c delegate --from org --to "$(c address agent)" --exp +86400 --out agent.chain.json
  c send --as agent --auth agent.chain.json --to ben@example.net --relay "$R1" --type chat.v1 --body '{"text":"hi"}'
  ```

  `delegate` prints the subject, then `root <address> hops <n> exp <seconds> caveats <JSON list>`. A relay delivers the
  envelope to a recipient whose accept-from record names `domain:<host>` when the chain's root, the org key, is that
  domain's current key (`packages/cli/src/cli.ts`, `crates/ac-relay/src/policy.rs`).

## 11. Two relays

Relays never exchange mail. Redundancy comes from an identity listing two relays in its address record: a sender
publishes the same bytes to up to three of the relays its recipient lists, and the recipient reads every relay it lists
and drops a second copy by its id (`spec/SPEC.md` §4.3). Run each relay on its own machine, with its own database and
its own `--advertise` name. Never put two relay processes behind one name or on one database: each keeps its rate
counters, its pairing codes and its push to live subscribers in its own memory. A second relay adds uptime, not room:
every message goes to both, so both fill together.

Checked with two relays on one machine, ports 7777 and 7778. The recipient's records list both and are published at
both:

```sh
c record address grace --relay "$R1" --relay "$R2" --sealing-key --out "$AC_HOME/grace.json"
c publish "$R1" "$AC_HOME/grace.json" && c publish "$R2" "$AC_HOME/grace.json"
c record accept-from grace --root "$(c address heidi)" --max-bytes 65536 --ttl 604800 \
  --out "$AC_HOME/grace.accept.json"
c publish "$R1" "$AC_HOME/grace.accept.json" && c publish "$R2" "$AC_HOME/grace.accept.json"
c send --as heidi --to "$(c address grace)" --relay "$R1" --type chat.v1 --body '{"text":"two"}' --allow-private-relays
c inbox --as grace --relay "$R1" --relay "$R2" --once --trust-root "$(c address heidi)"
```

`send` printed `published` for both relays, and `inbox` printed one `accept` line for the id. (Both relays were on
`127.0.0.1`, so the sender needed `--allow-private-relays` for the relay it did not name; without it that relay failed
`resolve-failed`.) With the second relay stopped, a send printed `published http://127.0.0.1:7777 tries=1` and
`retry http://127.0.0.1:7778 tries=1 reason=unreachable`, and the recipient still read the message from the first
relay. Once the second was back, `c resend --as heidi --relay "$R1"` printed `published http://127.0.0.1:7778
tries=2`, and `c record keep --as grace --relay "$R1" --relay "$R2" --once` republished both records at both relays. Run it at least every 11 hours (section 10).

Upgrade or restart one relay at a time, and check it before the other.

## 12. Upgrading to a new cut

1. Read `CHANGELOG.md` of the new cut for changed flags, defaults and limits.
2. Get the new cut into a new directory, as in `README.md`, "Quick start", step 1, and build it there (section 3),
   with `AC_REV`. Keep the old binary.
3. Back up the database (section 6).
4. Stop the running relay with SIGTERM, and start the new binary with the same flags and the same `--db`.
5. Read the new `listening` line, then check: `c health`, `ac-relay probe`, and with metrics,
   `ac_relay_build_info{rev="<new commit>"} 1`.

Checked by stopping a relay and starting a binary rebuilt with `AC_REV` on its database: the store came back with its
8 envelopes, no `cursors-raised` line (the marker was in place), and `ac_relay_build_info{rev="<commit>"} 1`, the commit it was built from.
**Not verified:** an upgrade across cuts with a schema change; the run reused one commit.

A new relay migrates an older database forward as it opens it, and an older relay refuses a database whose schema is
newer (section 6). So to roll back across a schema change, start the old binary on the backup from step 3, not on the
upgraded file. A restart drops subscribers for a moment (they reconnect), resets the counters, and drops open pairing
codes.

## 13. Hardening

- Bind to `127.0.0.1` behind a front on the same host, or to the one interface the front uses (section 5). Trust
  only the front's address with `--trust-proxy`; a wider network lets anyone in it choose the address they are counted
  and logged as.
- Make the front overwrite or strip the header the relay reads (`--client-ip-header`, `cf-connecting-ip` by
  default), or append to `x-forwarded-for`, on every request. A front that passes a client's own value on lets that
  client choose the address it is counted and logged as, and the per-address limits stop meaning anything.
- Run the relay as its own user, with its database directory 0700, as in sections 4 and 6. It needs no root: it
  listens on the port you give it, and the front takes 443.
- Keep `--metrics-bind` on loopback, or a private network your scraper alone reaches. The metrics carry no addresses,
  but they show your traffic.
- Choose `--log-ip`, and how long you keep logs and backups. Logs and backups hold addresses and timing, and backups
  hold sealed mail.
- Set `--max-store-bytes` below your disk, with room for the write-ahead log, so a flood fills the bound and not the
  disk.
- Keep the clock right (NTP). A publish whose `ts` is more than `--skew` (300 seconds) ahead of the relay's clock is
  refused `future-ts`, and one older than the TTL plus the skew `stale-ts`.
- Outbound, the relay needs DNS and HTTPS on port 443 for domain roots only. Without them a `domain:` root fails
  closed, `resolve-failed`, and mail under address roots still flows.
- Set `--abuse-contact`, and keep the blocklist file and `ac-relay block` at hand (section 9).
- The test-only flags (`--well-known-insecure-http`, `--well-known-resolve`, `--dns-resolve`) are refused unless
  `--bind` is a loopback address; never use them on a relay that serves anyone.

## 14. Configuration reference

The relay takes flags only. It reads no environment variable at run time: its arguments are parsed by clap built
without its `env` feature (`crates/ac-relay/Cargo.toml`), and its log level is fixed at INFO
(`crates/ac-relay/src/main.rs`). At build time it reads `AC_REV` (section 3). It reads `/etc/resolv.conf` at each TXT
lookup for a domain root. `ac-relay --help` prints the same list with every default. Sources: the flags in
`crates/ac-relay/src/main.rs`, the defaults in `crates/ac-relay/src/config.rs` and `crates/ac-relay/src/net.rs`.

Listening and names:

| flag | default | meaning |
|---|---|---|
| `--port <port>` | 0 | the port; 0 picks a free one |
| `--bind <ip>` | `127.0.0.1` | the address to listen on, IPv4 or IPv6; `0.0.0.0` or `::` listens on every interface. The relay has no TLS of its own: any other bind serves plain HTTP to whoever reaches it, so put a TLS front before it (section 5) |
| `--advertise <url>` | none | the URL to announce and answer from health, and the first base a fetch proof may name (section 5); without it, `http://` and the bound address (the loopback address when bound to `0.0.0.0` or `::`) |
| `--accept-base <url>` | none | another base a fetch proof may name; repeatable |

Storage and time:

| flag | default | meaning |
|---|---|---|
| `--db <file>` | required | the SQLite file; created when missing; its directory must exist |
| `--ttl <seconds>` | 604,800 | the longest an envelope is kept; with the skew, the stale-`ts` window |
| `--skew <seconds>` | 300 | the clock skew allowed |
| `--sweep-interval <seconds>` | 60 | how often expired rows, envelopes, tombstones and records are swept |
| `--max-store-bytes <bytes>` | 0 | the store bound of section 7; 0 is none |
| `--max-envelope-bytes <bytes>` | 65,536 | the envelope cap, at most 262,144 |

Rates and quotas: the eleven flags of section 7's table, from `--rate-window` to `--connection-reserve-permille`.

Connections and subscribers:

| flag | default | meaning |
|---|---|---|
| `--header-timeout <seconds>` | 10 | how long a client may take to send a request head (on a new connection, its first bytes) |
| `--body-timeout <seconds>` | 30 | how long a client may take to send a publish body; then 408 and closed |
| `--ping-interval <seconds>` | 30 | how often a subscriber is pinged |
| `--idle-timeout <seconds>` | 60 | how long a subscriber may stay silent, and how long the relay waits for its auth frame; at least twice `--ping-interval`, else exit 2 |

Front and logs:

| flag | default | meaning |
|---|---|---|
| `--trust-proxy <cidr>` | none | a trusted proxy's network, or one address; repeatable |
| `--client-ip-header <name>` | `cf-connecting-ip` | the header a trusted proxy names the client in; only with `--trust-proxy` |
| `--log-ip prefix\|full\|none` | `prefix` | how log lines write a client's address |

Abuse:

| flag | default | meaning |
|---|---|---|
| `--abuse-contact <uri>` | none | what `GET /v0/abuse` answers; 404 without it |
| `--blocklist <file>` | none | the blocklist file; a missing file blocks nothing, one that does not parse at start stops the start |

Metrics:

| flag | default | meaning |
|---|---|---|
| `--metrics-port <port>` | none | the metrics listener; without it there is none |
| `--metrics-bind <ip>` | `127.0.0.1` | its address; only with `--metrics-port` |
| `--metrics-litestream <url>` | none | Litestream's metrics on this host (`http://127.0.0.1:<port>/metrics`, `[::1]` or `localhost`), passed on at each scrape; only with `--metrics-port`; read from the code, not run |

Domain roots:

| flag | default | meaning |
|---|---|---|
| `--well-known-timeout <seconds>` | 10 | how long one resolution may take, 1 to 60 |
| `--well-known-cache-max <seconds>` | 86,400 | the longest a domain's record is cached, 1 to 86,400 |

The operator's override, for an organisation that lost both its key and its rotation key: `--pin-reset <domain>`
with `--new-key <address>`, `--operator <who>`, `--channel <how it was confirmed>` and `--reason <why>` deletes that
domain's pin and exits without listening; run it while the relay is stopped, or add `--queue` to append the request
to `<db>.pin-resets` for the relay's next start. **Not verified** here.

The rest: `--exit-on-stdin-eof` stops the relay as SIGTERM does when its stdin ends, for a parent process that holds a
pipe to it (**not verified** here); `--version`; `--help`. Test only, refused unless `--bind` is a loopback address:
`--well-known-insecure-http`, `--well-known-resolve <host>=<ip>:<port>`, `--dns-resolve <name>=<txt>`.

Two subcommands: `ac-relay probe <url> --key <file>` (section 8) and `ac-relay block <file> [+<entry> | -<entry>]...`
(section 9).

## 15. When something goes wrong

A relay answers an error as `{"error": "<code>"}` with an HTTP status; the CLI prints it as `bag: <code>: <detail>`.
A 429 and a 503 also carry `Retry-After`, the seconds to wait before trying again. The codes are Appendix A of
`spec/SPEC.md`; the ones an operator meets:

| code, status | what it means | what to do |
|---|---|---|
| `unreachable` (CLI) | no connection to the relay, or no reply | is the relay running (`c health`, `curl .../v0/health`)? Is the front forwarding to its port? |
| `unreachable` (CLI), with `connection-refused` in the log | the client held `--connections-per-ip` connections already, and the relay closed the new one unanswered (section 7) | close the client's idle connections; behind a front, put the front's address in `--trust-proxy`, or all its clients share one cap |
| `resolve-failed` (CLI) at a recipient's relay | the sender's edge refused a relay on a private or loopback address, or could not read the recipient's record | give your relay a public address; on a LAN, senders pass `--allow-private-relays` |
| `resolve-failed`, 503 with `Retry-After` 60 | the relay could not resolve a `domain:` root (DNS, HTTPS, the record), and holds no valid pinned record for it | check the relay's outbound DNS and HTTPS; the `well-known-refused` line's `reason` and the `txt` line name the step. The origin must answer `/.well-known/bag/address.json` itself with 200 over HTTPS, with no redirect, and `_bag.<host>` may hold at most one `v=ac1` TXT record (section 10, "Records at your origin") |
| `bad-auth`, 401 | a fetch or subscribe proof did not verify | for a fetch, the relay URL the client used, as its records list it, must equal `--advertise` or an `--accept-base` byte for byte (section 5; read from the code, not run); for either, check that `--as` names the mailbox's identity |
| `future-ts`, `stale-ts`, 422 (401 at fetch) | a timestamp outside the relay's window | fix the clock on the relay or on the client |
| `rate-limited`, 429 | over a limit; the log's `limit` names which | wait `Retry-After`; behind a front, check `--trust-proxy`, or every client shares one limit |
| `store-full`, 503 with `Retry-After` | the store reached `--max-store-bytes` (`Retry-After` is one sweep interval); or, at a rendezvous, a pairing open while the relay holds 10,000 open codes (`Retry-After` 600) | raise the bound (with room on the disk), or wait for mail to expire; for pairing, wait for open codes to lapse |
| `not-authorized`, 403 | a blocked sender, or a signer who may not read this | check the blocklist (`ac-relay block <file>`) |
| `not-hosted`, 403 | no recipient has an accept-from record at this relay | the recipient publishes `record accept-from` here, or pairs (section 10) |
| `root-not-accepted`, 403 | the recipient's accept-from record does not admit the sender's root | the recipient adds the root and publishes again |
| `stale-record`, 409 | the relay holds a record at least as new | sign again with a newer `iat`; `record keep` does |
| `record-expired`, 422 | a record past its life: an address record past `iat + ttl`, or a key record past its `exp` (`spec/SPEC.md` §7.5); at a domain root, an org record served past its life, logged `well-known-refused` with `reason` `record-expired` | sign again and publish (`c record keep --once`); re-sign the org record and replace the file daily (`docs/onboarding.md`, section 7); check the clocks |
| `no-nameplate`, 404 | a pairing code the relay does not hold: expired, mistyped, claimed at another relay, or dropped by a restart | both sides use the same rendezvous (section 10); start a new invitation |
| `internal`, 500 | the relay's own failure, its store say | read the `store-error` line; check the disk |
| `fatal` in the log, exit 1 | the relay could not start | the line names why: the database, the port, a setting, a newer schema |

`docs/partner-install.md`, section 8, covers the codes a user of the CLI meets.

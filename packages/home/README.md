# @usebag/home

The acts on a bag home that both the command line (`packages/cli`) and the MCP server (`packages/mcp`) do, so that an
agent never needs the command line for a feature bag offers.
Both may import this package; it imports neither, and never `shim` (`scripts/check-imports.sh`).

The home's reads:

- `homeIdentities(home)`: the identities `<home>/identities.json` lists, each label with the relays it names. No file
  is an empty home; a file that is not a list is `identities-invalid`.
- `homeRelays(identities)`: every relay they name, once each.
- `relaysHealth(relays, probe)`: each relay's health through the caller's probe, ok only when it answers true within
  3 s.
- `cachedHealth(probe)`: `relaysHealth` behind a 60 s cache, so a looping call cannot drum the relays; the same list
  asked again within the window gets the last answer with no probe.

The acts on one identity, each taking a `HomeIo` (`src/ports.ts`): it says its lines and warnings in the order it
does its work, so the lines before a failure keep their place, and asks its one question where the person's yes is
needed. Before the question it reads what the act relies on; after a yes it reads it again, and refuses with `busy`,
nothing written, when it differs (`askWithRecheck`), since a person's answer can take as long as a dialog stays open.

- `createIdentity` and `createAgentPointer` (`keygen.ts`): a new key file or keychain item, or an agent pointer.
- `publishFirstRecords` (`first-records.ts`): a new identity's first records at its relays, as onboard makes them (the
  first epoch's key record, a null-sealing address record, an accept-from naming only itself), the copies kept.
- `identityRemove`, `identityRelays` and `identityKeepAlive` (`identity.ts`).
- `custodyMove` (`custody.ts`): an identity between its key file and its keychain item.
- `unpairRoot` (`unpair.ts`): a pairing ended, in trust.json and the accept-from at each relay, or a local pair.
- `telemetrySwitch` (`telemetry.ts`): the machine's telemetry on (asked first), off and status (asking nothing), one
  switch per machine in HOME/.bag; the command line asks its own question at a terminal, a window its short one.

The files of a home they share: the identities file (`identities.ts`), the bag service's entry in it
(`service-home.ts`), who holds an identity (`held.ts`), the name book (`names.ts`), the trust file (`trust.ts`), the
keys in their custodies (`keys.ts`), the local delivery word, pairs and held mail (`local.ts`), and an identity's own
records at the relays (`records.ts`). Every error this package throws itself is a `HomeError` whose code is one the
command line already reports.

Hosts (wiring a host, the service unit) move here next.

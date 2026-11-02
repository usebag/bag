import { readFileSync } from 'node:fs'
import { parseRecord, recordSigner, serializeRecord } from '@usebag/core'
import { heldSomewhere, offerRecord } from '@usebag/edge'
import { CliError, parse, relayUrl, str } from '../args.ts'
import { laggingLines } from '../epochs.ts'
import { checkNoWindow, homeDir } from '../home.ts'
import type { Io } from '../io.ts'

// The two relay calls that need no identity: publish a signed record, and the health probe.

/**
 * publish <relay-url> <record-file> [--dir <home>]: checks the file is a record (spec/SPEC.md §7) and publishes it through the
 * edge's relay client (spec/SPEC.md §8.2). Prints `ok <kind> <signer>`. An address record of an identity a login
 * window of the home holds is refused window-open (the window's logout would overwrite it). An address record that
 * revokes goes to every relay it lists too, and each that did not take it is named, exit 3 (spec/SPEC.md §8.7).
 */
export async function publish(args: readonly string[], io: Io): Promise<number> {
  const p = parse(args, { positionals: ['relay-url', 'record-file'], options: { dir: { type: 'string' } } })
  const [url, file] = p.positionals as [string, string]
  const relay = relayUrl(url)
  const r = parseRecord(readFileSync(file))
  const dir = str(p, 'dir')
  if (r.kind === 'address' && (dir !== undefined || io.env.AC_HOME || io.env.HOME)) {
    await checkNoWindow(io, homeDir(io, dir), r.key)
  }
  const [client, bytes] = [io.relay({}), serializeRecord(r)]
  const listed = r.kind === 'address' && r.revoked.length > 0 ? r.relays : []
  const offered = await offerRecord(r, [...new Set([relay, ...listed])], (u) => client.publish(u, bytes))
  const { lagging } = heldSomewhere(offered)
  laggingLines(io, recordSigner(r), lagging)
  io.out(`ok ${r.kind} ${recordSigner(r)}`)
  return lagging.length > 0 ? 3 : 0
}

/** health <relay-url>: prints `ok` when the relay answers its health probe with 200, else fails `unhealthy`. */
export async function health(args: readonly string[], io: Io): Promise<number> {
  const p = parse(args, { positionals: ['relay-url'], options: {} })
  const relay = relayUrl(p.positionals[0] as string)
  if (!(await io.relay({}).health(relay))) throw new CliError('unhealthy', `${relay} did not answer 200`)
  io.out('ok')
  return 0
}

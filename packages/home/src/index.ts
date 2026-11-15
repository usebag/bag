import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { HomeError } from './ports.ts'

// packages/home: the acts on a bag home that the command line and the MCP server both do, so that an agent never
// needs the CLI for a feature bag offers. The CLI and the MCP server may import this package; it imports neither
// (scripts/check-imports.sh). For now it holds the home's reads only: the identities the home lists, with their relays, and those relays' health through the caller's probe.
// The acts that change a home (identity_create, host_wire and the rest) move here in the design's second phase.

/** A label as the identities file and the tools take it: local only, never sent (packages/mcp/src/identities.ts). */
export const LABEL = /^[a-z0-9][a-z0-9_-]{0,31}$/

/** One identity of the home as its identities file lists it: its label and the relays it names. */
export interface HomeIdentity {
  readonly label: string
  readonly relays: readonly string[]
}

/** One relay's answer to its health probe. */
export interface RelayHealth {
  readonly relay: string
  readonly ok: boolean
}

export { askWithRecheck, CHANGED_WHILE_ASKED, HomeError, type HomeIo } from './ports.ts'

/**
 * The identities <home>/identities.json lists, in its order: each label that passes LABEL, with the string relays it
 * names. No file is an empty home. An entry whose label does not pass is left out rather than refused, since the
 * service refuses the file itself when it reads it; this read only names what a window could bind. The service's own
 * keys (names ending .service, .session or .signin) can never pass LABEL, which has no dot.
 */
export function homeIdentities(home: string): HomeIdentity[] {
  let text: string
  try {
    text = readFileSync(join(home, 'identities.json'), 'utf8')
  } catch (e) {
    if ((e as { code?: unknown }).code === 'ENOENT') return []
    throw e
  }
  let doc: unknown
  try {
    doc = JSON.parse(text)
  } catch {
    throw new HomeError('identities-invalid', 'identities.json is not JSON')
  }
  const list = (doc as { identities?: unknown } | null)?.identities
  if (!Array.isArray(list))
    throw new HomeError('identities-invalid', 'identities.json has no identities list')
  const out: HomeIdentity[] = []
  for (const entry of list) {
    const e = (entry ?? {}) as { label?: unknown; relays?: unknown }
    if (typeof e.label !== 'string' || !LABEL.test(e.label)) continue
    const relays = Array.isArray(e.relays) ? e.relays.filter((r): r is string => typeof r === 'string') : []
    out.push({ label: e.label, relays })
  }
  return out
}

/** Every relay the identities name, each once, in the order first named. */
export function homeRelays(identities: readonly HomeIdentity[]): string[] {
  return [...new Set(identities.flatMap((i) => i.relays))]
}

/** How long a health answer is reused, in ms, so that a looping call cannot drum the relays. */
export const HEALTH_CACHE_MS = 60_000

/**
 * relaysHealth behind a cache: the same relays asked again within `ttlMs` (by `now`, in ms) get the last answer, with
 * no probe. Any other list probes again and replaces it.
 */
export function cachedHealth(
  probe: (relay: string) => Promise<boolean>,
  ttlMs = HEALTH_CACHE_MS,
  now: () => number = Date.now,
): (relays: readonly string[]) => Promise<RelayHealth[]> {
  let last: { key: string; at: number; value: Promise<RelayHealth[]> } | null = null
  return (relays) => {
    const key = JSON.stringify(relays)
    const t = now()
    if (last !== null && last.key === key && t - last.at < ttlMs) return last.value
    const value = relaysHealth(relays, probe)
    last = { key, at: t, value }
    return value
  }
}

/** How long one relay's probe may take before it counts as not answering, in ms. */
export const HEALTH_TIMEOUT_MS = 3000

/**
 * Each relay's health, probed at once through `probe` (the caller's relay client, which this package does not hold):
 * ok only when the probe resolves true within `timeoutMs`. A probe that throws, answers false or takes longer is not ok.
 */
export async function relaysHealth(
  relays: readonly string[],
  probe: (relay: string) => Promise<boolean>,
  timeoutMs = HEALTH_TIMEOUT_MS,
): Promise<RelayHealth[]> {
  return Promise.all(
    relays.map(async (relay) => {
      let timer: ReturnType<typeof setTimeout> | undefined
      const late = new Promise<boolean>((done) => {
        timer = setTimeout(() => done(false), timeoutMs)
      })
      try {
        return { relay, ok: (await Promise.race([probe(relay), late])) === true }
      } catch {
        return { relay, ok: false }
      } finally {
        clearTimeout(timer)
      }
    }),
  )
}
export {
  applyChange,
  type Before,
  backup,
  type Change,
  restore,
  stateAfter,
  stateOf as pathState,
  View,
} from './changes.ts'
export * from './check.ts'
export * from './custody.ts'
export * from './first-records.ts'
export * from './held.ts'
export * from './host-common.ts'
export * from './host-install.ts'
export * from './host-migrate.ts'
export * from './host-service.ts'
export * from './host-user.ts'
export * from './identities.ts'
export * from './identity.ts'
export * from './keygen.ts'
export * from './keys.ts'
export * from './local.ts'
export * from './names.ts'
export * from './packaged.ts'
export { changedWhileAsked } from './ports.ts'
export * from './proposals.ts'
export * from './records.ts'
export * from './removed.ts'
export * from './service-home.ts'
export * from './stage.ts'
export * from './telemetry.ts'
export * from './trust.ts'
export * from './unpair.ts'

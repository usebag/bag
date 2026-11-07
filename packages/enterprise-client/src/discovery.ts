import { discover, isDomainHost, parseJson, txtName } from '@usebag/core'
import type { OriginGet, RelayGuard } from '@usebag/edge'
import { EnterpriseError } from './instance.ts'

// How `bag sign-in <domain>` finds its bag enterprise instance (the agent contract's discovery), a fault never
// falling through: 1. BAG_ENTERPRISE_INSTANCES=<domain>=<origin>,... for a domain it names, no record fetched; 2. a
// reserved last label (RESERVED_LABELS): no record, so the stand-in or discovery_failed; 3. every other name: the
// record <origin>/.well-known/bag/enterprise.json, { "v": 1, "instance": "<https origin>" }, at the org's one origin of
// SPEC 12.1 (bag.<domain> when its _bag TXT says host=bag), fetched as a well-known record is (https, no redirect, a
// cap, the private-address guard); a 404 is no record, any other failure discovery_failed; 4. BAG_ENTERPRISE_URL. An
// origin from 1 or 4 is https, or http on a loopback host.

/** The last labels no record is fetched for (the agent contract's reserved labels; SPEC 12.3 item 1). */
export const RESERVED_LABELS = 'alt arpa example internal invalid local localhost onion test'.split(' ')

export const ENTERPRISE_RECORD_PATH = '/.well-known/bag/enterprise.json'

/** What discovery reads the network with: TXT records, one guarded GET, the guard. */
export interface DiscoveryNet {
  readonly txt: (name: string) => Promise<string[][]>
  readonly get: OriginGet
  readonly guard: Pick<RelayGuard, 'connectTo'>
}

type Env = Readonly<Record<string, string | undefined>>
const failed = (detail: string): EnterpriseError => new EnterpriseError('discovery_failed', detail)

/** `text` as a bare origin when it is one: https, or http on a loopback host when `loopback` allows it; else null. */
export function bareOrigin(text: string, loopback: boolean): string | null {
  let url: URL
  try {
    url = new URL(text)
  } catch {
    return null
  }
  const h = url.hostname
  const local = /^(localhost|.+\.localhost|\[::1\]|127\.\d+\.\d+\.\d+)$/.test(h)
  const scheme = url.protocol === 'https:' || (loopback && url.protocol === 'http:' && local)
  return scheme && text.replace(/\/$/, '') === url.origin ? url.origin : null
}

/** The record step: the instance the org's record names; null for no record (a 404, or a special-use name). */
async function fromRecord(domain: string, net: DiscoveryNet): Promise<string | null> {
  if (RESERVED_LABELS.includes(domain.slice(domain.lastIndexOf('.') + 1))) return null
  let url = domain
  let answer: Awaited<ReturnType<OriginGet>>
  try {
    const name = txtName(domain)
    url = discover(name === null ? [] : await net.txt(name), domain).origin + ENTERPRISE_RECORD_PATH
    answer = await net.get(url, await net.guard.connectTo(url), 10_000, 4096)
  } catch (e) {
    throw failed(`the enterprise record of ${domain} could not be fetched (${url}): ${(e as Error).message}`)
  }
  if (answer.status === 404) return null
  if (answer.status !== 200 || answer.body === null) throw failed(`${url} answered ${answer.status}`)
  let doc: Record<string, unknown> | null = null
  try {
    doc = parseJson(answer.body) as Record<string, unknown>
  } catch {
    // malformed: below
  }
  const ok = doc?.v === 1 && Object.keys(doc).length === 2 && typeof doc.instance === 'string'
  const instance = ok ? bareOrigin(doc?.instance as string, false) : null
  if (instance === null) throw failed(`${url} is not { "v": 1, "instance": "<https origin>" }`)
  return instance
}

/** The instance's origin for `domain` (a lowercase host), by the three steps; discovery_failed when none is found. */
export async function discoverInstance(domain: string, env: Env, net: DiscoveryNet): Promise<string> {
  if (!isDomainHost(domain)) throw new EnterpriseError('usage', `${JSON.stringify(domain)} is not a domain`)
  const pair = (env.BAG_ENTERPRISE_INSTANCES ?? '').split(',').find((p) => p.split('=')[0]?.trim() === domain)
  const record = pair === undefined ? await fromRecord(domain, net) : null
  if (record !== null) return record
  const given = pair === undefined ? env.BAG_ENTERPRISE_URL : pair.slice(pair.indexOf('=') + 1).trim()
  const from = pair === undefined ? 'BAG_ENTERPRISE_URL' : 'BAG_ENTERPRISE_INSTANCES'
  if (!given) throw failed(`no instance for ${domain}: no record, BAG_ENTERPRISE_INSTANCES or _URL`)
  const origin = bareOrigin(given, true)
  if (origin === null) throw failed(`${from} names no https or loopback origin for ${domain}`)
  return origin
}

import type { CaveatContext, CaveatEvaluator, CaveatVerdict } from '../caveats.ts'
import { isPlainObject } from '../json.ts'

/**
 * The coding profile's caveat grammar (spec/SPEC.md §6):
 *
 *   type=<type>        the sealed type is exactly <type>
 *   type=<prefix>.*    the sealed type starts with "<prefix>."
 *   repo=<name>        the sealed body is an object whose string member `repo` is exactly <name>
 *
 * <type>, <prefix> and <name> are non-empty, and <type> and <prefix> hold no "*". Before the sealed part is open
 * these caveats answer 'needs-sealed'. Anything else, including a malformed pattern, is 'unknown'.
 */
export function evaluateCodingCaveat(caveat: string, ctx: CaveatContext): CaveatVerdict {
  if (caveat.startsWith('type=')) {
    const pattern = caveat.slice('type='.length)
    const prefix = pattern.endsWith('.*') ? pattern.slice(0, -2) : undefined
    const name = prefix ?? pattern
    if (name.length === 0 || name.includes('*')) return 'unknown'
    if (ctx.sealed === undefined) return 'needs-sealed'
    const type = ctx.sealed.type
    const holds = prefix === undefined ? type === pattern : type.startsWith(`${prefix}.`)
    return holds ? 'hold' : 'fail'
  }
  if (caveat.startsWith('repo=')) {
    const name = caveat.slice('repo='.length)
    if (name.length === 0) return 'unknown'
    if (ctx.sealed === undefined) return 'needs-sealed'
    const body = ctx.sealed.body
    return isPlainObject(body) && body.repo === name ? 'hold' : 'fail'
  }
  return 'unknown'
}

/** The coding profile's evaluator. */
export const codingEvaluator: CaveatEvaluator = { name: 'coding', evaluate: evaluateCodingCaveat }

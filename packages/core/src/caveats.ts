import type { SealedContent } from './seal.ts'

/**
 * An evaluator's verdict on one caveat (spec/SPEC.md §6): it holds, it fails, the evaluator does not know it, or the
 * evaluator needs the sealed part to decide.
 */
export type CaveatVerdict = 'hold' | 'fail' | 'unknown' | 'needs-sealed'

/** What a caveat is judged against: the outer fields, the chain's root, and the sealed part once it is open. */
export interface CaveatContext {
  readonly from: string
  readonly to: readonly string[]
  readonly ts: number
  readonly root: string
  readonly sealed?: SealedContent | undefined
}

/**
 * A profile's caveat evaluator. A caveat is a predicate that must hold, never a grant: an
 * evaluator answers only for the caveats of its grammar and returns 'unknown' for the rest.
 */
export interface CaveatEvaluator {
  readonly name: string
  evaluate(caveat: string, ctx: CaveatContext): CaveatVerdict
}

/** The outcome of evaluating a chain's effective caveats. */
export type CaveatResult =
  | { readonly ok: true }
  | { readonly ok: false; readonly code: 'unknown-caveat' | 'caveat-failed'; readonly caveat: string }

function verdict(evaluator: CaveatEvaluator, caveat: string, ctx: CaveatContext): CaveatVerdict {
  try {
    return evaluator.evaluate(caveat, ctx)
  } catch {
    return 'fail'
  }
}

/**
 * Evaluates the effective caveats in chain order, failing closed (spec/SPEC.md §6). Every evaluator judges each caveat;
 * the caveat holds only when at least one says 'hold' and none says 'fail' or 'needs-sealed'. A 'fail', a
 * 'needs-sealed' (the sealed part is required, so the edge evaluates after unsealing) or an evaluator that throws
 * gives caveat-failed; a caveat no evaluator knows gives unknown-caveat. The first caveat that does not hold decides.
 */
export function evaluateCaveats(
  caveats: readonly string[],
  evaluators: readonly CaveatEvaluator[],
  ctx: CaveatContext,
): CaveatResult {
  for (const caveat of caveats) {
    const verdicts = evaluators.map((e) => verdict(e, caveat, ctx))
    if (verdicts.includes('fail') || verdicts.includes('needs-sealed')) {
      return { ok: false, code: 'caveat-failed', caveat }
    }
    if (!verdicts.includes('hold')) return { ok: false, code: 'unknown-caveat', caveat }
  }
  return { ok: true }
}

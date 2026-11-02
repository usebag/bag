import { AcError } from './errors.ts'

/** The values the canonical form carries (spec/SPEC.md §2): strings, integers, null and lists of them. */
export type CanonicalValue = string | number | null | readonly CanonicalValue[]

/** The largest integer the canonical form carries: 2^53 - 1. */
export const MAX_CANONICAL_INTEGER = Number.MAX_SAFE_INTEGER

/** True for an integer from 0 to 2^53 - 1. */
export function isCanonicalInteger(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0
}

/**
 * The canonical form of a value (spec/SPEC.md §2): a list is `[a,b]` with no white space, a string is escaped as
 * JSON.stringify escapes it (only `"`, `\` and U+0000 to U+001F; lowercase `\u00xx`; no normalization), an integer is
 * decimal. bad-canonical for anything else: a fraction, a negative number, a number over 2^53 - 1, a boolean, an
 * object, undefined, or a string with a lone surrogate.
 */
export function canonical(value: CanonicalValue): string {
  const out: string[] = []
  write(value, out)
  return out.join('')
}

function write(value: unknown, out: string[]): void {
  if (value === null) {
    out.push('null')
  } else if (typeof value === 'string') {
    if (!value.isWellFormed()) throw new AcError('bad-canonical', 'a string with a lone surrogate')
    out.push(JSON.stringify(value))
  } else if (typeof value === 'number') {
    if (!isCanonicalInteger(value))
      throw new AcError('bad-canonical', `${value} is not an integer from 0 to 2^53 - 1`)
    out.push(String(value))
  } else if (Array.isArray(value)) {
    out.push('[')
    // An index loop, not forEach: a hole in a sparse list must be rejected, not skipped.
    for (let i = 0; i < value.length; i++) {
      if (i > 0) out.push(',')
      write(value[i], out)
    }
    out.push(']')
  } else {
    throw new AcError('bad-canonical', `a value of type ${value === undefined ? 'undefined' : typeof value}`)
  }
}

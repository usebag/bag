// Line S2, "the derived hop attenuates": the pre-registered set of 200 `sign` requests (V3), 20 each of
// the ten cases of the line, built deterministically from its text. Committed before any run, at 6974626 (the
// c3778a6 code), before any test code of the line; no request below
// was chosen after a result.
// Data only: `sub` names a fixture party (never the requesting session, so no request is a renewal).
//
// The ten cases, each with the expected code:
//   drop       a caveat of the grant dropped                          not-in-grant
//   reorder    the grant's caveats reordered                          not-in-grant
//   rewrite    a caveat of the grant rewritten                        not-in-grant
//   append     the grant's caveats, then appended ones                signed
//   past-chain `exp` past the session chain's earliest, in the window exp-not-monotone
//   past-window `exp` past the window's end                            exp-not-monotone
//   empty      no caveats                                             not-in-grant
//   caveats-33 33 caveats (the grant's two, then 31)                  too-many-caveats (the section 6.2 code past the cap)
//   bytes-257  a caveat of 257 UTF-8 bytes                            caveat-too-long (the section 6.2 code past the cap)
//   semantic   `type=coding.task.v1` under a grant of `type=coding.*` not-in-grant (no semantic test)
// The pass: 0 of the 180 refusals signed, the 20 appends signed. A refusal under another code is a deviation,
// not red.

/** The grant of every case but `semantic`: two caveats, so a drop and a reorder are expressible. */
export const S2_GRANT = ['type=coding.*', 'repo=r'] as const
/** The grant of the `semantic` case, "a session holding `type=coding.*`". */
export const S2_SEMANTIC_GRANT = ['type=coding.*'] as const
/** The first grant's `exp`, an hour after T0; the window is the default 8 hours. */
export const S2_GRANT_EXP_AFTER_T0 = 3600
export const S2_WINDOW = 28_800

export const S2_CASES = [
  'drop',
  'reorder',
  'rewrite',
  'append',
  'past-chain',
  'past-window',
  'empty',
  'caveats-33',
  'bytes-257',
  'semantic',
] as const
export type S2Case = (typeof S2_CASES)[number]

export type S2Expect = 'signed' | 'not-in-grant' | 'exp-not-monotone' | 'too-many-caveats' | 'caveat-too-long'

export const S2_EXPECT: Readonly<Record<S2Case, S2Expect>> = {
  drop: 'not-in-grant',
  reorder: 'not-in-grant',
  rewrite: 'not-in-grant',
  append: 'signed',
  'past-chain': 'exp-not-monotone',
  'past-window': 'exp-not-monotone',
  empty: 'not-in-grant',
  'caveats-33': 'too-many-caveats',
  'bytes-257': 'caveat-too-long',
  semantic: 'not-in-grant',
}

export interface S2Request {
  readonly n: number
  readonly case: S2Case
  /** The grant the session holds (its effective caveats). */
  readonly grant: readonly string[]
  /** A fixture party's name. */
  readonly sub: 'bob' | 'carol' | 'mallory' | 'other' | 'org'
  readonly caveats: readonly string[]
  /** `exp` as seconds after T0. */
  readonly expAfterT0: number
  readonly expect: S2Expect
}

const SUBS = ['bob', 'carol', 'mallory', 'other', 'org'] as const
const [TYPE, REPO] = S2_GRANT
const G: readonly string[] = S2_GRANT
const E = S2_GRANT_EXP_AFTER_T0
const at = <T>(list: readonly T[], i: number): T => list[i % list.length] as T
/** An `exp` at or before the chain's earliest, varied by i. */
const inChain = (i: number): number => E - (i % 5) * 60

const REWRITES: readonly (readonly string[])[] = [
  ['type=coding.**', REPO],
  ['type=Coding.*', REPO],
  ['type=coding.* ', REPO],
  [' type=coding.*', REPO],
  ['type=coding.task.*', REPO],
  ['type=*', REPO],
  ['type=coding', REPO],
  ['type=codinG.*', REPO],
  [TYPE, 'repo=R'],
  [TYPE, 'repo=r2'],
  [TYPE, 'repo= r'],
  [TYPE, 'repo=r\u200b'],
  [TYPE, 'repo=*'],
  [TYPE, 'repo='],
  [TYPE, 'Repo=r'],
  [TYPE, 'repo=r '],
  [TYPE, 'repo=rr'],
  [TYPE, 'repo=s', 'x=1'],
  [`${TYPE},${REPO}`],
  [TYPE.replace('c', '\u0441'), REPO],
]

const REORDERS: readonly (readonly string[])[] = [
  [REPO, TYPE],
  [REPO, TYPE, 'x=1'],
  ['x=1', TYPE, REPO],
  [REPO, 'x=1', TYPE],
  [TYPE, 'x=1', REPO],
]

const caseRequests: Record<S2Case, (i: number) => Omit<S2Request, 'n' | 'case' | 'expect'>> = {
  drop: (i) => ({
    grant: G,
    sub: at(SUBS, i),
    caveats: [...(i % 2 === 0 ? [REPO] : [TYPE]), ...(i >= 10 ? [`x=${i}`] : [])],
    expAfterT0: inChain(i),
  }),
  reorder: (i) => ({
    grant: G,
    sub: at(SUBS, i),
    caveats: [...at(REORDERS, i), ...(i >= 5 ? [`y=${i}`] : [])],
    expAfterT0: inChain(i),
  }),
  rewrite: (i) => ({ grant: G, sub: at(SUBS, i), caveats: at(REWRITES, i), expAfterT0: inChain(i) }),
  append: (i) => ({
    grant: G,
    sub: at(SUBS, i),
    caveats: [...G, ...Array.from({ length: 1 + (i % 3) }, (_, k) => `append=${i}.${k}`)],
    expAfterT0: inChain(i),
  }),
  'past-chain': (i) => ({
    grant: G,
    sub: at(SUBS, i),
    caveats: i % 2 === 0 ? G : [...G, `x=${i}`],
    expAfterT0: E + at([1, 2, 30, 59, 60, 61, 600, 3600, 7200, 25_199], i) + (i >= 10 ? 1 : 0),
  }),
  'past-window': (i) => ({
    grant: G,
    sub: at(SUBS, i),
    caveats: i % 2 === 0 ? G : [...G, `x=${i}`],
    expAfterT0: S2_WINDOW + at([1, 2, 60, 3600, 86_400], i) + Math.floor(i / 5),
  }),
  empty: (i) => ({ grant: G, sub: at(SUBS, i), caveats: [], expAfterT0: inChain(i) }),
  'caveats-33': (i) => ({
    grant: G,
    sub: at(SUBS, i),
    caveats: [...G, ...Array.from({ length: 31 }, (_, k) => `c${i}=${k}`)],
    expAfterT0: inChain(i),
  }),
  'bytes-257': (i) => {
    const long = at(
      ['x'.repeat(257), `a${'\u00e9'.repeat(128)}`, `repo=${'r'.repeat(252)}`, 'z'.repeat(257)],
      i,
    )
    const where = i % 3
    const caveats = where === 0 ? [...G, long] : where === 1 ? [TYPE, long] : [...G, 'x=1', long]
    return { grant: G, sub: at(SUBS, i), caveats, expAfterT0: inChain(i) }
  },
  semantic: (i) => ({
    grant: S2_SEMANTIC_GRANT,
    sub: at(SUBS, i),
    caveats: at(
      [
        ['type=coding.task.v1'],
        ['type=coding.task.v1', 'repo=r'],
        ['type=coding.result.v1'],
        ['type=coding.task.v1', 'type=coding.*'],
        ['type=coding.task.*'],
      ],
      i,
    ),
    expAfterT0: inChain(i),
  }),
}

export const S2_REQUESTS: readonly S2Request[] = S2_CASES.flatMap((c, ci) =>
  Array.from({ length: 20 }, (_, i) => ({
    n: ci * 20 + i,
    case: c,
    expect: S2_EXPECT[c],
    ...caseRequests[c](i),
  })),
)

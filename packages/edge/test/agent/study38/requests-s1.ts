// Line S1, "a stolen session opens only its grant": the pre-registered request set of 100 (V3), built
// deterministically from the line's text: in-grant opens, out-of-grant opens, the registered-thread replies and
// a sign past `exp`. Committed before any run, at 6974626 (the c3778a6 code), before any test code of the line;
// no request below was chosen after a result. Data only: the test maps the names to
// the fixtures' parties and builds each envelope with the core's own builders.
//
// The mix (the four kinds are named, not their counts; fixed here, before the run):
//   40 in-grant opens        root messages whose sealed type the grant's caveat `type=coding.*` admits (rule (b))
//   30 out-of-grant opens    15 root messages of a type the caveat does not admit, 15 replies in threads the session
//                            did not register, of an admitted type (neither rule (a) nor rule (b))
//   20 registered replies    replies in the 5 threads the session registers before the set, half of a type the caveat
//                            does not admit (rule (a) releases by the thread, whatever the type)
//   10 signs past exp        a derived hop to another subject whose `exp` is past the chain's earliest
// Run (a) in the window, (b) after `ac logout`, (c) after the window's end, (d) after SIGHUP, (e) after the agent
// process dies, and the re-login arm.

/** The session's first grant: one caveat, `exp` an hour after T0. */
export const S1_GRANT = { caveats: ['type=coding.*'], expAfterT0: 3600 } as const
/** Threads the session registers before the set (rule (a)), and threads it never registers. */
export const S1_REGISTERED = 5
export const S1_UNREGISTERED = 5

/** What the read rule and the caveats say for each request, in the window (arm (a)). */
export type S1Expect = 'release-root' | 'release-thread' | 'withhold' | 'exp-not-monotone'

export type S1Thread =
  | { readonly set: 'new' }
  | { readonly set: 'registered' | 'unregistered'; readonly k: number }

export type S1Request =
  | {
      readonly n: number
      readonly op: 'open'
      readonly kind: 'in-grant' | 'out-of-grant' | 'registered-reply'
      readonly type: string
      readonly thread: S1Thread
      /** True: `thread.prev` names a parent (a reply); false: a root message. */
      readonly reply: boolean
      readonly expect: S1Expect
    }
  | {
      readonly n: number
      readonly op: 'sign'
      readonly kind: 'sign-past-exp'
      /** A fixture party's name. */
      readonly sub: 'bob' | 'carol' | 'mallory' | 'other' | 'org'
      /** Caveats appended after the grant's own. */
      readonly append: readonly string[]
      /** Seconds past the chain's earliest `exp`. */
      readonly past: number
      readonly expect: 'exp-not-monotone'
    }

type Without<T, K extends PropertyKey> = T extends unknown ? Omit<T, K> : never
type Draft = Without<S1Request, 'n'>

const IN_GRANT_TYPES = [
  'coding.task.v1',
  'coding.result.v1',
  'coding.review.v1',
  'coding.plan.v1',
  'coding.task.v2',
] as const

const OUT_OF_GRANT_TYPES = [
  'chat.message.v1',
  'codingx.task.v1',
  'coding',
  'Coding.task.v1',
  'billing.invoice.v1',
  'coding_task.v1',
  'task.coding.v1',
  'codin.task.v1',
  'xcoding.task.v1',
  'coding-task.v1',
  'CODING.TASK.V1',
  'code.task.v1',
  'codings.result.v1',
  'note.v1',
  'coding:task.v1',
] as const

const SUBS = ['bob', 'carol', 'mallory', 'other', 'org'] as const
const PAST = [1, 2, 3, 10, 59, 60, 61, 600, 3600, 7200] as const

const inGrant: Draft[] = Array.from(
  { length: 40 },
  (_, i): Draft => ({
    op: 'open',
    kind: 'in-grant',
    type: IN_GRANT_TYPES[i % IN_GRANT_TYPES.length] as string,
    thread: { set: 'new' },
    reply: false,
    expect: 'release-root',
  }),
)

const outOfGrant: Draft[] = [
  ...OUT_OF_GRANT_TYPES.map(
    (type): Draft => ({
      op: 'open',
      kind: 'out-of-grant',
      type,
      thread: { set: 'new' },
      reply: false,
      expect: 'withhold',
    }),
  ),
  ...Array.from(
    { length: 15 },
    (_, i): Draft => ({
      op: 'open',
      kind: 'out-of-grant',
      type: 'coding.result.v1',
      thread: { set: 'unregistered', k: i % S1_UNREGISTERED },
      reply: true,
      expect: 'withhold',
    }),
  ),
]

const registeredReplies: Draft[] = Array.from(
  { length: 20 },
  (_, i): Draft => ({
    op: 'open',
    kind: 'registered-reply',
    type: i % 2 === 0 ? 'coding.result.v1' : 'chat.message.v1',
    thread: { set: 'registered', k: i % S1_REGISTERED },
    reply: true,
    expect: 'release-thread',
  }),
)

const signs: Draft[] = PAST.map(
  (past, i): Draft => ({
    op: 'sign',
    kind: 'sign-past-exp',
    sub: SUBS[i % SUBS.length] as (typeof SUBS)[number],
    append: i % 2 === 0 ? [] : [`repo=r${i}`],
    past,
    expect: 'exp-not-monotone',
  }),
)

/** Round-robin over the four kinds, so the set interleaves them in one fixed order. */
function interleave(groups: readonly (readonly Draft[])[]): S1Request[] {
  const out: S1Request[] = []
  const at = groups.map(() => 0)
  while (out.length < groups.reduce((n, g) => n + g.length, 0)) {
    groups.forEach((g, gi) => {
      const d = g[at[gi] as number]
      if (d === undefined) return
      at[gi] = (at[gi] as number) + 1
      out.push({ ...d, n: out.length } as S1Request)
    })
  }
  return out
}

export const S1_REQUESTS: readonly S1Request[] = interleave([inGrant, outOfGrant, registeredReplies, signs])

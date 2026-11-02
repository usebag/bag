// Line G1, the grant surface: the pre-registered set of 40 first-grant requests from
// clients that are not the agent's terminal, and the 10 confirmed with a `y` typed on it (V3), built
// deterministically (the 40 and the 10 are `ac grant`'s first grants).
// Committed before any run, on the run branch, before any test
// code of the line; no request below was chosen after a result.
// It lives in the cli package (not beside S1 and S2 in the edge's tests)
// because G1 runs through `ac login` and `ac grant`, and a cli test may not import a path out of its own package
// (scripts/check-imports.sh). Data only: each request's session is made fresh by the test.
//
// The four arms of the 40, 10 each (the arms are named, not their counts; fixed here, before the run):
//   no-tty        `ac grant` from a process whose stdin is no terminal
//   pty           `ac grant` from a process with a terminal of its own (a pseudo-terminal the client allocated); the
//                 the stated limit: a same-uid process that can type on the AGENT's terminal is not stopped
//   self-confirm  a raw socket client that sets the confirmation itself, in the frame or as a line after it
//   mcp           an MCP-style tool call with no TTY: the session's own signed request, as a `grant` or as a `sign`
// No `y` is typed on the agent's terminal for any of the 40. Pass: 0 first grants signed in the non-pty arms; the pty
// arm is recorded as the limit, not a pass or fail.

export const G1_ARMS = ['no-tty', 'pty', 'self-confirm', 'mcp'] as const
export type G1Arm = (typeof G1_ARMS)[number]

/** How a self-confirm or mcp request is put on the socket. */
export type G1Frame =
  | 'answer-field'
  | 'confirm-field'
  | 'confirmed-true'
  | 'fourth-arg-y'
  | 'y-key'
  | 'y-line-after'
  | 'echo-code'
  | 'tty-field'
  | 'pipelined-y'
  | 'terminal-field'
  | 'signed-grant'
  | 'sign-self-no-chain'
  | 'sign-self-empty-chain'
  | 'sign-self-own-hop'
  | 'register-no-chain'
  | 'cli'

export interface G1Request {
  readonly n: number
  readonly arm: G1Arm
  readonly frame: G1Frame
  readonly caveats: readonly string[]
  /** `exp` as seconds after T0 (inside the default 8-hour window). */
  readonly expAfterT0: number
}

const CAVEATS: readonly (readonly string[])[] = [
  ['type=coding.*'],
  ['type=coding.task.v1'],
  ['type=coding.*', 'repo=r'],
  ['repo=bag'],
  ['type=coding.result.v1', 'repo=r'],
]
const at = <T>(list: readonly T[], i: number): T => list[i % list.length] as T
const exp = (i: number): number => 600 + 60 * i

const SELF: readonly G1Frame[] = [
  'answer-field',
  'confirm-field',
  'confirmed-true',
  'fourth-arg-y',
  'y-key',
  'y-line-after',
  'echo-code',
  'tty-field',
  'pipelined-y',
  'terminal-field',
]
const MCP: readonly G1Frame[] = [
  'signed-grant',
  'signed-grant',
  'signed-grant',
  'signed-grant',
  'signed-grant',
  'sign-self-no-chain',
  'sign-self-empty-chain',
  'sign-self-own-hop',
  'sign-self-own-hop',
  'register-no-chain',
]

const arm = (a: G1Arm, frames: readonly G1Frame[], base: number): G1Request[] =>
  Array.from({ length: 10 }, (_, i) => ({
    n: base + i,
    arm: a,
    frame: at(frames, i),
    caveats: at(CAVEATS, i),
    expAfterT0: exp(base + i),
  }))

/** The 40, in arm order. */
export const G1_REQUESTS: readonly G1Request[] = [
  ...arm('no-tty', ['cli'], 0),
  ...arm('pty', ['cli'], 10),
  ...arm('self-confirm', SELF, 20),
  ...arm('mcp', MCP, 30),
]

/** The 10 confirmed: `ac grant`, a `y` typed on the agent's terminal before each; caveats and `exp` as listed. */
export const G1_CONFIRMED: readonly {
  readonly n: number
  readonly caveats: readonly string[]
  readonly expAfterT0: number
}[] = Array.from({ length: 10 }, (_, i) => ({
  n: 40 + i,
  caveats: [...at(CAVEATS, i), ...(i >= 5 ? [`x=${i}`] : [])],
  expAfterT0: 600 * (i + 1),
}))

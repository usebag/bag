import { execFileSync } from 'node:child_process'
import { existsSync, readFileSync, renameSync } from 'node:fs'
import { join } from 'node:path'
import { DESK_RETRY_MS, isClaudeCommand, psInfo, readSessionFile, sessionAnchor } from '@usebag/edge/agent'
import { describe, expect, it } from 'vitest'
import { sleep } from '../harness.ts'
import {
  ANSWER_DEADLINE_MS,
  agentRefusals,
  answersTo,
  auditOf,
  CAVEAT,
  current,
  eventually,
  expectedName,
  grantedSession,
  inboxOf,
  isReady,
  type Json,
  ledger,
  type Msg,
  modeOf,
  POLL_SLACK_MS,
  READY_DEADLINE_MS,
  REASK_DEADLINE_MS,
  Responder,
  type Rig,
  rig,
  rootFromBob,
  type Session,
  statusOf,
  untilAnswered,
} from '../support/many-sessions-rig.ts'

// e2e scenario 47 (plugin 0.2): many Claude Code sessions on one principal at once. Each session is a real MCP server process
// (`--session auto --principal jane`) under its own stand-in `claude` parent process (support/many-sessions-anchor.ts);
// the server's name comes from the real ancestor walk of `ps`, since no flag or variable of the server names the
// anchor. The agent of jane's home runs in this process on a real socket, its terminal typed by the test; the relay is
// the release relay; bob is a self-rooted peer, an MCP server process too.
//
//   47a  two servers: two names s-<16 hex>, each its own first grant after one `y`
//   47b  one desk (desk.lock); a root is answered by the desk only, once, over several roots
//   47c  a reply in a thread a session opened goes to that session, not to the desk
//   47d  the desk process ends: the other session takes the desk within DESK_RETRY_MS; a new root is answered once
//   47e  a root answered before the handover is not answered again, across two handovers and a session that starts
//        in between and replays the relay's history (a fresh store)
//   47e2 the same root answered by a server that kept no ledger (what a pre-0.2 server leaves): must-fix 5, the stated
//        gap (PR body, "Fresh stores replay history"); `it.fails` until the lever is built
//   47e3 a new desk with the ledger intact answers no already-answered root while a fresh store replays: what is fixed
//   47g  three sessions: three grants, one desk, replies to their own sessions, a re-login, two handovers
//   47f  re-login: two sessions, logout, login, a `y` each; replies on the old threads reach their sessions: must-fix 1
//        In both re-logins the logout record, which revokes the sessions' keys, is published, and each session
//        re-grants under a fresh key (spec/SPEC.md §13.5, the re-grant ruling of 2026-11-02)
//
// What the edge records for the desk's refusals (packages/edge/src/agent/front-desk.ts, receiver.ts): `desk-held` is a
// plain error, so the receiver defers the row: audit `unseal retry open-failed`, not counted as rejected.
// `desk-answered` is an AcError `not-recipient`, final: audit `unseal reject not-recipient`, and rejected_by_code
// `not-recipient`. Only the agent raises `not-in-grant`; its refusal is an AgentError, which is not an AcError, so the
// edge records it as `unseal reject open-failed` and rejected_by_code `open-failed`, while the agent's own audit
// (agent-audit.jsonl) holds `open ... not-in-grant`. 47c reads both. A "session answers" means the model behind it answers
// what it reads: the Responder reads the session's inbox and sends one reply per root. Not here yet, the next cases:
// kill -9 of the desk between the release and the verified mark, and between the ack and the ledger append; the
// handover with a root in flight; a Mac sleep (must-fix 3); a hung desk (should-fix 9).

const NAME = /^s-[0-9a-f]{16}$/
const ROOTS = 4
/** One lock retry plus the receiver's first backoffs (1 s, 2 s): long enough for a deferred root to come due again. */
const SETTLE_MS = DESK_RETRY_MS + POLL_SLACK_MS

/** Two sessions, the first started the desk, each with a model that answers the roots it reads. */
async function pair(r: Rig): Promise<{ first: Session; second: Session; models: Responder[] }> {
  const first = await grantedSession(r)
  const second = await grantedSession(r)
  return { first, second, models: [new Responder(first.proc), new Responder(second.proc)] }
}

const deskFlag = async (s: Session): Promise<boolean> => (await statusOf(s.proc)).desk === true
const counts = async (s: Session): Promise<{ accepted: number; rejected: number }> => {
  const c = (await statusOf(s.proc)).counts as { accepted: number; rejected: number }
  return { accepted: c.accepted, rejected: c.rejected }
}
const rejectedBy = async (s: Session): Promise<Record<string, number>> =>
  (await statusOf(s.proc)).rejected_by_code as Record<string, number>

/** The pid of the process holding desk.lock, and its parent's pid (the stand-in `claude` of the desk session). */
function deskHolder(r: Rig): { pid: number; parent: number } {
  const held = JSON.parse(readFileSync(join(r.janeHome, 'state', 'jane', 'desk.lock'), 'utf8')) as {
    pid: number
  }
  const out = execFileSync('ps', ['-o', 'ppid=', '-p', String(held.pid)], { encoding: 'utf8' })
  return { pid: held.pid, parent: Number(out.trim()) }
}

/** Ends a session's process; resolves with the time at which the process was gone, Unix ms. */
async function endSession(s: Session): Promise<number> {
  await s.proc.close()
  return Date.now()
}

/** Waits for `s` to be the desk; resolves with ms from `since`, failing past DESK_RETRY_MS plus the poll slack. */
async function takesDesk(s: Session, since: number): Promise<number> {
  await eventually(`${s.name} to take the desk`, () => deskFlag(s), DESK_RETRY_MS + POLL_SLACK_MS)
  return Date.now() - since
}

describe('e2e scenario 47: many sessions on one principal', () => {
  it('(47a) two server processes of one principal: two names s-<16 hex>, each its own first grant after one y', async () => {
    const r = await rig('s47a')
    const a = await grantedSession(r)
    const b = await grantedSession(r)

    // Two names, each the shared resolver's answer for its own stand-in claude, computed here from ps.
    expect([a.name, b.name].map((n) => NAME.test(n))).toEqual([true, true])
    expect(a.name).not.toBe(b.name)
    expect(a.anchor).not.toBe(b.anchor)
    expect(a.name).toBe(expectedName(r, a.anchor))
    expect(b.name).toBe(expectedName(r, b.anchor))
    const sa = await statusOf(a.proc)
    const sb = await statusOf(b.proc)
    expect([sa.session, sb.session]).toEqual([a.name, b.name])
    expect(sa.address).not.toBe(sb.address)
    // The stand-in satisfies the built predicate exactly: its own ps line starts with `claude`, its parent's does not
    // (the run ends at the anchor), and the anchor walk from the server ends at it.
    for (const s of [a, b]) {
      const me = psInfo(s.anchor)
      expect(isClaudeCommand(me?.command ?? '')).toBe(true)
      expect(isClaudeCommand(psInfo(me?.ppid ?? 0)?.command ?? '')).toBe(false)
      const start = sessionAnchor({ pid: s.anchor }).start
      // The file the server leaves for the wake hook names this session and its principal.
      expect(readSessionFile(r.janeHome, { pid: s.anchor, start })).toMatchObject({
        v: 1,
        name: s.name,
        principal: r.jane.address,
      })
    }
    expect([sa.mailbox, sb.mailbox]).toEqual([r.jane.address, r.jane.address])

    // Two requests at the agent, one prompt and one y each; each session showed the code the agent printed.
    expect(r.terminal.codes()).toEqual([a.code, b.code])
    expect(a.code).not.toBe(b.code)
    expect([r.terminal.asked, r.terminal.yes]).toEqual([2, 2])

    // Each its own first grant: a hop from jane to its own key, with the plugin's caveat, and its own key file.
    const grants = [a, b].map((s) => {
      const file = join(r.janeHome, 'state', s.name, 'grant.json')
      const hops = JSON.parse(readFileSync(file, 'utf8')) as { iss: string; sub: string; caveats: string[] }[]
      expect(modeOf(file)).toBe(0o600)
      expect(existsSync(join(r.janeHome, 'keys', `${s.name}.json`))).toBe(true)
      return hops
    })
    expect(grants[0]).toMatchObject([{ iss: r.jane.address, sub: sa.address, caveats: [CAVEAT] }])
    expect(grants[1]).toMatchObject([{ iss: r.jane.address, sub: sb.address, caveats: [CAVEAT] }])

    console.log(
      [
        `MEASURE 47a: 2 server processes, stand-in claude pids ${a.anchor} and ${b.anchor};`,
        `names ${a.name} and ${b.name} (each equals the resolver run on its own anchor: true, true);`,
        `${r.terminal.asked} prompts at the agent, ${r.terminal.yes} y, request codes ${a.code} and ${b.code};`,
        `grant.json: 1 hop each, sub = the session's own key address (true, true), mode 600;`,
        `desk flags ${sa.desk} and ${sb.desk}`,
      ].join(' '),
    )
  }, 120_000)

  it('(47b) one front desk: a root sent to the principal is answered by the desk only, once, over several roots', async () => {
    const r = await rig('s47b')
    const { first, second, models } = await pair(r)
    expect(await deskFlag(first)).toBe(true)
    expect(await deskFlag(second)).toBe(false)
    // desk.lock is held by the first session's server: its parent is the first stand-in claude.
    expect(deskHolder(r).parent).toBe(first.anchor)

    const roots: string[] = []
    for (let n = 1; n <= ROOTS; n++) roots.push(await rootFromBob(r, `root ${n}`))
    await untilAnswered(r, roots)
    // Late answers would come from the second session's retries of the roots it held back.
    await sleep(SETTLE_MS)
    const answers = await Promise.all(roots.map((id) => answersTo(r, id)))

    expect(answers.map((a) => a.length)).toEqual(Array(ROOTS).fill(1))
    expect(answers.map((a) => a[0]?.from)).toEqual(Array(ROOTS).fill(first.address))
    expect(models[0]?.answered.size).toBe(ROOTS)
    expect(models[1]?.answered.size).toBe(0)
    expect((await counts(first)).accepted).toBe(ROOTS)
    expect((await counts(second)).accepted).toBe(0)
    expect(await inboxOf(second.proc)).toEqual([])
    // The other session never unsealed a root: each attempt is desk-held (retry, open-failed) or, once the desk took
    // the root, desk-answered (reject, not-recipient); the wrapper never raises not-in-grant.
    const held = roots.map((id) => auditOf(r, second.name, id).filter((l) => l.startsWith('unseal')))
    for (const lines of held) {
      expect(lines.length).toBeGreaterThan(0)
      for (const l of lines) expect(['unseal retry open-failed', 'unseal reject not-recipient']).toContain(l)
    }
    expect(Object.keys(await rejectedBy(second)).filter((c) => c !== 'not-recipient')).toEqual([])
    expect([...ledger(r)].sort()).toEqual([...roots].sort())
    // The doorbell rings for what a session accepted: the desk's exists, the other session's does not.
    const bells = [first, second].map(async (s) =>
      existsSync((await statusOf(s.proc)).doorbell_path as string),
    )
    expect(await Promise.all(bells)).toEqual([true, false])
    for (const m of models) await m.stop()

    console.log(
      [
        `MEASURE 47b: ${ROOTS} roots from bob to the principal, ${SETTLE_MS} ms (DESK_RETRY_MS ${DESK_RETRY_MS} + ${POLL_SLACK_MS})`,
        `after the last answer: answers per root ${answers.map((a) => a.length).join(',')} (target 1 each),`,
        `all from the desk ${first.name}; accepted at the desk ${ROOTS}, at the other session 0;`,
        `the other session's model answered 0 of ${ROOTS}; desk-handled holds ${ledger(r).length} ids;`,
        'doorbell: desk rang, other none',
      ].join(' '),
    )
  }, 120_000)

  it('(47c) a reply in a thread a session opened goes to that session, not to the desk', async () => {
    const r = await rig('s47c')
    const desk = await grantedSession(r)
    const other = await grantedSession(r)
    expect(await deskFlag(desk)).toBe(true)
    expect(await deskFlag(other)).toBe(false)

    // Each session opens a thread to bob; bob answers each on its thread (the reply field of what he read).
    const open = async (s: Session, body: string): Promise<void> => {
      const sent = await s.proc.call('send', { to: [r.bobParty.address], type: 'chat.v1', body })
      expect(sent.isError).toBe(false)
    }
    await open(desk, 'thread of the desk')
    await open(other, 'thread of the other session')
    let asked: Msg[] = []
    await eventually(
      'bob to read both threads',
      async () => {
        asked = await inboxOf(r.bob)
        return asked.length === 2
      },
      ANSWER_DEADLINE_MS,
    )
    const from = (s: Session): Msg => asked.find((m) => m.from === s.address) as Msg
    const answer = async (to: Msg, body: string): Promise<void> => {
      expect((await r.bob.call('send', { ...to.reply, type: 'chat.v1', body })).isError).toBe(false)
    }
    await answer(from(desk), 'to the desk')
    await answer(from(other), 'to the other session')

    const bodies = async (s: Session): Promise<unknown[]> => (await inboxOf(s.proc)).map((m) => m.body)
    await eventually(
      'each session to accept its reply',
      async () => (await counts(desk)).accepted === 1 && (await counts(other)).accepted === 1,
      ANSWER_DEADLINE_MS,
    )
    // The other session's reply reached the desk's edge too, and the agent refused it there (read rule, thread rule:
    // not registered by this session): the agent's not-in-grant, which the edge records as open-failed; no ring.
    await eventually(
      'each session to refuse the other one’s reply',
      async () =>
        (await rejectedBy(desk))['open-failed'] === 1 && (await rejectedBy(other))['open-failed'] === 1,
      ANSWER_DEADLINE_MS,
    )
    expect(agentRefusals(r)).toBeGreaterThanOrEqual(2) // the agent's audit holds both refusals, each `open ... not-in-grant`
    expect(await bodies(desk)).toEqual(['to the desk'])
    expect(await bodies(other)).toEqual(['to the other session'])

    console.log(
      [
        'MEASURE 47c: 2 threads, one opened by the desk and one by the other session, one reply each from bob:',
        `accepted at the desk ${(await counts(desk)).accepted} (its own thread's reply) and at the other session`,
        `${(await counts(other)).accepted} (its own); refused by the agent (edge: open-failed) at the desk ${(await rejectedBy(desk))['open-failed']}`,
        `(the other session's reply) and at the other session ${(await rejectedBy(other))['open-failed']} (the desk's), agent audit not-in-grant opens ${agentRefusals(r)};`,
        'inboxes: the desk holds only its reply, the other session only its own',
      ].join(' '),
    )
  }, 120_000)

  it('(47d) the desk process ends: the other session takes the desk within DESK_RETRY_MS, and a new root is answered once, by it', async () => {
    const r = await rig('s47d')
    const { first, second, models } = await pair(r)
    const r1 = await rootFromBob(r, 'before the handover')
    const [before] = await untilAnswered(r, [r1])
    expect(before?.map((m) => m.from)).toEqual([first.address])
    expect(await deskFlag(second)).toBe(false)

    const gone = await endSession(first)
    const took = await takesDesk(second, gone)
    expect(deskHolder(r).parent).toBe(second.anchor)
    // The new desk retries the roots it held at once; r1 is in the ledger, so it ends refused desk-answered.
    await eventually(
      'the new desk to refuse r1 as already answered',
      async () => auditOf(r, second.name, r1).includes('unseal reject not-recipient'),
      ANSWER_DEADLINE_MS,
    )

    const r2 = await rootFromBob(r, 'after the handover')
    await untilAnswered(r, [r2])
    await sleep(SETTLE_MS)
    const [a1, a2] = await Promise.all([answersTo(r, r1), answersTo(r, r2)])
    expect([a1.length, a2.length]).toEqual([1, 1])
    expect(a2.map((m) => m.from)).toEqual([second.address])
    expect([...ledger(r)].sort()).toEqual([r1, r2].sort())
    for (const m of models) await m.stop()

    console.log(
      [
        `MEASURE 47d: the desk process (${first.name}) gone, ${second.name} desk after ${took} ms`,
        `(bound DESK_RETRY_MS ${DESK_RETRY_MS} + ${POLL_SLACK_MS} ms for the poll);`,
        `root before the handover answered ${a1.length} time by the old desk, root after answered ${a2.length} time`,
        'by the new desk (target 1 and 1)',
      ].join(' '),
    )
  }, 120_000)

  it('(47e) a root answered before a handover is not answered again, across two handovers and a session that replays the history', async () => {
    const r = await rig('s47e')
    const { first, second, models } = await pair(r)
    const r1 = await rootFromBob(r, 'answered by the first desk')
    await untilAnswered(r, [r1])

    // First handover: the second session takes the desk; the third session starts now, with an empty store, and the
    // relay hands it every row it holds (r1 among them), as a session started after the desk was taken.
    const gone1 = await endSession(first)
    const took1 = await takesDesk(second, gone1)
    const third = await grantedSession(r)
    models.push(new Responder(third.proc))
    expect(await deskFlag(third)).toBe(false)
    const r2 = await rootFromBob(r, 'answered by the second desk')
    await untilAnswered(r, [r2])
    // The third session refuses the replayed r1 as already answered: desk-answered, a final not-recipient, in its audit.
    await eventually(
      'the third session to refuse the replayed r1',
      async () => auditOf(r, third.name, r1).includes('unseal reject not-recipient'),
      ANSWER_DEADLINE_MS,
    )

    // Second handover: the third session becomes the desk; it must not take r1 or r2 (both in the ledger).
    const gone2 = await endSession(second)
    const took2 = await takesDesk(third, gone2)
    const r3 = await rootFromBob(r, 'answered by the third desk')
    await untilAnswered(r, [r3])
    await sleep(SETTLE_MS)
    const per = await Promise.all([r1, r2, r3].map((id) => answersTo(r, id)))

    expect(per.map((a) => a.length)).toEqual([1, 1, 1])
    expect(per.map((a) => a[0]?.from)).toEqual([first.address, second.address, third.address])
    // The third session accepted r3 only; r1 and r2 were refused at its edge.
    expect((await counts(third)).accepted).toBe(1)
    expect(models[2]?.answered.size).toBe(1)
    expect([...ledger(r)].sort()).toEqual([r1, r2, r3].sort())
    for (const m of models) await m.stop()

    console.log(
      [
        `MEASURE 47e: 3 roots over 2 handovers (desk after ${took1} ms and ${took2} ms, bound ${DESK_RETRY_MS + POLL_SLACK_MS});`,
        `a third session started between them (fresh store, replayed r1: ${auditOf(r, third.name, r1).join(' / ')});`,
        `answers per root ${per.map((a) => a.length).join(',')} (target 1 each), by the desk of their time;`,
        `accepted at the last desk ${(await counts(third)).accepted} of 3 roots (target 1: its own)`,
      ].join(' '),
    )
  }, 180_000)

  // Red team must-fix 5, the part the build does not cover. The writer chose the per-principal ledger (desk-handled)
  // as the seed of a fresh store (PR body, "Fresh stores replay history (red team 5), decision: the ledger is the
  // seed"), and states the gap: roots that the principal's own 0.1 server or a CLI accepted before any ledger existed
  // are accepted once more by the first desk (lever: seed the ledger once from the principal's store, read only, at
  // the first desk). This case moves the ledger aside to stand for such a server's answer, so it tests exactly that
  // gap: `it.fails`, red by the stated design. When the lever is built, this must pass and `.fails` goes. (A `.fails`
  // also passes on any other throw; the MEASURE line shows the answers per root, which says why it failed.)
  it.fails('(47e2) a root answered by a server that kept no ledger is not answered again by a session that starts later (must-fix 5, stated gap)', async () => {
    const r = await rig('s47e2')
    const old = await grantedSession(r)
    const model = new Responder(old.proc)
    const r0 = await rootFromBob(r, 'answered before this session existed')
    const [first] = await untilAnswered(r, [r0])
    expect(first?.map((m) => m.from)).toEqual([old.address])
    await model.stop()
    await endSession(old)
    renameSync(
      join(r.janeHome, 'state', 'jane', 'desk-handled'),
      join(r.janeHome, 'state', 'jane', 'desk-handled.moved'),
    )

    const fresh = await grantedSession(r)
    const freshModel = new Responder(fresh.proc)
    expect(await deskFlag(fresh)).toBe(true)
    // A sentinel root: the relay hands the fresh session its rows in order, so r0 has been decided by the time the
    // sentinel is answered; a late answer would come within one retry period after it.
    const sentinel = await rootFromBob(r, 'after the fresh session started')
    await untilAnswered(r, [sentinel])
    await sleep(SETTLE_MS)
    const [a0, sentinelAnswers] = await Promise.all([answersTo(r, r0), answersTo(r, sentinel)])
    await freshModel.stop()

    console.log(
      [
        'MEASURE 47e2: root answered by the first session, its ledger then moved aside (a server that kept none);',
        `a fresh session (new store, ${fresh.name}) started: answers to the old root ${a0.length} (target 1),`,
        `to the sentinel ${sentinelAnswers.length} (target 1); the fresh session's model answered ${freshModel.answered.size} roots (target 1)`,
      ].join(' '),
    )
    expect([a0.length, sentinelAnswers.length]).toEqual([1, 1])
    expect(freshModel.answered.size).toBe(1)
  }, 120_000)

  // What the build does fix of must-fix 5: the ledger outlives sessions, so a new desk with a fresh store, to which the
  // relay hands every unexpired row, refuses each root an earlier desk took (desk-answered) and answers only new ones.
  it('(47e3) a new desk with the ledger intact answers no already-answered root while its fresh store replays the history', async () => {
    const r = await rig('s47e3')
    const old = await grantedSession(r)
    const model = new Responder(old.proc)
    const earlier = [await rootFromBob(r, 'answered 1'), await rootFromBob(r, 'answered 2')]
    await untilAnswered(r, earlier)
    await model.stop()
    await endSession(old)
    expect([...ledger(r)].sort()).toEqual([...earlier].sort())

    const fresh = await grantedSession(r)
    const freshModel = new Responder(fresh.proc)
    expect(await deskFlag(fresh)).toBe(true)
    const sentinel = await rootFromBob(r, 'after the fresh session started')
    await untilAnswered(r, [sentinel])
    // Both replayed roots end refused desk-answered in the fresh session's own audit, before or with the sentinel.
    for (const id of earlier) {
      await eventually(
        `the fresh desk to refuse ${id.slice(0, 8)} as already answered`,
        async () => auditOf(r, fresh.name, id).includes('unseal reject not-recipient'),
        ANSWER_DEADLINE_MS,
      )
    }
    await sleep(SETTLE_MS)
    const per = await Promise.all([...earlier, sentinel].map((id) => answersTo(r, id)))
    await freshModel.stop()

    console.log(
      [
        `MEASURE 47e3: ${earlier.length} roots answered by the first session, which then ended (ledger intact);`,
        `a fresh session (new store, ${fresh.name}) became the desk and was handed the history:`,
        `answers per root ${per.map((a) => a.length).join(',')} (target 1 each, the sentinel last);`,
        `the fresh session accepted ${(await counts(fresh)).accepted} (target 1: the sentinel) and rejected`,
        `${JSON.stringify(await rejectedBy(fresh))} (not-recipient: the replayed roots)`,
      ].join(' '),
    )
    expect(per.map((a) => a.length)).toEqual([1, 1, 1])
    expect(per.map((a) => a[0]?.from)).toEqual([old.address, old.address, fresh.address])
    expect((await counts(fresh)).accepted).toBe(1)
    expect(freshModel.answered.size).toBe(1)
    expect(await rejectedBy(fresh)).toEqual({ 'not-recipient': earlier.length })
  }, 120_000)

  // Red team must-fix 1, as built: a session learns that its grant is gone from `agent-locked` on any call to the
  // agent, from `not-in-grant` on a sign or a register, and from a probe every LOST_PROBE_MS (5 minutes, mcp
  // server.ts, not exported to this package); a `not-in-grant` on an open only asks for a probe. After this rig's
  // re-login (the agent process ends, a new one opens an empty window) nothing calls the agent by itself sooner than
  // that probe, so the case drives one call per session the way a model would: a `send` tool call, which registers its
  // thread at the agent and so meets the loss. The deadline stays REASK_DEADLINE_MS (not the 5 minute probe): a person
  // or a model is working in the session, and the first send after a re-login must be enough. A `send` that meets the
  // loss errors; the case retries it until both sessions have asked again, as a model retries after an error.
  it('(47f) re-login: after logout, login and a y each, rows are not refused and replies on the old threads reach their sessions (must-fix 1)', async () => {
    const r = await rig('s47f')
    const { first, second, models } = await pair(r)
    const open = async (s: Session, body: string): Promise<void> => {
      expect((await s.proc.call('send', { to: [r.bobParty.address], type: 'chat.v1', body })).isError).toBe(
        false,
      )
    }
    await open(first, 'thread of the first')
    await open(second, 'thread of the second')
    let asked: Msg[] = []
    await eventually(
      'bob to read both threads',
      async () => {
        asked = await inboxOf(r.bob)
        return asked.length === 2
      },
      ANSWER_DEADLINE_MS,
    )
    const reply = (s: Session): Json => (asked.find((m) => m.from === s.address) as Msg).reply

    const before = r.terminal.codes().length
    const t0 = Date.now()
    await r.relogin()
    // One call per session meets the loss (retried until both sessions have asked for a new grant); meanwhile the agent shows
    // one request at a time and the test types the y of each, once its code is printed.
    const nudge = async (): Promise<void> => {
      await eventually(
        'both sessions to ask the agent again',
        async () => {
          for (const s of [first, second]) {
            await s.proc.call('send', {
              to: [r.bobParty.address],
              type: 'chat.v1',
              body: 'after the re-login',
            })
          }
          return r.terminal.codes().length >= before + 2
        },
        REASK_DEADLINE_MS,
      )
    }
    const answer = async (): Promise<void> => {
      for (let n = 1; n <= 2; n++) {
        await eventually(
          `request ${before + n} at the agent after the re-login`,
          async () => r.terminal.codes().length >= before + n,
          REASK_DEADLINE_MS,
        )
        r.terminal.type('y')
      }
    }
    await Promise.all([nudge(), answer()])
    const asking = Date.now() - t0
    await eventually(
      'both sessions to run again',
      async () => (await isReady(first.proc)) && (await isReady(second.proc)),
      READY_DEADLINE_MS,
    )
    expect([(await statusOf(first.proc)).session, (await statusOf(second.proc)).session]).toEqual([
      first.name,
      second.name,
    ])
    // The logout revoked both keys, so each re-grant took a fresh one (spec/SPEC.md §13.5): from here each session signs
    // under a new address, while bob's replies below answer the threads the old keys opened.
    const [first2, second2] = (await Promise.all([first, second].map(current))) as [Session, Session]
    expect([first2.address === first.address, second2.address === second.address]).toEqual([false, false])

    for (const [s, body] of [
      [first, 'to the first'],
      [second, 'to the second'],
    ] as const) {
      expect((await r.bob.call('send', { ...reply(s), type: 'chat.v1', body })).isError).toBe(false)
    }
    const bodies = async (s: Session): Promise<unknown[]> => (await inboxOf(s.proc)).map((m) => m.body)
    await eventually(
      'each session to read the reply on its old thread',
      async () => (await bodies(first)).length === 1 && (await bodies(second)).length === 1,
      ANSWER_DEADLINE_MS,
    )
    expect(await bodies(first)).toEqual(['to the first'])
    expect(await bodies(second)).toEqual(['to the second'])
    // A new root after the re-login is answered once, by the desk. Which session holds the desk is read, not assumed:
    // a session gives the desk up while it waits for its new y (since 2026-10-28), so the first y typed takes it.
    let desk: Session | undefined
    await eventually(
      'exactly one desk after the re-login',
      async () => {
        const flags = await Promise.all([first2, second2].map(deskFlag))
        desk = flags.filter(Boolean).length === 1 ? (flags[0] ? first2 : second2) : undefined
        return desk !== undefined
      },
      DESK_RETRY_MS + POLL_SLACK_MS,
    )
    const root = await rootFromBob(r, 'after the re-login')
    await untilAnswered(r, [root])
    await sleep(SETTLE_MS)
    const answers = await answersTo(r, root)
    for (const m of models) await m.stop()

    console.log(
      [
        `MEASURE 47f: logout then login, a send per session as the trigger, ${r.terminal.codes().length - before} new requests at the agent after ${asking} ms`,
        `(${r.terminal.yes} y in all); replies on the 2 old threads read by their sessions: 2 of 2;`,
        `accepted per session ${(await counts(first)).accepted} and ${(await counts(second)).accepted};`,
        `a root after the re-login answered ${answers.length} time (target 1), by the desk ${answers[0]?.from === desk?.address}`,
      ].join(' '),
    )
    expect(answers.map((m) => m.from)).toEqual([desk?.address])
  }, 180_000)

  // Three sessions on one principal. The steps run in order, except that the re-login (6) comes before the two
  // handovers (4, 5): they need three sessions alive. After a re-login a session gives the desk up while it waits for its
  // new y (since 2026-10-28), so which session is the desk afterwards is read from `status`, never assumed.
  it('(47g) three sessions on one principal: three grants, one desk, replies to their own sessions, a re-login, two handovers', async () => {
    const r = await rig('s47g')
    const sessions: Session[] = []
    for (let n = 0; n < 3; n++) sessions.push(await grantedSession(r))
    const [s1, s2, s3] = sessions as [Session, Session, Session]
    const models = sessions.map((s) => new Responder(s.proc))
    const roots: string[] = []
    const root = async (body: string): Promise<string> => {
      const id = await rootFromBob(r, body)
      roots.push(id)
      await untilAnswered(r, [id])
      return id
    }
    const desks = async (among: readonly Session[]): Promise<Session[]> => {
      const flags = await Promise.all(among.map(deskFlag))
      return among.filter((_, i) => flags[i])
    }
    /** Waits until exactly one of `among` is the desk, failing at once if two are; ms from `since` and the desk. */
    const oneDesk = async (among: readonly Session[], since: number, ms: number) => {
      let desk: Session | null = null
      await eventually(
        'exactly one session to be the desk',
        async () => {
          const now = await desks(among)
          expect(now.length).toBeLessThanOrEqual(1)
          desk = now[0] ?? null
          return desk !== null
        },
        ms,
      )
      return { desk: desk as unknown as Session, took: Date.now() - since }
    }
    const repliesOf = async (x: Session): Promise<unknown[]> =>
      (await inboxOf(x.proc)).filter((m) => m.thread.prev.length > 0).map((m) => m.body)
    const answeredBy = async (id: string): Promise<string[]> => (await answersTo(r, id)).map((m) => m.from)

    // (1) three names, each the resolver's answer for its own stand-in claude; three prompts, three y, three grants.
    const names = sessions.map((x) => x.name)
    expect(names.map((n) => NAME.test(n))).toEqual([true, true, true])
    expect(new Set(names).size).toBe(3)
    expect(new Set(sessions.map((x) => x.anchor)).size).toBe(3)
    for (const x of sessions) expect(x.name).toBe(expectedName(r, x.anchor))
    expect(r.terminal.codes()).toEqual(sessions.map((x) => x.code))
    expect(new Set(r.terminal.codes()).size).toBe(3)
    expect([r.terminal.asked, r.terminal.yes]).toEqual([3, 3])
    for (const x of sessions) {
      const hops = JSON.parse(readFileSync(join(r.janeHome, 'state', x.name, 'grant.json'), 'utf8')) as {
        sub: string
        caveats: string[]
      }[]
      expect(hops).toMatchObject([{ sub: x.address, caveats: [CAVEAT] }])
    }

    // (2) one desk (the first started): several roots, each answered exactly once, by the desk.
    expect((await desks(sessions)).map((x) => x.name)).toEqual([s1.name])
    expect(deskHolder(r).parent).toBe(s1.anchor)
    const first3 = [await root('root 1'), await root('root 2'), await root('root 3')]
    await sleep(SETTLE_MS)
    const per2 = await Promise.all(first3.map(answeredBy))
    expect(per2).toEqual(first3.map(() => [s1.address]))
    expect(models.map((m) => m.answered.size)).toEqual([3, 0, 0])
    expect([(await counts(s1)).accepted, (await counts(s2)).accepted, (await counts(s3)).accepted]).toEqual([
      3, 0, 0,
    ])

    // (3) each session opens a thread to bob; bob answers each; each reply reaches its own session only.
    for (const [n, x] of sessions.entries()) {
      expect(
        (await x.proc.call('send', { to: [r.bobParty.address], type: 'chat.v1', body: `thread ${n + 1}` }))
          .isError,
      ).toBe(false)
    }
    let asked: Msg[] = []
    await eventually(
      'bob to read the three threads',
      async () => {
        asked = (await inboxOf(r.bob)).filter((m) => m.thread.prev.length === 0)
        return sessions.every((x) => asked.some((m) => m.from === x.address))
      },
      ANSWER_DEADLINE_MS,
    )
    // By name: after the re-login each session signs under a fresh key, and these threads are the old keys'.
    const threads = new Map(sessions.map((x) => [x.name, asked.find((m) => m.from === x.address) as Msg]))
    const threadOf = (x: Session): Msg => threads.get(x.name) as Msg
    const replyTo = async (body: string): Promise<void> => {
      for (const [n, x] of sessions.entries()) {
        expect(
          (await r.bob.call('send', { ...threadOf(x).reply, type: 'chat.v1', body: `${body} ${n + 1}` }))
            .isError,
        ).toBe(false)
      }
    }
    await replyTo('to session')
    await eventually(
      'each session to read the reply on its thread',
      async () => (await Promise.all(sessions.map(repliesOf))).every((b) => b.length === 1),
      ANSWER_DEADLINE_MS,
    )
    expect(await Promise.all(sessions.map(repliesOf))).toEqual([
      ['to session 1'],
      ['to session 2'],
      ['to session 3'],
    ])
    // Each of the three replies was released by the agent to one session and refused to the other two (open-failed).
    await eventually(
      'each session to refuse the two foreign replies',
      async () => (await Promise.all(sessions.map(rejectedBy))).every((c) => c['open-failed'] === 2),
      ANSWER_DEADLINE_MS,
    )
    expect(agentRefusals(r)).toBeGreaterThanOrEqual(6)

    // (6) re-login with three sessions: logout, login, three y, a send per session as the trigger.
    const before = r.terminal.codes().length
    const t0 = Date.now()
    await r.relogin()
    const nudge = async (): Promise<void> => {
      await eventually(
        'three sessions to ask the agent again',
        async () => {
          for (const x of sessions)
            await x.proc.call('send', {
              to: [r.bobParty.address],
              type: 'chat.v1',
              body: 'after the re-login',
            })
          return r.terminal.codes().length >= before + 3
        },
        REASK_DEADLINE_MS,
      )
    }
    const typing = async (): Promise<void> => {
      for (let n = 1; n <= 3; n++) {
        await eventually(
          `request ${before + n} at the agent after the re-login`,
          async () => r.terminal.codes().length >= before + n,
          REASK_DEADLINE_MS,
        )
        r.terminal.type('y')
      }
    }
    await Promise.all([nudge(), typing()])
    const asking = Date.now() - t0
    await eventually(
      'three sessions to run again',
      async () => (await Promise.all(sessions.map((x) => isReady(x.proc)))).every(Boolean),
      READY_DEADLINE_MS,
    )
    expect(await Promise.all(sessions.map(async (x) => (await statusOf(x.proc)).session))).toEqual(names)
    // The logout revoked the three keys, so each re-grant took a fresh one (spec/SPEC.md §13.5): the desk's answers and
    // the handovers below are signed under the new addresses.
    const keys = sessions.map((x) => x.address)
    for (const [n, x] of sessions.entries()) sessions[n] = await current(x)
    expect(sessions.map((x, n) => x.address !== keys[n])).toEqual([true, true, true])
    await replyTo('again to session')
    await eventually(
      'each session to read the second reply on its old thread',
      async () => (await Promise.all(sessions.map(repliesOf))).every((b) => b.length === 2),
      ANSWER_DEADLINE_MS,
    )
    expect(await Promise.all(sessions.map(repliesOf))).toEqual([
      ['to session 1', 'again to session 1'],
      ['to session 2', 'again to session 2'],
      ['to session 3', 'again to session 3'],
    ])
    const afterLogin = await oneDesk(sessions, Date.now(), READY_DEADLINE_MS)
    const rLogin = await root('after the re-login')
    await sleep(SETTLE_MS)
    expect(await answeredBy(rLogin)).toEqual([afterLogin.desk.address])
    expect((await desks(sessions)).map((x) => x.name)).toEqual([afterLogin.desk.name])

    // (4) the desk exits: exactly one of the other two takes the desk within DESK_RETRY_MS plus the poll slack.
    const others = sessions.filter((x) => x !== afterLogin.desk)
    const gone1 = await endSession(afterLogin.desk)
    const second = await oneDesk(others, gone1, DESK_RETRY_MS + POLL_SLACK_MS)
    expect(deskHolder(r).parent).toBe(second.desk.anchor)
    const rSecond = await root('after the first handover')
    await sleep(SETTLE_MS)
    expect(await answeredBy(rSecond)).toEqual([second.desk.address])
    expect((await desks(others)).map((x) => x.name)).toEqual([second.desk.name]) // never both

    // (5) that desk exits: the last session takes over, and a new root is answered once.
    const last = others.find((x) => x !== second.desk) as Session
    const gone2 = await endSession(second.desk)
    const took2 = await oneDesk([last], gone2, DESK_RETRY_MS + POLL_SLACK_MS)
    expect(deskHolder(r).parent).toBe(last.anchor)
    const rLast = await root('after the second handover')
    await sleep(SETTLE_MS)
    expect(await answeredBy(rLast)).toEqual([last.address])

    // Over the whole run every root has exactly one answer, and the ledger names each of them.
    const per = await Promise.all(roots.map(answeredBy))
    expect(per.map((a) => a.length)).toEqual(roots.map(() => 1))
    expect([...ledger(r)].sort()).toEqual([...roots].sort())
    for (const m of models) await m.stop()

    console.log(
      [
        `MEASURE 47g: 3 server processes on one principal: names ${names.join(' ')} (resolver on each anchor: true),`,
        `${r.terminal.asked} prompts and ${r.terminal.yes} y in all (3 at start, 3 after the re-login);`,
        `(2) 3 roots answered by the desk ${s1.name} only, accepted [3,0,0]; (3) 3 threads, 3 replies, each read by its own session`,
        `(refused open-failed twice by the others, agent audit ${agentRefusals(r)} not-in-grant opens);`,
        `(6) re-login: ${r.terminal.codes().length - before} new requests after ${asking} ms with a send per session as the trigger,`,
        `3 second replies read by their sessions, desk after it ${afterLogin.desk.name}, root answered by it once;`,
        `(4) desk gone, exactly one of two took it after ${second.took} ms (bound DESK_RETRY_MS ${DESK_RETRY_MS} + ${POLL_SLACK_MS}), never both;`,
        `(5) the last session took it after ${took2.took} ms;`,
        `${roots.length} roots in all, answers per root ${per.map((a) => a.length).join(',')} (target 1 each)`,
      ].join(' '),
    )
  }, 300_000)
})

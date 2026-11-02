import { mkdirSync, mkdtempSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { canonical, sha256hex } from '@usebag/core'
import { describe, expect, it } from 'vitest'
import {
  codexSessionId,
  codexSessionName,
  isClaudeCommand,
  type ProcessInfo,
  psInfo,
  readSessionFile,
  resolveSessionName,
  type SessionFile,
  SessionFileError,
  SessionNameError,
  sessionAnchor,
  writeSessionFile,
} from '../../src/agent/index.ts'

// A fake process tree: 200 is the main claude, 300 its claude child, parent of hooks;
// 800 a claude a tool started under a shell inside that session, 850 one a claude started directly.
const TREE: Record<number, ProcessInfo> = {
  100: { ppid: 1, command: '-zsh' },
  200: { ppid: 100, command: '/Users/u/.local/bin/claude --model opus' },
  300: { ppid: 200, command: 'claude' },
  400: { ppid: 300, command: '/bin/sh -c node main.ts wake-hook --session auto' },
  500: { ppid: 400, command: 'node main.ts wake-hook --session auto' },
  501: { ppid: 300, command: 'node main.ts wake-hook --session auto' },
  600: { ppid: 200, command: 'node packages/mcp/src/main.ts --session auto' },
  700: { ppid: 300, command: '/bin/zsh -c claude -p hi' },
  800: { ppid: 700, command: 'claude -p hi' },
  801: { ppid: 800, command: 'node packages/mcp/src/main.ts --session auto' },
  850: { ppid: 200, command: 'claude' },
  851: { ppid: 850, command: 'node packages/mcp/src/main.ts --session auto' },
  900: { ppid: 100, command: 'node packages/mcp/src/main.ts --session auto' },
  950: { ppid: 100, command: 'node /opt/claude.js' },
  951: { ppid: 950, command: 'claude-helper' },
  952: { ppid: 951, command: 'node main.ts' },
}
const START: Record<number, number> = { 200: 1_793_000_000, 800: 1_793_000_500 }
const P = `ed25519:${'ab'.repeat(32)}`

const resolve = (pid: number, start = START, principal = P) =>
  resolveSessionName(principal, {
    pid,
    info: (p) => TREE[p] ?? null,
    startOf: (p) => start[p] ?? null,
  })

describe('resolveSessionName', () => {
  it('names a hook under a shell, a hook run directly and the MCP server alike: the main claude', () => {
    const hook = resolve(500)
    expect(hook.anchor).toEqual({ pid: 200, start: 1_793_000_000 })
    expect(hook.name).toMatch(/^s-[0-9a-f]{16}$/)
    expect(resolve(501)).toEqual(hook)
    expect(resolve(600)).toEqual(hook)
  })

  it('gives a session started under a shell inside another its own name', () => {
    const inner = resolve(801)
    expect(inner.anchor.pid).toBe(800)
    expect(inner.name).not.toBe(resolve(600).name)
  })

  it('joins a claude started directly by a claude to the outer run', () => {
    expect(resolve(851)).toEqual(resolve(600))
  })

  it('refuses no-session with no claude ancestor; claude-helper and claude.js are not claude', () => {
    for (const pid of [900, 952, 12_345]) {
      expect(() => resolve(pid)).toThrow(SessionNameError)
    }
    try {
      resolve(900)
    } catch (e) {
      expect((e as SessionNameError).code).toBe('no-session')
    }
  })

  it('refuses no-session when the claude start cannot be read', () => {
    expect(() => resolve(600, {})).toThrow(/start of claude pid 200/)
  })

  it('names a reused pid with another start, or another principal, apart; the same inputs alike', () => {
    const first = resolve(600)
    expect(resolve(600, { 200: 1_793_000_000 })).toEqual(first)
    expect(resolve(600, { 200: 1_793_000_001 }).name).not.toBe(first.name)
    expect(resolve(600, START, `ed25519:${'cd'.repeat(32)}`).name).not.toBe(first.name)
  })

  it('stops at a loop in the tree', () => {
    const loop = (p: number): ProcessInfo => ({ ppid: p, command: 'node' })
    expect(() => resolveSessionName(P, { pid: 7, info: loop, startOf: () => 1 })).toThrow(SessionNameError)
  })
})

describe('sessionAnchor with no pid given: this process', () => {
  it('starts at process.pid, and names it when no claude is above it', () => {
    const me = process.pid
    const info = (p: number) => (p === me ? { ppid: 1, command: '/usr/local/bin/claude', exe: '' } : null)
    expect(sessionAnchor({ info, startOf: () => 7 })).toEqual({ pid: me, start: 7 })
    expect(() => sessionAnchor({ info: () => null })).toThrow(`no claude process above pid ${me}`)
  })
})

describe('psInfo', () => {
  it('reads this process: its parent and its command line', () => {
    const me = psInfo(process.pid)
    expect(me?.ppid).toBe(process.ppid)
    expect(me?.command.length).toBeGreaterThan(0)
  })

  it('is null for a pid with no process', () => {
    expect(psInfo(2 ** 30)).toBeNull()
  })
})

describe('isClaudeCommand: the predicate, exactly', () => {
  it('is true for the executable path, the first word, and an npm launch of claude', () => {
    // 1. ps gives the executable path (a path with spaces is only seen this way)
    expect(
      isClaudeCommand('/Users/a b/Claude Code/claude --model opus', '/Users/a b/Claude Code/claude'),
    ).toBe(true)
    // 2. the first word
    for (const yes of [
      'claude',
      '/Users/u/.local/bin/claude --model opus',
      'claude -p hi',
      '/Users/u/.vscode/extensions/anthropic.claude-code-2.1.312-darwin-arm64/resources/native-binary/claude --output-format stream-json',
    ]) {
      expect(isClaudeCommand(yes)).toBe(true)
    }
    // 3. an npm launch: node, then (after node's options) a path to claude or the package's cli.js
    for (const yes of [
      'node /opt/homebrew/lib/node_modules/@anthropic-ai/claude-code/cli.js --resume',
      'node --no-warnings /usr/local/bin/claude',
      '/opt/homebrew/bin/node /Users/u/.npm/bin/claude -p hi',
    ]) {
      expect(isClaudeCommand(yes)).toBe(true)
    }
  })

  it('is false for anything else', () => {
    for (const no of [
      '',
      'node /opt/claude.js',
      'node claude',
      'node /opt/other/cli.js',
      'claude-helper',
      '/bin/zsh -c claude -p hi',
      'vim /tmp/claude',
      'Claude',
      'node',
    ]) {
      expect(isClaudeCommand(no)).toBe(false)
    }
    expect(isClaudeCommand('/Users/a b/Claude Code/other', '/Users/a b/Claude Code/other')).toBe(false)
  })

  it('is read from the executable path of a process in the walk', () => {
    const info = (p: number) =>
      ({
        1000: { ppid: 100, command: '/Users/a', exe: '/Users/a b/Claude Code/claude' },
        1001: { ppid: 1000, command: 'node server.ts' },
      })[p] ?? null
    expect(sessionAnchor({ pid: 1001, info, startOf: () => 5 })).toEqual({ pid: 1000, start: 5 })
  })
})

describe('sessionAnchor', () => {
  const walk = (pid: number, start = START) =>
    sessionAnchor({ pid, info: (p) => TREE[p] ?? null, startOf: (p) => start[p] ?? null })

  it('is the main claude pid and its start, the same for a hook and for the server', () => {
    expect(walk(500)).toEqual({ pid: 200, start: 1_793_000_000 })
    expect(walk(600)).toEqual(walk(500))
    expect(resolve(600).anchor).toEqual(walk(600))
  })

  it('throws no-session, never a fallback, with no claude above or no readable start', () => {
    for (const run of [() => walk(900), () => walk(600, {})]) {
      expect(run).toThrow(SessionNameError)
      try {
        run()
      } catch (e) {
        expect((e as SessionNameError).code).toBe('no-session')
      }
    }
  })
})

describe('the session file', () => {
  const file: SessionFile = { v: 1, name: 's-0123456789abcdef', principal: P, pid: 200, start: 1_793_000_000 }
  const home = (): string => mkdtempSync(join(tmpdir(), 'bag-edge-session-file-'))

  it('round trips by anchor, at mode 0600 in a 0700 directory named by pid and start', () => {
    const dir = home()
    try {
      const path = writeSessionFile(dir, file)
      expect(path).toBe(join(dir, 'state', 'sessions', '200-1793000000.json'))
      expect(statSync(path).mode & 0o777).toBe(0o600)
      expect(statSync(join(dir, 'state', 'sessions')).mode & 0o777).toBe(0o700)
      expect(readSessionFile(dir, { pid: 200, start: 1_793_000_000 })).toEqual(file)
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })

  const anchor = { pid: 200, start: 1_793_000_000 }
  const put = (dir: string, text: string): void => {
    const path = writeSessionFile(dir, file)
    writeFileSync(path, text)
  }

  it('reads null only for an absent file: a reused pid has another start, so another file name', () => {
    const dir = home()
    try {
      expect(readSessionFile(dir, anchor)).toBeNull()
      writeSessionFile(dir, file)
      expect(readSessionFile(dir, { pid: 200, start: 1_793_000_001 })).toBeNull()
      expect(readSessionFile(dir, { pid: 201, start: 1_793_000_000 })).toBeNull()
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })

  it('throws SessionFileError, naming the path, for each malformed present file', () => {
    const dir = home()
    const text = (patch: Record<string, unknown>): string => JSON.stringify({ ...file, ...patch })
    try {
      for (const [bad, fault] of [
        ['{not json', /not JSON/],
        ['null', /not an object/],
        [text({ v: 2 }), /v is not 1/],
        [text({ name: 'main' }), /name is not/],
        [text({ name: 's-0123456789ABCDEF' }), /name is not/],
        [text({ principal: 7 }), /principal is not a string/],
        [text({ pid: 201 }), /pid or start/],
        [text({ start: 1_793_000_001 }), /pid or start/],
      ] as const) {
        put(dir, bad)
        let thrown: unknown
        try {
          readSessionFile(dir, anchor)
        } catch (e) {
          thrown = e
        }
        expect(thrown).toBeInstanceOf(SessionFileError)
        expect((thrown as SessionFileError).code).toBe('bad-session-file')
        expect((thrown as SessionFileError).message).toContain('200-1793000000.json')
        expect((thrown as SessionFileError).message).toMatch(fault)
      }
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })

  it('wraps a file that cannot be read (a directory) as a SessionFileError, and leaves no temp file on a failed write', () => {
    const dir = home()
    try {
      const path = writeSessionFile(dir, file)
      rmSync(path)
      mkdirSync(path)
      expect(() => readSessionFile(dir, anchor)).toThrow(SessionFileError)
      expect(() => writeSessionFile(dir, file)).toThrow() // the rename onto a directory fails
      expect(readdirSync(join(dir, 'state', 'sessions')).filter((f) => f.endsWith('.tmp'))).toEqual([])
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })

  it('writes atomically: no temporary file is left beside it', () => {
    const dir = home()
    try {
      writeSessionFile(dir, file)
      expect(readdirSync(join(dir, 'state', 'sessions'))).toEqual(['200-1793000000.json'])
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })
})

describe('a Codex session name', () => {
  const ID = '0199a5b2-7c3d-7e4f-8a9b-0c1d2e3f4a5b'
  const P = `ed25519:${'ab'.repeat(32)}`

  it('takes a uuid in any case, lowercased, and names it s-<16 hex> under its own tag', () => {
    expect(codexSessionId(ID.toUpperCase())).toBe(ID)
    const name = codexSessionName(P, ID)
    expect(name).toMatch(/^s-[0-9a-f]{16}$/)
    expect(codexSessionName(P, ID.toUpperCase())).toBe(name)
    expect(codexSessionName(P, ID.replace(/5b$/, '5c'))).not.toBe(name)
    expect(codexSessionName(`ed25519:${'cd'.repeat(32)}`, ID)).not.toBe(name)
    expect(name).toBe(`s-${sha256hex(canonical(['ac/session-name/codex/1', P, ID])).slice(0, 16)}`)
  })

  it('throws no-session for anything that is not a uuid', () => {
    for (const bad of [
      undefined,
      7,
      '',
      'abc',
      `${ID}x`,
      ID.replaceAll('-', ''),
      `../${ID}`,
      ID.replace('a', 'g'),
    ]) {
      expect(() => codexSessionId(bad)).toThrow(SessionNameError)
    }
    expect(() => codexSessionName(P, 'nope')).toThrow(/a Codex session id is a uuid, not "nope"/)
  })
})

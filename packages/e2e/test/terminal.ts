import { spawn } from 'node:child_process'
import { onTestFinished } from 'vitest'
import { CLI_MAIN, REPO, until } from './harness.ts'

// A CLI child process whose stdin is a pseudo-terminal, for the commands that refuse `no-tty` (scenario 41's pattern,
// kept apart so that scenario 46 can use it without touching 41). The CLI sees a real terminal on fd 0 (io.isTty is
// process.stdin.isTTY); Python's pty module (the gate already needs Python 3.13) opens it, gives its slave end to the
// child, and copies this process's lines into the master end; the child's stdout and stderr stay pipes. No CLI source
// and no environment variable is involved.

const lines = (text: string): string[] => text.split('\n').filter((l) => l !== '')

/**
 * Runs argv[1:] with its stdin on a new pseudo-terminal: this process's stdin is copied to the master end, whatever
 * the terminal echoes is drained and dropped, stdout and stderr are inherited. SIGTERM ends the child; the exit code is
 * the child's (128 + n for a signal n).
 */
const PTY = `
import os, pty, select, signal, subprocess, sys
master, slave = pty.openpty()
child = subprocess.Popen(sys.argv[1:], stdin=slave)
os.close(slave)
signal.signal(signal.SIGTERM, lambda *_: child.terminate())
fds = [0, master]
while child.poll() is None:
    for fd in select.select(fds, [], [], 0.05)[0]:
        try:
            data = os.read(fd, 4096)
        except OSError:
            data = b''
        if fd == 0 and data:
            os.write(master, data)
        elif not data:
            fds.remove(fd)
code = child.returncode
sys.exit(code if code >= 0 else 128 - code)
`

/** A CLI process whose stdin is a terminal: its stdout lines, its raw stderr, a line typed at it, its exit. */
export interface Terminal {
  out(): string[]
  err(): string
  type(line: string): void
  readonly exit: Promise<number>
}

/**
 * `node packages/cli/src/main.ts <args>` on a terminal. Its raw stdout and stderr are pushed to `seen` when it ends
 * (the secret count reads them); a child still running when the test ends is sent SIGTERM, as a hangup would end it.
 */
export function terminal(args: readonly string[], seen: string[]): Terminal {
  const env: NodeJS.ProcessEnv = { ...process.env }
  delete env.AC_HOME
  // The CLI keeps one telemetry store per machine, in HOME/.bag: off here, so no scenario counts into it or marks it.
  env.DO_NOT_TRACK = '1'
  const child = spawn('python3', ['-I', '-c', PTY, process.execPath, CLI_MAIN, ...args], { cwd: REPO, env })
  let out = ''
  let err = ''
  child.stdout.on('data', (d: Buffer) => {
    out += d.toString()
  })
  child.stderr.on('data', (d: Buffer) => {
    err += d.toString()
  })
  child.stdin.on('error', () => {})
  const exit = new Promise<number>((resolve) => {
    child.on('close', (code, signal) => {
      seen.push(out, err)
      resolve(code ?? (signal === null ? -1 : 128))
    })
  })
  onTestFinished(() => {
    if (child.exitCode === null && child.signalCode === null) child.kill('SIGTERM')
  })
  return {
    out: () => lines(out),
    err: () => err,
    type: (line) => child.stdin.write(`${line}\n`),
    exit,
  }
}

/** The first stdout line of `t` that starts with `prefix`, once it is there (30 s at most). */
export async function lineOf(t: Terminal, prefix: string): Promise<string> {
  await until(`a line "${prefix}..."`, () => t.out().some((l) => l.startsWith(prefix)), 30_000)
  return t.out().find((l) => l.startsWith(prefix)) as string
}

/** The exit code of `t`; fails after 30 s naming its stderr (the lines of this CLI hold no key). */
export async function exited(t: Terminal, what: string): Promise<number> {
  let timer: NodeJS.Timeout | undefined
  const late = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error(`${what} did not exit within 30 s; stderr ${t.err()}`)), 30_000)
  })
  try {
    return await Promise.race([t.exit, late])
  } finally {
    clearTimeout(timer)
  }
}

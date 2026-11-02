import type { Clock } from '@usebag/edge'

// The server's log: one JSON object per line on stderr, never on stdout, which carries MCP frames only. A line holds
// an event and plain values (addresses, ids, codes, counts), never key material and never a message body.

/** A value a log line may carry. */
export type LogValue = string | number | boolean | null | readonly string[]

export type LogLevel = 'info' | 'warn' | 'error'

export interface Logger {
  log(level: LogLevel, event: string, fields?: Readonly<Record<string, LogValue>>): void
}

/** A logger that writes each line, with its time from the clock, through `write` (stderr). */
export function jsonLogger(write: (line: string) => void, clock: Clock): Logger {
  return {
    log(level, event, fields = {}) {
      const ts = new Date(clock.now() * 1000).toISOString()
      write(`${JSON.stringify({ ts, level, event, ...fields })}\n`)
    },
  }
}

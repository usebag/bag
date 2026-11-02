import type { RequestHandlerExtra } from '@modelcontextprotocol/sdk/shared/protocol.js'
import type { ServerNotification, ServerRequest } from '@modelcontextprotocol/sdk/types.js'
import type { Timers } from './desk.ts'
import type { Logger } from './log.ts'

// Progress during one wait or ask call. When the host's request
// carries `_meta.progressToken`, the server sends `notifications/progress` for it every --progress-seconds (15 s by
// default) while the call blocks: `progress` the seconds elapsed in its wait (a fresh ask's wait starts once the
// question is sent), `total` the wait's window rounded up to a whole second, and a message that names the tool and
// says both. Without a token, or with --progress-seconds 0, it sends nothing. A tick due at or after the window's end
// is not sent: the call returns then. One `progress` log line per call that has a token says the host asked. Whether
// a host resets its own timeout on these is not measured (packages/mcp/README.md).

/** What a tool handler's `extra` must give: the request's _meta and a notification bound to that request. */
export type ProgressExtra = Pick<
  RequestHandlerExtra<ServerRequest, ServerNotification>,
  '_meta' | 'sendNotification'
>

export interface ProgressOptions {
  readonly tool: string
  readonly extra: ProgressExtra
  /** Seconds between two notifications; 0 sends none. */
  readonly every: number
  /** The wait's window in seconds: how long the call blocks at most. */
  readonly window: number
  readonly timers: Timers
  readonly log: Logger
}

const noop = (): void => {}

/** Starts the notifications of one call; returns the stop, which the call runs when it returns. */
export function startProgress(o: ProgressOptions): () => void {
  const token = o.extra._meta?.progressToken
  if (token === undefined || o.every === 0) return noop
  o.log.log('info', 'progress', { tool: o.tool, every_s: o.every, window_s: o.window })
  const total = Math.ceil(o.window)
  let elapsed = 0
  let cancel = noop
  const next = (): void => {
    if (elapsed + o.every < o.window) cancel = o.timers.after(o.every * 1000, tick)
  }
  const tick = (): void => {
    elapsed += o.every
    const message = `${o.tool}: nothing yet, ${elapsed} s of this call's ${total} s`
    const params = { progressToken: token, progress: elapsed, total, message }
    // Through a promise, so that a send that throws at once is logged as one that rejects, never out of the timer.
    Promise.resolve()
      .then(() => o.extra.sendNotification({ method: 'notifications/progress', params }))
      .catch((e: unknown) => o.log.log('warn', 'progress-failed', { tool: o.tool, detail: String(e) }))
    next()
  }
  next()
  return () => cancel()
}

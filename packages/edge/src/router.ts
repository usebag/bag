import type { Clock, EdgeStore, InboundMessage, SessionHandler, SpawnHook } from './ports.ts'

// Routing by thread (spec/SPEC.md §9.6): a thread's session is kept in threads(thread_id, session_id), so a reply
// reaches the session that opened the thread, across restarts; a root message on an unknown thread goes to the
// default handler, else to the spawn hook; anything else, or a session that is not live, is queued. Each bind,
// register and route on a bound thread records its last use, which the edge's prune reads.

/** Where a message went: a live session, or the inbox queue (with why, when a handler failed). */
export type RouteOutcome =
  | { readonly state: 'routed'; readonly session: string; readonly error: null }
  | { readonly state: 'queued'; readonly session: null; readonly error: string | null }

const QUEUED: RouteOutcome = { state: 'queued', session: null, error: null }

export class Router {
  readonly #store: EdgeStore
  readonly #clock: Clock
  readonly #spawn: SpawnHook | undefined
  readonly #live = new Map<string, SessionHandler>()
  #default: SessionHandler | null = null

  constructor(store: EdgeStore, clock: Clock, spawn?: SpawnHook) {
    this.#store = store
    this.#clock = clock
    this.#spawn = spawn
  }

  /** Binds a thread to the handler's session, persisted, and makes the handler live. */
  register(threadId: string, handler: SessionHandler): void {
    this.#store.threadSet(threadId, handler.session, this.#clock.now())
    this.attach(handler)
  }

  /** Makes a session's handler live for the threads bound to it, including those bound before a restart. */
  attach(handler: SessionHandler): void {
    this.#live.set(handler.session, handler)
  }

  /** Takes a session's handler down; its threads queue until it attaches again. */
  detach(session: string): void {
    this.#live.delete(session)
  }

  /** The handler for root messages on threads no session holds; null to queue them (or ask the spawn hook). */
  setDefault(handler: SessionHandler | null): void {
    this.#default = handler
    if (handler !== null) this.attach(handler)
  }

  /** Binds a thread to a session unless it is bound already: the sender's side of "replies reach the opener". */
  bind(threadId: string, session: string): void {
    const now = this.#clock.now()
    if (this.#store.threadGet(threadId) === null) this.#store.threadSet(threadId, session, now)
    else this.#store.threadTouch(threadId, now)
  }

  /** Delivers a message to its thread's live session, or a new root's default or spawned handler, else queues it. */
  async route(message: InboundMessage): Promise<RouteOutcome> {
    const bound = this.#store.threadGet(message.thread.id)
    let handler: SessionHandler | null = null
    if (bound !== null) {
      this.#store.threadTouch(message.thread.id, this.#clock.now())
      handler = this.#live.get(bound) ?? null
    } else if (message.thread.prev.length === 0) {
      handler = this.#bound(message.thread.id, this.#default ?? (await this.#spawned(message)))
    }
    if (handler === null) return QUEUED
    try {
      await handler.deliver(message)
      return { state: 'routed', session: handler.session, error: null }
    } catch {
      return { state: 'queued', session: null, error: 'the handler threw' }
    }
  }

  /**
   * Registers a new root's handler for its thread. Synchronous, apart from route's await: V8's block counts after an
   * await in an async function made this branch read as never taken (a count of -9), though tests take it.
   */
  #bound(threadId: string, handler: SessionHandler | null): SessionHandler | null {
    if (handler !== null) this.register(threadId, handler)
    return handler
  }

  async #spawned(message: InboundMessage): Promise<SessionHandler | null> {
    if (this.#spawn === undefined) return null
    try {
      return await this.#spawn.onUnroutedThread({ message })
    } catch {
      return null
    }
  }
}

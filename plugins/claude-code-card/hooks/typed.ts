// bag's typed-word mark: tells bag's UserPromptSubmit command hook (`bag-shim hook`) whether the person typed the
// prompt in this window's composer. The module's prompt.submit event names where a prompt came from (origin.kind:
// `composer` for typing; a schedule, `claude -p` or another session otherwise); the classic UserPromptSubmit event that
// follows carries the prompt_id the command hook sees. One pending entry, the latest only: each prompt.submit overwrites
// it, each classic event consumes it (read, then cleared, always). A classic event is marked only when the entry's text
// is its prompt exactly and the entry is under MARK_MS old: `bag_typed` for `composer`, `bag_not_typed` for any other
// kind; anything else passes on with no key, and the hook then treats the prompt as unproven. No `$`, nothing logged.

/** How long a prompt.submit entry stands for the classic event after it, in ms. */
export const MARK_MS = 5000

/** The latest prompt.submit: its origin's kind, its text, and when it came. */
type Pending = { readonly kind: string; readonly text: string; readonly at: number }

/** The mark for one registration of the module (card.ts): `submitted` on prompt.submit, `consume` on the classic event. */
export function typedMark(now: () => number) {
  let pending: Pending | null = null
  return {
    submitted(e: { readonly origin?: unknown; readonly text?: unknown }): void {
      const kind = (e.origin as { kind?: unknown } | null | undefined)?.kind
      pending = {
        kind: typeof kind === 'string' ? kind : '',
        text: typeof e.text === 'string' ? e.text : '',
        at: now(),
      }
    },
    consume<E extends { readonly prompt?: unknown; readonly prompt_id?: unknown }>(e: E): E {
      const p = pending
      pending = null
      const id = e.prompt_id
      if (p === null || typeof id !== 'string' || id === '' || p.text !== e.prompt) return e
      const age = now() - p.at
      if (age < 0 || age >= MARK_MS) return e
      return { ...e, [p.kind === 'composer' ? 'bag_typed' : 'bag_not_typed']: { v: 1, prompt_id: id } }
    },
  }
}

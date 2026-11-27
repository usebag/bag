import type { Register } from 'claude-code'
import { acts, HEADER, runCard, withCard } from './card-logic'
import { typedMark } from './typed'

// bag's question card: on a Claude Code surface that shows no MCP dialog (the VS Code extension, Claude Desktop's Code
// tab), this hooks module draws each of bag's questions in Claude Code's own question card ($.ui.ask) and passes the
// person's pick down the hook chain as `bag_card` (route d1), where bag's command hook (`bag card-hook`, this plugin's
// hooks.json) answers the elicitation with it. Everywhere else, and whenever it cannot draw, it passes the request on
// untouched: no marker, so the host's own answer stands and bag reads it as today. It writes no log line.

export const register: Register = (on) => {
  // The typed-word mark (typed.ts): a throw passes the event on untouched, so the command hook sees no key.
  const typed = typedMark(() => Date.now())
  on('prompt.submit', async (_$, e, next) => {
    typed.submitted(e)
    return next(e)
  }).catch((_$, e, next) => next(e))
  on('classic.UserPromptSubmit', async (_$, e, next) => next(typed.consume(e))).catch((_$, e, next) =>
    next(e),
  )
  on('classic.Elicitation', async ($, e, next) => {
    const entrypoint = await $.env.get('CLAUDE_CODE_ENTRYPOINT')
    if (!acts(e, entrypoint)) return next(e)
    const content = await runCard(
      e,
      entrypoint ?? '',
      (q, options) => $.ui.ask(q, { options, header: HEADER }),
      () => Date.now(),
    )
    return next(content === null ? e : withCard(e, content))
    // A throw before next: the request goes on untouched (no marker). After it: next(e) replays what it settled to.
  }).catch((_$, e, next) => next(e))
}

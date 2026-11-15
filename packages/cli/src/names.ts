import { isAddress } from '@usebag/core'
import { readSession, resolveLabel } from '@usebag/enterprise-client'
import { NameBook as HomeNameBook, NAME } from '@usebag/home'

// Petnames: the name book of a home moved to packages/home, which the MCP server shares. The command line's book adds
// find, which may ask a bag enterprise session's organisation for a name the book lacks.

export { type Display, instant, NAME, NAMES_FILE, type NameEntry, type Previous, short } from '@usebag/home'

/** The name book of a home, as packages/home keeps it, with the organisation's names behind it. */
export class NameBook extends HomeNameBook {
  /** As resolve, then, for a name the book lacks with an enterprise session in the home, the org's agent so labelled. */
  async find(text: string, fetch?: typeof globalThis.fetch, org?: string): Promise<string> {
    const book = isAddress(text) || this.has(text) || !NAME.test(text) || readSession(this.home, org) === null
    const o = { ...(fetch && { fetch }), ...(org && { org }) }
    return (book ? undefined : await resolveLabel(this.home, text, o)) ?? this.resolve(text)
  }
}

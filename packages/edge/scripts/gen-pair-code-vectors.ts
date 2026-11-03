/**
 * Writes the generated members of spec/vectors/pair-code.json (spec/SPEC.md §8.10, §11) from the shipped edge code:
 * `check_digits` (pairingCode), `request_mac` (macOf), `invite_string` (inviteText) and `pair_open` (the core's
 * signPreimage over the pair/open preimage, as the inviter signs it). The file's `codec` and `s_derivation` members stay
 * hand-maintained and are left as they are. Every key here comes from a fixed seed and is test data by construction.
 *
 *   node packages/edge/scripts/gen-pair-code-vectors.ts           rewrite the generated members
 *   node packages/edge/scripts/gen-pair-code-vectors.ts --check   fail unless the committed members are what the code
 *                                                                 produces now
 *
 * Run Biome's formatter on the file after a rewrite. Added 2026-11-03 (branch spec/id-gaps).
 */

import { readFileSync, writeFileSync } from 'node:fs'
import { isDeepStrictEqual } from 'node:util'
import * as core from '@usebag/core'
import { codeSecret } from '../src/pair-code.ts'
import { type Invite, inviteText, macOf, pairingCode, readInvite } from '../src/pairing.ts'

const FILE = new URL('../../../spec/vectors/pair-code.json', import.meta.url)

const seed = (b: number, first = b): Uint8Array => {
  const s = new Uint8Array(32).fill(b)
  s[0] = first
  return s
}
const signing = (b: number) => core.signingKeyFromSeed(seed(b))
const sealing = (b: number, first = b) => core.toHex(core.sealingKeyFromSeed(seed(b, first)).publicKey)

const inviter = signing(0x11).address
const invitationKey = signing(0x22)
const invitation = invitationKey.address
const requester = signing(0x33).address
const RELAY = 'https://relay.acme.example'
const EXP = 1_798_000_600
const WORD_CODE = { nameplate: '472', words: ['tulip', 'orbit', 'cedar'] }
const S_CODE = codeSecret(WORD_CODE, invitation)
const S_PASTE = '00112233445566778899aabbccddeeff'

function digitsCase(name: string, sealingKey: string, s: string) {
  const v: Invite = { inviter, i: invitation, relay: RELAY, secret: s }
  const preimage = ['ac/peer-code/1', inviter, invitation, requester, sealingKey, s]
  const canonical = core.canonical(preimage)
  const d = core.sha256(canonical)
  const first4 = Buffer.from(d).readUInt32BE(0)
  const shown = pairingCode(v, requester, sealingKey)
  const digits = shown.replace(' ', '')
  if (digits !== String(first4 % 1_000_000).padStart(6, '0')) throw new Error(`${name}: digits disagree`)
  return {
    name,
    inviter,
    invitation,
    requester,
    sealing: sealingKey,
    s_hex: s,
    canonical: Buffer.from(canonical).toString(),
    sha256: core.toHex(d),
    first4_be: first4,
    digits,
    shown,
  }
}

/** A requester sealing key whose digits begin with 0, found by moving the seed's first byte from 0x55. */
function leadingZeroSealing(): string {
  for (let first = 0x55; first < 0x55 + 256; first++) {
    const k = sealing(0x55, first & 0xff)
    const v: Invite = { inviter, i: invitation, relay: RELAY, secret: S_PASTE }
    if (pairingCode(v, requester, k).startsWith('0')) return k
  }
  throw new Error('no sealing key with a leading zero digit in 256 tries')
}

function macCase(name: string, sealingKey: string, s: string) {
  const v: Invite = { inviter, i: invitation, relay: RELAY, secret: s }
  const canonical = core.canonical(['ac/peer-request/1', inviter, invitation, requester, sealingKey, EXP])
  return {
    name,
    inviter,
    invitation,
    requester,
    sealing: sealingKey,
    exp: EXP,
    s_hex: s,
    canonical: Buffer.from(canonical).toString(),
    mac: macOf(v, requester, sealingKey, EXP),
  }
}

function inviteCase(name: string, s: string) {
  const v: Invite = { inviter, i: invitation, relay: RELAY, secret: s }
  const invite = inviteText(v)
  const back = readInvite(invite)
  if (!isDeepStrictEqual({ ...back }, { ...v }))
    throw new Error(`${name}: the invite string does not read back`)
  const canonical = core.canonical(['ac/peer-invite/1', inviter, invitation, RELAY, s])
  return {
    name,
    inviter,
    invitation,
    relay: RELAY,
    s_hex: s,
    canonical: Buffer.from(canonical).toString(),
    invite,
  }
}

function openCase(name: string, relays: string[], ttl: number) {
  const preimage = ['ac/pair-open/1', inviter, invitation, relays, ttl]
  const canonical = core.canonical(preimage)
  const sig = core.signPreimage(invitationKey, preimage)
  if (!core.verifyPreimage(invitation, preimage, sig))
    throw new Error(`${name}: the signature does not verify`)
  return {
    name,
    invitation_seed: core.toHex(seed(0x22)),
    inviter,
    invitation,
    relays,
    ttl,
    canonical: Buffer.from(canonical).toString(),
    sha256: core.toHex(core.sha256(canonical)),
    sig,
    body: JSON.stringify({ inviter, invitation, relays, ttl, sig }),
  }
}

function generated() {
  return {
    check_digits: {
      alg: "digits = decimal( uint32_be( sha256( utf8( canonical(['ac/peer-code/1', inviter, invitation, requester, sealing, S]) ) )[0..4] ) mod 10^6 ), left-padded with 0 to six digits; shown as three digits, one space, three digits",
      fields:
        'inviter, invitation and requester are addresses; sealing is the requester X25519 public key in lowercase hex (its key record sealing_key, else its address record sealing_key); S is the 16-byte invitation MAC key as 32 lowercase hex characters',
      cases: [
        digitsCase('word code: S from the words of 472-tulip-orbit-cedar', sealing(0x44), S_CODE),
        digitsCase('invite string: S drawn at random', sealing(0x44), S_PASTE),
        digitsCase('digits with a leading zero, kept as six digits', leadingZeroSealing(), S_PASTE),
      ],
    },
    request_mac: {
      alg: "mac = lowercase_hex( HMAC-SHA256( key = the 16 bytes of S, utf8( canonical(['ac/peer-request/1', inviter, invitation, requester, sealing, exp]) ) ) )",
      fields:
        "exp is the invitation's end, its address record's iat + ttl, a canonical integer; the other fields as in check_digits",
      cases: [macCase('word code', sealing(0x44), S_CODE), macCase('invite string', sealing(0x44), S_PASTE)],
    },
    invite_string: {
      alg: "invite = 'ac-peer1:' + base64url_no_padding( utf8( canonical(['ac/peer-invite/1', inviter, invitation, relay, S]) ) )",
      cases: [inviteCase('an invite string', S_PASTE)],
    },
    pair_open: {
      alg: "sig = Ed25519( the invitation key, sha256( utf8( canonical(['ac/pair-open/1', inviter, invitation, relays, ttl]) ) ) ); relays is a list of 1 to 64 distinct relay URLs, ttl 1 to 600",
      cases: [
        openCase('one relay, the rendezvous itself, as the edge opens it', [RELAY], 600),
        openCase('two relays in their listed order, ttl 120', [RELAY, 'https://relay2.acme.example'], 120),
      ],
    },
  }
}

const file = JSON.parse(readFileSync(FILE, 'utf8')) as Record<string, unknown>
const fresh = generated()
if (process.argv.includes('--check')) {
  const stale = Object.keys(fresh).filter((k) => !isDeepStrictEqual(file[k], fresh[k as keyof typeof fresh]))
  if (stale.length > 0) {
    console.error(`pair-code.json: ${stale.join(', ')} differ from what the code produces`)
    process.exit(1)
  }
  console.log(`pair-code.json: ${Object.keys(fresh).join(', ')} match the code`)
} else {
  // The hand-maintained members keep their own layout: the generated ones are written after them, last in the file.
  const text = readFileSync(FILE, 'utf8')
  const cut = text.indexOf(',\n  "check_digits":')
  const kept = cut >= 0 ? text.slice(0, cut) : text.slice(0, text.lastIndexOf('\n}'))
  const member = ([k, v]: [string, unknown]) =>
    `  ${JSON.stringify(k)}: ${JSON.stringify(v, null, 2).replaceAll('\n', '\n  ')}`
  writeFileSync(FILE, `${kept},\n${Object.entries(fresh).map(member).join(',\n')}\n}\n`)
  console.log(`pair-code.json: wrote ${Object.keys(fresh).join(', ')}`)
}

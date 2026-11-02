//! `ac-relay probe <url> --key <file>`: a relay checked from outside, by a healthcheck with no shell:
//! health; the accept-from record of the key's own mailbox (roots itself, 4,096 bytes, `ttl` 60) when the relay holds
//! none; an envelope from the key to itself (its sealed part 16 random bytes, sealed to no one, no type), published
//! and fetched back byte for byte, swept once its 60 s are past; each call within 5 s. The key file is made 0600, and
//! its seed is never printed. The fetch proof's audience is the URL health answers, the relay's own first base, so
//! that a probe of the same relay by another name passes too: its port inside a container, or the app's fly.dev name
//! (spec/SPEC.md §8.3); the probed base when health names none.
//!
//! Each call runs on a thread of its own, given 5 s, and the client has no timeout of its own: with one,
//! ureq sets the socket's timeout before nearly every read and write, and on macOS that `setsockopt` fails with EINVAL
//! on a socket its peer has reset, so an answer that had arrived was lost as `io: Invalid argument (os error 22)`.

use ac_core::envelope::{Envelope, Sealed, Wrap};
use ac_core::keys::SigningKey;
use ac_core::records::{AcceptFromRecord, Record, Roots};
use ac_core::{hex, requests};
use serde_json::Value;
use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

type Reply = (u16, Vec<u8>);
type Response = Result<ureq::http::Response<ureq::Body>, ureq::Error>;

/// The time each call has (spec/SPEC.md §8.9 item 5).
const CALL: Duration = Duration::from_secs(5);

/// A call's status and body, or the step and what failed.
fn answer(step: &str, call: Response) -> Result<Reply, String> {
    let mut response = call.map_err(|e| format!("{step}: {e}"))?;
    let body = response.body_mut().read_to_vec().map_err(|e| format!("{step}: {e}"))?;
    Ok((response.status().as_u16(), body))
}

/// The call `send` makes on `agent`, its answer read whole, within [`CALL`] on a thread of its own: a call past it is
/// left to the process's exit.
fn call(
    step: &'static str,
    agent: &ureq::Agent,
    send: impl FnOnce(&ureq::Agent) -> Response + Send + 'static,
) -> Result<Reply, String> {
    let (done, answered) = std::sync::mpsc::channel();
    let agent = agent.clone();
    std::thread::spawn(move || done.send(answer(step, send(&agent))));
    answered.recv_timeout(CALL).unwrap_or_else(|_| Err(format!("{step}: no answer within 5 s")))
}

/// `step` failed unless `ok`, naming the answer's status and body.
fn require(step: &str, ok: bool, (status, body): &Reply) -> Result<(), String> {
    if ok { Ok(()) } else { Err(format!("{step}: {status} {}", String::from_utf8_lossy(body))) }
}

/// Probes the relay at `url`: the id of the envelope it published and read back.
///
/// # Errors
///
/// The step that failed, `health`, `key`, `record`, `publish` or `fetch`, and what went wrong, as one sentence.
pub fn run(url: &str, key_file: &Path) -> Result<String, String> {
    let base = url.trim_end_matches('/');
    let config = ureq::Agent::config_builder().http_status_as_error(false).max_redirects(0).proxy(None);
    let agent = ureq::Agent::new_with_config(config.build());
    let at = format!("{base}/v0/health");
    let health = call("health", &agent, move |a| a.get(at).call())?;
    let said = serde_json::from_slice::<Value>(&health.1).unwrap_or_default();
    require("health", health.0 == 200 && said["ok"] == true, &health)?;
    let audience = said["url"].as_str().unwrap_or(base).to_owned();
    let key = load_key(key_file).map_err(|e| format!("key: {}: {e}", key_file.display()))?;
    let since = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    let (me, now) = (key.address(), since.as_secs());
    let at = format!("{base}/v0/fetch/record/{me}/accept-from");
    let held = call("record", &agent, move |a| a.get(at).call())?;
    if held.0 == 404 {
        let roots = Roots::Listed(vec![me.clone()]);
        let rec =
            AcceptFromRecord { owner: me.clone(), roots, max_bytes: 4_096, ttl: 60, iat: now, sig: [0; 64] };
        let mut record = Record::AcceptFrom(rec);
        let signed = record.sign(&key).is_ok();
        let (at, body) = (format!("{base}/v0/publish"), record.to_bytes());
        let stored = call("record", &agent, move |a| a.post(at).send(body))?;
        require("record", signed && stored.0 == 200, &stored)?;
    } else {
        require("record", held.0 == 200, &held)?;
    }
    // The sealed part's 16 bytes are the second's nanoseconds, so each run's envelope has an id of its own.
    let wraps = vec![Wrap { to: me.clone(), enc: "00".repeat(32), ct: "00".repeat(48) }];
    let sealed = Sealed { wraps, nonce: "00".repeat(12), ct: hex::encode(&since.as_nanos().to_be_bytes()) };
    let Ok(env) = Envelope::sign(&key, vec![me.clone()], Vec::new(), now, sealed) else {
        return Err("publish: the probe's envelope does not sign".to_owned());
    };
    let (bytes, id) = (env.to_bytes(), env.id_hex());
    let (at, body) = (format!("{base}/v0/publish"), bytes.clone());
    let published = call("publish", &agent, move |a| a.post(at).send(body))?;
    let v: Value = serde_json::from_slice(&published.1).unwrap_or_default();
    let stored = v["id"] == id.as_str() && v["duplicate"] == false && v["delivered"] == 1;
    require("publish", published.0 == 200 && stored, &published)?;
    let proof = requests::fetch_preimage(&me, &id, now, &audience);
    let sig = hex::encode(&key.sign_preimage(&proof).unwrap_or([0; 64]));
    let (at, signer) = (format!("{base}/v0/fetch/{id}"), me.to_string());
    let fetched = call("fetch", &agent, move |a| {
        a.get(at).header("ac-signer", signer).header("ac-ts", now.to_string()).header("ac-sig", sig).call()
    })?;
    require("fetch", fetched.0 == 200 && fetched.1 == bytes, &fetched)?;
    Ok(id)
}

/// The probe's key from `path`, 64 hex characters; a missing file is made with 32 random bytes, mode 0600.
fn load_key(path: &Path) -> std::io::Result<SigningKey> {
    let bad = std::io::Error::other("it does not hold 64 hex characters");
    let seed = match std::fs::read_to_string(path) {
        Ok(text) => hex::decode_array::<32>(text.trim()).ok().ok_or(bad)?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let mut seed = [0u8; 32];
            getrandom::fill(&mut seed)?;
            let mut file = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)?;
            file.write_all(format!("{}\n", hex::encode(&seed)).as_bytes())?;
            seed
        }
        Err(e) => return Err(e),
    };
    Ok(SigningKey::from_seed(&seed))
}

#[cfg(test)]
mod tests;

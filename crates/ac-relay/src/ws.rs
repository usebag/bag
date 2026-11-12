//! The subscribe call: a WebSocket on `/v0/subscribe` (spec/SPEC.md §8.5).
//!
//! 1. The relay sends `{"t":"challenge","nonce":<64 hex>,"ts":<now>}`.
//! 2. The subscriber answers `{"t":"auth","mailbox","signer","auth":[hops],"cursor":int|null,"sig"}`
//!    ([`crate::auth`]). A refusal is `{"t":"error","error":<code>}` (`bad-auth`, `not-authorized`, a chain code, or
//!    since 2026-10-26 `revoked`) and close code 4001; a store that fails to read the mailbox's kept revoked list closes
//!    it 1011.
//! 3. The relay sends `{"t":"ok","cursor"}`: the cursor it resumes after, the one asked for, or for `null` the
//!    signer's stored ack (0 when none), never beyond the mailbox's last cursor.
//! 4. It pushes `{"t":"env","cursor","received_at","envelope"}` in cursor order, with at most 32 unacknowledged:
//!    `received_at` is the second the relay stored the envelope, and `envelope` is a JSON string whose UTF-8 bytes
//!    are the exact stored bytes (the envelope was once embedded as raw JSON text).
//! 5. The subscriber sends `{"t":"ack","cursor"}`: everything up to that cursor arrived. The relay stores it per
//!    mailbox and signer, the latest at most once a second and when the subscriber goes. An ack means delivered; it
//!    never deletes anything. Delivery is at least once: a frame not acked, or whose ack was lost with its
//!    connection, is sent again to the next subscription that resumes before it, and the edge drops what it has seen
//!    by id.
//! 6. A subscription under a chain ends once the relay's clock is past the chain's earliest `exp`: no `env` frame
//!    after it, then `{"t":"error","error":"hop-expired"}` and close 4001, within half a second (the clock is read
//!    before each batch of `env` frames and every 500 ms). The subscriber renews its chain and
//!    subscribes again.
//! 7. A subscription under a chain ends once a newer address record of the mailbox revokes a key of its chain (since
//!    2026-10-26): no `env` frame after that record is stored, then `{"t":"error","error":
//!    "revoked"}` and close 4001, the class of step 6's end. The relay counts the address records it stores and
//!    notifies the key's mailbox; a subscription reads the mailbox's kept list again when that count has moved since it
//!    last read it, before any frame and when notified for its mailbox, so with no address record stored it reads none.
//!
//! The relay pings every `ping_interval` (30 s by default) and closes with 4003 a subscriber it has heard nothing
//! from, a pong included, for `idle_timeout` (60 s, at least two ping intervals), or one that sends no auth frame
//! within it. Every frame and every pong restarts the silence: the wait ends on each, so the deadline is computed
//! again from the last one heard (once a pong moved `heard` without ending the wait, and an idle subscriber
//! that answered every ping could be closed at exactly the idle timeout). A subscriber that stops reading is closed the
//! same way: a frame or a ping that cannot reach its socket within `idle_timeout` ends the session. The arms are polled
//! in a fixed order
//! (`biased`): shutdown, then the subscriber's frames, notifications, the ping, and the idle deadline last. A frame
//! that breaks the protocol after the handshake (anything but an ack, an ack for a cursor never sent) gets
//! `{"t":"error","error":"bad-shape"}` and closes with 4002 (implementation default). A store failure closes with
//! 1011; a relay shutting down closes with 1001.

use crate::auth::Subscriber;
use crate::metrics::{METRICS, SUBSCRIPTIONS_OPEN};
use crate::relay::Relay;
use crate::store::MailboxEntry;
use ac_core::{Code, json};
use axum::extract::ws::{CloseFrame, Message, WebSocket};
use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, mpsc, watch};
use tokio::time::{Instant, sleep, sleep_until, timeout};

/// The counter of subscriptions by `result` (`ok` or the code); the gauge of those open is the metrics module's.
const SUBSCRIBES: &str = "ac_relay_subscribes_total";

/// Close code: the auth frame was refused.
pub const CLOSE_AUTH: u16 = 4001;
/// Close code: a frame broke the protocol.
pub const CLOSE_PROTOCOL: u16 = 4002;
/// Close code: the subscriber was silent too long, or never sent its auth frame.
pub const CLOSE_IDLE: u16 = 4003;
/// Close code: the relay is shutting down.
pub const CLOSE_GOING_AWAY: u16 = 1001;
/// Close code: the relay failed internally.
pub const CLOSE_INTERNAL: u16 = 1011;
/// Close code of a subscription refused at its address's limit: try again later.
pub const CLOSE_TRY_LATER: u16 = 1013;

/// A subscription's read buffer, allocated whole and filled with zeros at its first read. A subscriber sends acks,
/// under 64 bytes, and one auth frame, about 330 bytes with no chain and 320 more for each hop with no caveats, so the
/// 8 hops a chain holds fit. It bounds no frame: a longer one grows the buffer to its length, over more reads.
/// tungstenite's default of 128 KiB made a held subscription cost 138 to 140 KiB, and at that a Machine of 256 MB runs
/// out of memory at about 1,470 subscriptions, before any cap of the relay.
pub(crate) const READ_BUFFER: usize = 4_096;

/// How often a subscription under a chain looks at the relay's clock for the chain's end, besides before each frame.
pub const EXPIRY_CHECK: Duration = Duration::from_millis(500);

/// How long a close, and the error frame before it, may take. The subscriber may have stopped reading, and it is going
/// either way.
const CLOSE_WAIT: Duration = Duration::from_secs(1);

/// The least time between two writes of one subscription's ack. Losing the last second's ack to a crash costs a
/// redelivery, which a receiver drops by id.
const ACK_WRITE_EVERY: Duration = Duration::from_secs(1);

/// The cursor of an ack frame, `{"t":"ack","cursor":<integer>}` and nothing else, read as the auth frame is
/// ([`ac_core::json`]); `None` for anything else.
fn ack_cursor(text: &str) -> Option<u64> {
    let value = json::parse(text.as_bytes()).ok()?;
    let object = value.as_object().filter(|o| json::has_exact_keys(o, &["t", "cursor"]))?;
    let ack = object.get("t").and_then(serde_json::Value::as_str) == Some("ack");
    object.get("cursor").filter(|_| ack).and_then(json::canonical_integer)
}

enum Next {
    Text(String),
    /// A ping or a pong: the subscriber is alive, and `heard` moved. It ends the wait, so that the caller computes
    /// its idle deadline again from the new `heard`.
    Heard,
    Closed,
    Binary,
}

/// The next frame from the subscriber; `heard` moves on every frame, a ping or a pong included.
async fn next_frame(socket: &mut WebSocket, heard: &mut Instant) -> Next {
    match socket.recv().await {
        Some(Ok(Message::Text(t))) => {
            *heard = Instant::now();
            Next::Text(t.as_str().to_owned())
        }
        Some(Ok(Message::Ping(_) | Message::Pong(_))) => {
            *heard = Instant::now();
            Next::Heard
        }
        Some(Ok(Message::Binary(_))) => Next::Binary,
        Some(Ok(Message::Close(_)) | Err(_)) | None => Next::Closed,
    }
}

async fn send(socket: &mut WebSocket, text: String) -> bool {
    socket.send(Message::Text(text.into())).await.is_ok()
}

async fn close(socket: &mut WebSocket, code: u16, reason: &'static str) {
    let frame = Message::Close(Some(CloseFrame { code, reason: reason.into() }));
    let _ = timeout(CLOSE_WAIT, socket.send(frame)).await;
}

async fn refuse(socket: &mut WebSocket, code: Code, close_code: u16) {
    let frame = serde_json::json!({"t": "error", "error": code.as_str()}).to_string();
    let _ = timeout(CLOSE_WAIT, send(socket, frame)).await;
    close(socket, close_code, code.as_str()).await;
}

/// Refuses a subscription at its address's limit before any challenge: `rate-limited`, which a client retries, and
/// nothing about any identity (ruling 8).
pub(crate) async fn at_limit(socket: &mut WebSocket) {
    refuse(socket, Code::RateLimited, CLOSE_TRY_LATER).await;
}

/// A store failure under a subscriber: logged; the subscriber is closed with 1011.
#[allow(clippy::needless_pass_by_value, reason = "taken by value to serve as a map_err function")]
fn store_error(e: crate::store::StoreError) -> Failure {
    tracing::error!(event = "store-error", error = %e);
    METRICS.tick(crate::metrics::STORE_ERRORS);
    Failure::Store
}

/// Why a session ends early.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Failure {
    /// The store failed: close 1011.
    Store,
    /// The subscriber broke the protocol: an error frame with `bad-shape`, close 4002.
    Protocol,
    /// The subscriber's chain expired: an error frame with `hop-expired`, close 4001.
    Expired,
    /// A newer address record of the mailbox revokes a key of the subscriber's chain: an error frame with `revoked`,
    /// close 4001.
    Revoked,
    /// The socket is gone.
    Gone,
    /// A frame did not reach the socket within the idle timeout: the subscriber stopped reading. Close 4003.
    Stuck,
}

fn nonce() -> Option<String> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).ok()?;
    Some(ac_core::hex::encode(&bytes))
}

/// Serves one subscriber until it leaves, breaks the protocol, goes silent, or the relay stops. `_tracker` is held
/// for the connection's life so that shutdown can wait for every subscriber to be closed; `ip` is the client's
/// address, for the log, which names it as `--log-ip` says.
pub async fn serve(
    mut socket: WebSocket,
    relay: Arc<Relay>,
    mut stop: watch::Receiver<bool>,
    _tracker: mpsc::Sender<()>,
    ip: IpAddr,
) {
    let Some(nonce) = nonce() else {
        close(&mut socket, CLOSE_INTERNAL, "internal").await;
        return;
    };
    let challenge_ts = relay.now();
    let challenge = serde_json::json!({"t": "challenge", "nonce": nonce, "ts": challenge_ts}).to_string();
    if !send(&mut socket, challenge).await {
        return;
    }
    let idle = relay.config.idle_timeout;
    let mut heard = Instant::now();
    // The auth frame must come within one idle timeout of the challenge; a ping or a pong does not extend it.
    let deadline = heard + idle;
    let text = loop {
        // Checked here as well as in the select: frames come first there, so a flood of pings would never let the
        // deadline's arm be polled.
        if Instant::now() >= deadline {
            close(&mut socket, CLOSE_IDLE, "no auth").await;
            return;
        }
        let frame = tokio::select! {
            biased;
            _ = stop.changed() => {
                close(&mut socket, CLOSE_GOING_AWAY, "relay shutting down").await;
                return;
            }
            f = next_frame(&mut socket, &mut heard) => f,
            () = sleep_until(deadline) => {
                close(&mut socket, CLOSE_IDLE, "no auth").await;
                return;
            }
        };
        match frame {
            Next::Text(t) => break t,
            Next::Heard => {}
            Next::Binary => return refuse(&mut socket, Code::BadAuth, CLOSE_AUTH).await,
            Next::Closed => return,
        }
    };
    // Subscribe to notifications, and read the count of stored address records, before the mailbox's kept revoked list
    // and its rows are read, so that no row and no record stored in between is missed.
    let events = relay.events();
    let seen = relay.address_records();
    let sub = match relay.authorize_subscriber(&text, &nonce, challenge_ts) {
        Ok(sub) => sub,
        Err(Code::Internal) => return close(&mut socket, CLOSE_INTERNAL, "internal").await,
        Err(code) => {
            tracing::info!(event = "subscribe-refused", code = %code, ip = %relay.config.front.log_ip.show(ip));
            METRICS.count(SUBSCRIBES, "result", code.as_str());
            METRICS.refused("subscribe", Some(code));
            return refuse(&mut socket, code, CLOSE_AUTH).await;
        }
    };
    let Ok((start, fresh)) = start_cursor(&relay, &sub) else {
        return close(&mut socket, CLOSE_INTERNAL, "internal").await;
    };
    let ip = relay.config.front.log_ip.show(ip);
    tracing::info!(event = "subscribe", mailbox = %sub.mailbox, signer = %sub.signer, cursor = start, ip = %ip);
    if !send(&mut socket, serde_json::json!({"t": "ok", "cursor": start}).to_string()).await {
        return;
    }
    let now = relay.now();
    // Before the `ok` count, so that a reader who sees that count sees this one.
    if fresh {
        METRICS.first_subscribed(now, sub.mailbox.as_str());
    }
    METRICS.count(SUBSCRIBES, "result", "ok");
    METRICS.shift(SUBSCRIPTIONS_OPEN, 1);
    METRICS.subscribed(now, sub.mailbox.as_str());
    let mut session = Session {
        relay: &relay,
        sub,
        sent: VecDeque::new(),
        last_sent: start,
        seen,
        notified: false,
        acked: 0,
        written: 0,
        next_write: Instant::now(),
    };
    let reason = session.run(&mut socket, events, &mut stop, heard).await;
    // The ack of the last second: a failure is logged by the call, and the subscriber has gone either way.
    let _ = session.write_ack();
    tracing::info!(event = "subscribe-closed", mailbox = %session.sub.mailbox, signer = %session.sub.signer,
        last_sent = session.last_sent, reason);
    METRICS.count("ac_relay_subscriptions_closed_total", "reason", reason);
    METRICS.shift(SUBSCRIPTIONS_OPEN, -1);
}

/// The cursor `sub` resumes after, and whether its mailbox is fresh: no envelope has reached it at this relay, its last
/// cursor 0 (cursors are never deleted).
fn start_cursor(relay: &Relay, sub: &Subscriber) -> Result<(u64, bool), Failure> {
    let mailbox = sub.mailbox.as_str();
    let last = relay.store.last_cursor(mailbox).map_err(store_error)?;
    let wanted = match sub.cursor {
        Some(c) => c,
        None => relay.store.acked(mailbox, sub.signer.as_str()).map_err(store_error)?.unwrap_or(0),
    };
    Ok((wanted.min(last), last == 0))
}

struct Session<'a> {
    relay: &'a Relay,
    sub: Subscriber,
    /// Cursors sent and not yet acknowledged, oldest first.
    sent: VecDeque<u64>,
    last_sent: u64,
    /// The relay's count of stored address records when the mailbox's kept revoked list was last read.
    seen: u64,
    /// A notification for the mailbox came since the last fill: its address record may have been replaced.
    notified: bool,
    /// The highest cursor this subscriber has acknowledged, and the highest stored.
    acked: u64,
    written: u64,
    /// When the next ack may be stored.
    next_write: Instant,
}

impl Session<'_> {
    async fn run(
        &mut self,
        socket: &mut WebSocket,
        mut events: broadcast::Receiver<String>,
        stop: &mut watch::Receiver<bool>,
        mut heard: Instant,
    ) -> &'static str {
        let period = self.relay.config.ping_interval;
        let idle = self.relay.config.idle_timeout;
        let mut next_ping = Instant::now() + period;
        let mut next_expiry_check = Instant::now() + EXPIRY_CHECK;
        let mut dirty = true;
        loop {
            if dirty {
                match self.fill(socket).await {
                    Ok(()) => dirty = false,
                    Err(failure) => return end(socket, failure).await,
                }
            }
            // `heard` moves only when a frame or a pong arrives, and each ends this select, so the deadline computed
            // here is always the one of the last thing heard.
            let silent_until = heard + idle;
            tokio::select! {
                biased;
                _ = stop.changed() => {
                    close(socket, CLOSE_GOING_AWAY, "relay shutting down").await;
                    return "relay shutting down";
                }
                frame = next_frame(socket, &mut heard) => match frame {
                    Next::Text(text) => match self.on_ack(&text) {
                        Ok(freed) => dirty |= freed,
                        Err(failure) => return end(socket, failure).await,
                    },
                    Next::Heard => {}
                    Next::Binary => return end(socket, Failure::Protocol).await,
                    Next::Closed => return "closed by the subscriber",
                },
                event = events.recv() => match event {
                    Ok(mailbox) if mailbox != self.sub.mailbox.as_str() => {}
                    Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => (dirty, self.notified) = (true, true),
                    Err(broadcast::error::RecvError::Closed) => return "relay stopped",
                },
                // The chain's end is read on the relay's clock by `fill`; this only makes it look.
                () = sleep_until(next_expiry_check), if self.sub.expires.is_some() => {
                    next_expiry_check = Instant::now() + EXPIRY_CHECK;
                    dirty = true;
                }
                () = sleep_until(self.next_write), if self.acked > self.written => {
                    if let Err(failure) = self.write_ack() {
                        return end(socket, failure).await;
                    }
                }
                () = sleep_until(next_ping) => {
                    next_ping = Instant::now() + period;
                    let ping = Message::Ping(Vec::new().into());
                    match timeout(idle, socket.send(ping)).await {
                        Ok(Ok(())) => {}
                        Ok(Err(_)) => return "ping failed",
                        Err(_) => return end(socket, Failure::Stuck).await,
                    }
                }
                () = sleep_until(silent_until) => {
                    close(socket, CLOSE_IDLE, "idle").await;
                    return "idle";
                }
            }
        }
    }

    /// Sends unexpired rows after the last one sent, until the unacknowledged window is full; or, once the relay's
    /// clock is past the chain's earliest `exp`, or a newer address record of the mailbox revokes a key of the chain,
    /// nothing, and the session ends.
    async fn fill(&mut self, socket: &mut WebSocket) -> Result<(), Failure> {
        if self.expired() {
            return Err(Failure::Expired);
        }
        if std::mem::take(&mut self.notified) {
            self.check_revoked()?;
        }
        let mut room = self.relay.config.max_unacked.saturating_sub(self.sent.len());
        // A byte budget on top of the window: rows are read a budget's worth of full-size envelopes at a time, and the
        // batch stops before the row that would pass the budget, except its first row, so that a large row still goes.
        let budget = self.relay.config.batch_bytes;
        let chunk = (budget / self.relay.config.max_envelope_bytes.max(1)).max(1);
        let mut batch = 0usize;
        while room > 0 {
            let asked = room.min(chunk);
            let rows = self
                .relay
                .store
                .mailbox_after(self.sub.mailbox.as_str(), self.last_sent, asked, self.relay.now())
                .map_err(store_error)?;
            let got = rows.len();
            for row in rows {
                if batch > 0 && batch.saturating_add(row.bytes.len()) > budget {
                    return Ok(());
                }
                batch = batch.saturating_add(row.bytes.len());
                self.push(socket, row).await?;
                room -= 1;
            }
            if got < asked {
                break;
            }
        }
        Ok(())
    }

    /// Sends one row as an `env` frame, after the chain's end and the revoked list are looked at again.
    async fn push(&mut self, socket: &mut WebSocket, row: MailboxEntry) -> Result<(), Failure> {
        // Before each frame, not each batch: the next frame may leave long after this batch was read.
        if self.expired() {
            return Err(Failure::Expired);
        }
        self.check_revoked()?;
        // The stored bytes were read as UTF-8 JSON at publish, so the string holds them exactly.
        let envelope = serde_json::Value::String(String::from_utf8_lossy(&row.bytes).into_owned());
        let frame = format!(
            r#"{{"t":"env","cursor":{},"received_at":{},"envelope":{envelope}}}"#,
            row.cursor, row.received_at
        );
        self.send_frame(socket, frame).await?;
        self.sent.push_back(row.cursor);
        self.last_sent = row.cursor;
        Ok(())
    }

    /// Sends one frame within the idle timeout (LD-2). A subscriber that stops reading fills the socket's buffers, and
    /// an unbounded send would hold this task past any close. The chain's end and a revocation are looked at while it
    /// waits, as [`EXPIRY_CHECK`] says, so that a frame stuck at the socket does not go out after them.
    async fn send_frame(&mut self, socket: &mut WebSocket, frame: String) -> Result<(), Failure> {
        let give_up = Instant::now() + self.relay.config.idle_timeout;
        let sending = send(socket, frame);
        tokio::pin!(sending);
        loop {
            tokio::select! {
                sent = &mut sending => return if sent { Ok(()) } else { Err(Failure::Gone) },
                () = sleep_until(give_up) => return Err(Failure::Stuck),
                () = sleep(EXPIRY_CHECK), if self.sub.expires.is_some() => {
                    if self.expired() {
                        return Err(Failure::Expired);
                    }
                    self.check_revoked()?;
                }
            }
        }
    }

    /// Reads the mailbox's kept revoked list again when the relay has stored an address record since the last read,
    /// so that no frame goes out under a hop a newer record revokes; the mailbox key itself has no chain.
    fn check_revoked(&mut self) -> Result<(), Failure> {
        let seen = self.relay.address_records();
        if self.sub.hops.is_empty() || seen == self.seen {
            return Ok(());
        }
        self.seen = seen;
        if self.relay.revokes(&self.sub.mailbox, &self.sub.hops).map_err(store_error)? {
            return Err(Failure::Revoked);
        }
        Ok(())
    }

    /// Whether the relay's clock is past the chain's earliest `exp` (a chain is valid through its `exp`).
    fn expired(&self) -> bool {
        self.sub.expires.is_some_and(|exp| self.relay.now() > exp)
    }

    /// Takes one ack; whether it freed room in the window, the one case that gives `fill` anything to do. An ack at or
    /// below the last one reaches no store call, so a repeated ack costs the relay nothing (LN2-L2).
    fn on_ack(&mut self, text: &str) -> Result<bool, Failure> {
        let cursor = ack_cursor(text).ok_or(Failure::Protocol)?;
        if cursor > self.last_sent {
            return Err(Failure::Protocol);
        }
        let waiting = self.sent.len();
        while self.sent.front().is_some_and(|c| *c <= cursor) {
            self.sent.pop_front();
        }
        self.acked = self.acked.max(cursor);
        if Instant::now() >= self.next_write {
            self.write_ack()?;
        }
        Ok(self.sent.len() < waiting)
    }

    /// Stores the latest ack, if a newer one came since the last write. A subscriber streaming its backlog would
    /// otherwise write once an envelope; at most one write every [`ACK_WRITE_EVERY`] keeps the writer for everyone.
    fn write_ack(&mut self) -> Result<(), Failure> {
        if self.acked > self.written {
            let (mailbox, signer) = (self.sub.mailbox.as_str(), self.sub.signer.as_str());
            self.relay.store.ack(mailbox, signer, self.acked).map_err(store_error)?;
            self.written = self.acked;
            self.next_write = Instant::now() + ACK_WRITE_EVERY;
        }
        Ok(())
    }
}

/// Ends a session that failed: the close that goes with the failure, and the reason for the log.
async fn end(socket: &mut WebSocket, failure: Failure) -> &'static str {
    match failure {
        Failure::Store => {
            close(socket, CLOSE_INTERNAL, "internal").await;
            "store error"
        }
        Failure::Protocol => {
            refuse(socket, Code::BadShape, CLOSE_PROTOCOL).await;
            "protocol error"
        }
        Failure::Expired => {
            refuse(socket, Code::HopExpired, CLOSE_AUTH).await;
            "hop-expired"
        }
        Failure::Revoked => {
            refuse(socket, Code::Revoked, CLOSE_AUTH).await;
            "revoked"
        }
        Failure::Gone => "send failed",
        Failure::Stuck => {
            close(socket, CLOSE_IDLE, "idle").await;
            "stopped reading"
        }
    }
}

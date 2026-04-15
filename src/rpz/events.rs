//! Block-event sink shared by the RPZ engine and the control socket.
//!
//! Records every RPZ match in three places:
//!   1. A bounded ring of recent events (for `tail-blocks` replay).
//!   2. A `tokio::sync::broadcast` channel (for live tailing).
//!   3. A bounded "top-N" counter map keyed by qname (for `top-blocked`).
//!
//! All operations are non-blocking from the query hot path: enqueueing into a
//! `Mutex<VecDeque>` of capped size and a `try_send` on the broadcast channel.

use parking_lot::Mutex;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tokio::sync::broadcast;

const RECENT_CAP: usize = 4096;
const TOP_CAP: usize = 1024;

/// A single RPZ match event. Kept small + Clone so it can fan out to many
/// broadcast subscribers cheaply.
#[derive(Debug, Clone, serde::Serialize)]
pub struct BlockEvent {
    /// Unix milliseconds.
    pub ts: u64,
    /// Dotted query name (lowercased).
    pub qname: String,
    /// Action taken: "nxdomain" | "nodata" | "redirect" | "drop" | "passthru".
    pub action: &'static str,
    /// Owning RPZ zone.
    pub zone: String,
}

/// Shared sink. Cheap to clone — internally `Arc`s.
#[derive(Clone)]
pub struct BlockEvents {
    inner: Arc<Inner>,
}

struct Inner {
    recent: Mutex<VecDeque<BlockEvent>>,
    top: Mutex<HashMap<String, u64>>,
    tx: broadcast::Sender<BlockEvent>,
}

impl Default for BlockEvents {
    fn default() -> Self {
        Self::new()
    }
}

impl BlockEvents {
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(1024);
        Self {
            inner: Arc::new(Inner {
                recent: Mutex::new(VecDeque::with_capacity(RECENT_CAP)),
                top: Mutex::new(HashMap::with_capacity(TOP_CAP)),
                tx,
            }),
        }
    }

    /// Record a match. Called from the RPZ engine on every hit.
    pub fn record(&self, event: BlockEvent) {
        // 1. Push onto recent ring (drop oldest if full).
        {
            let mut ring = self.inner.recent.lock();
            if ring.len() == RECENT_CAP {
                ring.pop_front();
            }
            ring.push_back(event.clone());
        }

        // 2. Bump top-N counter; evict the least-hit entry if we exceed cap.
        {
            let mut top = self.inner.top.lock();
            *top.entry(event.qname.clone()).or_insert(0) += 1;
            if top.len() > TOP_CAP {
                if let Some(victim) = top
                    .iter()
                    .min_by_key(|(_, c)| **c)
                    .map(|(k, _)| k.clone())
                {
                    top.remove(&victim);
                }
            }
        }

        // 3. Broadcast (best-effort — slow subscribers lose events).
        let _ = self.inner.tx.send(event);
    }

    /// Snapshot the most recent N events, oldest first.
    pub fn recent(&self, n: usize) -> Vec<BlockEvent> {
        let ring = self.inner.recent.lock();
        let len = ring.len();
        let skip = len.saturating_sub(n);
        ring.iter().skip(skip).cloned().collect()
    }

    /// Subscribe to live block events.
    pub fn subscribe(&self) -> broadcast::Receiver<BlockEvent> {
        self.inner.tx.subscribe()
    }

    /// Top-N blocked qnames by hit count, descending.
    pub fn top_blocked(&self, n: usize) -> Vec<(String, u64)> {
        let top = self.inner.top.lock();
        let mut v: Vec<(String, u64)> = top.iter().map(|(k, c)| (k.clone(), *c)).collect();
        v.sort_unstable_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        v.truncate(n);
        v
    }

    /// Reset all counters and drop the recent buffer.
    pub fn reset(&self) {
        self.inner.recent.lock().clear();
        self.inner.top.lock().clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(name: &str, zone: &str) -> BlockEvent {
        BlockEvent {
            ts: 0,
            qname: name.into(),
            action: "nxdomain",
            zone: zone.into(),
        }
    }

    #[test]
    fn ring_caps_and_orders() {
        let events = BlockEvents::new();
        for i in 0..(RECENT_CAP + 10) {
            events.record(ev(&format!("d{i}.test"), "z"));
        }
        let recent = events.recent(5);
        assert_eq!(recent.len(), 5);
        // Oldest of the snapshot is offset (RECENT_CAP+10-5).
        let expected_first = format!("d{}.test", RECENT_CAP + 5);
        assert_eq!(recent[0].qname, expected_first);
    }

    #[test]
    fn top_blocked_sorted_and_capped() {
        let events = BlockEvents::new();
        for _ in 0..3 {
            events.record(ev("a.test", "z"));
        }
        events.record(ev("b.test", "z"));
        events.record(ev("c.test", "z"));
        events.record(ev("c.test", "z"));

        let top = events.top_blocked(2);
        assert_eq!(top.len(), 2);
        assert_eq!(top[0].0, "a.test");
        assert_eq!(top[0].1, 3);
        assert_eq!(top[1].0, "c.test");
        assert_eq!(top[1].1, 2);
    }

    #[tokio::test]
    async fn broadcast_delivers() {
        let events = BlockEvents::new();
        let mut rx = events.subscribe();
        events.record(ev("x.test", "z"));
        let got = rx.recv().await.unwrap();
        assert_eq!(got.qname, "x.test");
    }
}

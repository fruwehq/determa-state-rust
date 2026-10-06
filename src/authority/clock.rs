//! Exact host-owned final clock reads: no arbitrary user code at commit.
use std::sync::{
    atomic::{AtomicBool, AtomicI64, Ordering},
    Arc,
};
use std::time::{SystemTime, UNIX_EPOCH};

/// Installed native clock, separate from portable worker timestamps.
/// Controlled sources require the trusted installer to maintain their sample
/// and availability. They do not tick, schedule or query external services.
#[derive(Clone)]
pub struct NativeCommitClock(ClockSource);
#[derive(Clone)]
enum ClockSource {
    System,
    Controlled {
        now: Arc<AtomicI64>,
        unavailable: Arc<AtomicBool>,
    },
}
impl NativeCommitClock {
    pub fn system() -> Self {
        Self(ClockSource::System)
    }
    pub fn controlled(now: Arc<AtomicI64>, unavailable: Arc<AtomicBool>) -> Self {
        Self(ClockSource::Controlled { now, unavailable })
    }
    pub fn read_ns(&self) -> Result<i64, String> {
        match &self.0 {
            ClockSource::System => {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|_| "native clock before epoch".to_string())?;
                i64::try_from(now.as_nanos()).map_err(|_| "native clock overflow".into())
            }
            ClockSource::Controlled { now, unavailable } => {
                if unavailable.load(Ordering::SeqCst) {
                    return Err("native clock unavailable".into());
                }
                Ok(now.load(Ordering::SeqCst))
            }
        }
    }
}

//! Store backends (SPEC §8/§13.1). A store persists registered definition YAML
//! sources, instance snapshots, the virtual clock, and the processing mode. The
//! three standard backends — `file`, `mem`, `sqlite` — are behaviorally identical.

use crate::runtime::{Mode, Snapshot};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StoreData {
    #[serde(default)]
    pub defs: Vec<String>,
    #[serde(default)]
    pub instances: Vec<Snapshot>,
    #[serde(default)]
    pub clock: u64,
    #[serde(default = "default_mode")]
    pub mode: String,
}

fn default_mode() -> String {
    "auto".to_string()
}

impl StoreData {
    pub fn mode(&self) -> Mode {
        if self.mode == "manual" {
            Mode::Manual
        } else {
            Mode::Auto
        }
    }
}

/// A parsed `--store` spec.
#[derive(Debug, Clone)]
pub enum StoreSpec {
    File(PathBuf),
    Mem,
    Sqlite(PathBuf),
}

impl StoreSpec {
    pub fn parse(spec: &str) -> StoreSpec {
        if let Some(rest) = spec.strip_prefix("file:") {
            StoreSpec::File(PathBuf::from(rest))
        } else if spec == "mem:" || spec == "mem" {
            StoreSpec::Mem
        } else if let Some(rest) = spec.strip_prefix("sqlite:") {
            StoreSpec::Sqlite(PathBuf::from(rest))
        } else {
            StoreSpec::File(PathBuf::from(spec))
        }
    }
}

pub trait Store {
    fn load(&self) -> StoreData;
    fn save(&self, data: &StoreData);
}

// ---- file backend (single JSON document in a directory) ----

pub struct FileStore {
    dir: PathBuf,
}

impl FileStore {
    pub fn new(dir: PathBuf) -> Self {
        FileStore { dir }
    }
    fn path(&self) -> PathBuf {
        self.dir.join("store.json")
    }
}

impl Store for FileStore {
    fn load(&self) -> StoreData {
        match fs::read(self.path()) {
            Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
            Err(_) => StoreData::default(),
        }
    }
    fn save(&self, data: &StoreData) {
        let _ = fs::create_dir_all(&self.dir);
        let bytes = serde_json::to_vec_pretty(data).expect("serialize store");
        let _ = fs::write(self.path(), bytes);
    }
}

// ---- in-memory backend (ephemeral; lives only within one process) ----

use std::cell::RefCell;
use std::rc::Rc;

pub struct MemStore {
    inner: Rc<RefCell<StoreData>>,
}

impl MemStore {
    pub fn new() -> Self {
        MemStore {
            inner: Rc::new(RefCell::new(StoreData::default())),
        }
    }
    pub fn handle(&self) -> Rc<RefCell<StoreData>> {
        self.inner.clone()
    }
}

impl Default for MemStore {
    fn default() -> Self {
        Self::new()
    }
}

impl Store for MemStore {
    fn load(&self) -> StoreData {
        self.inner.borrow().clone()
    }
    fn save(&self, data: &StoreData) {
        *self.inner.borrow_mut() = data.clone();
    }
}

// ---- sqlite backend (single-row JSON blob) ----

pub struct SqliteStore {
    path: PathBuf,
}

impl SqliteStore {
    pub fn new(path: PathBuf) -> Self {
        SqliteStore { path }
    }
    fn conn(&self) -> rusqlite::Result<rusqlite::Connection> {
        if let Some(parent) = self.path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let conn = rusqlite::Connection::open(&self.path)?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS harel_store (id INTEGER PRIMARY KEY, data TEXT NOT NULL);",
        )?;
        Ok(conn)
    }
}

impl Store for SqliteStore {
    fn load(&self) -> StoreData {
        let conn = match self.conn() {
            Ok(c) => c,
            Err(_) => return StoreData::default(),
        };
        let row: Option<String> = conn
            .query_row(
                "SELECT data FROM harel_store WHERE id = 0",
                [],
                |r| r.get(0),
            )
            .ok();
        match row {
            Some(s) => serde_json::from_str(&s).unwrap_or_default(),
            None => StoreData::default(),
        }
    }
    fn save(&self, data: &StoreData) {
        if let Ok(conn) = self.conn() {
            let s = serde_json::to_string(data).unwrap_or_default();
            let _ = conn.execute(
                "INSERT INTO harel_store (id, data) VALUES (0, ?1) \
                 ON CONFLICT(id) DO UPDATE SET data = excluded.data",
                rusqlite::params![s],
            );
        }
    }
}

/// Open the appropriate backend for a spec.
pub fn open(spec: &StoreSpec) -> Box<dyn Store> {
    match spec {
        StoreSpec::File(dir) => Box::new(FileStore::new(dir.clone())),
        StoreSpec::Mem => Box::new(MemStore::new()),
        StoreSpec::Sqlite(path) => Box::new(SqliteStore::new(path.clone())),
    }
}

/// Map a `BTreeMap<String,Value>` snapshot map back into typed data (unused hook).
pub fn _inflate(_m: BTreeMap<String, crate::Value>) {}

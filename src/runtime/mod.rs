//! The harel runtime engine (SPEC §5). Run-to-completion dispatch over a resolved
//! [`Machine`]: hierarchical states with LCA exit/entry, esvs with scope, history,
//! defer, timers over a virtual clock, orthogonal regions + `done`, choice
//! pseudostates, active objects (spawn/publish/scope), faults, and snapshot/restore.

use crate::cel::{self, CelError, Env};
use crate::machine::{HistoryKind, Machine, NodeId, StateDef, StateKind};
use crate::model::Action;
use crate::value::{map1, Value};
use std::collections::{BTreeMap, BTreeSet, HashSet, VecDeque};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Active,
    Faulted,
    Terminated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Auto,
    Manual,
}

pub type InstanceId = String;

#[derive(Debug, Clone, PartialEq)]
pub struct QueuedEvent {
    pub etype: String,
    pub payload: Value,
    pub origin: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
enum QItem {
    Event(QueuedEvent),
    Timer { state: NodeId, after_idx: usize },
}

impl QItem {
    fn label(&self) -> String {
        match self {
            QItem::Event(e) => e.etype.clone(),
            QItem::Timer { .. } => "__time__".into(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ArmedTimer {
    pub state: NodeId,
    pub after_idx: usize,
    pub due: u64,
}

#[derive(Debug, Clone)]
pub struct DeadLetterRecord {
    pub event: QueuedEvent,
    pub reason: String,
}

#[derive(Debug, Clone)]
enum HistRecord {
    Shallow(Vec<NodeId>),
    Deep(Vec<NodeId>),
}

pub struct Instance {
    pub id: InstanceId,
    pub parent: Option<InstanceId>,
    pub def_id: String,
    pub def_version: i64,
    pub status: Status,
    pub mode: Mode,
    pub active: BTreeSet<NodeId>,
    pub esvs: BTreeMap<String, Value>,
    pub external_source: BTreeMap<String, Value>,
    queue: VecDeque<QItem>,
    deferred: Vec<QItem>,
    pub timers: Vec<ArmedTimer>,
    pub spawn_counter: u64,
    pub dead_letter: Vec<DeadLetterRecord>,
    history: BTreeMap<NodeId, HistRecord>,
    done_emitted: HashSet<NodeId>,
}

/// A per-RTC-step observer record (SPEC §8 / §14).
#[derive(Debug, Clone, Default)]
pub struct StepRecord {
    pub event: String,
    pub transition: Option<String>,
    pub entered: Vec<String>,
    pub exited: Vec<String>,
    pub published: Vec<String>,
    pub spawned: Vec<String>,
    pub faulted: bool,
}

#[derive(Debug, Clone, Default)]
pub struct RunResult {
    pub published: Vec<String>,
    pub spawned: Vec<String>,
}

// ===================== tree helpers =====================

fn ancestors_inclusive(m: &Machine, n: NodeId) -> Vec<NodeId> {
    let mut out = Vec::new();
    let mut cur = Some(n);
    while let Some(c) = cur {
        out.push(c);
        cur = m.get(c).parent;
    }
    out
}

fn proper_ancestors(m: &Machine, n: NodeId) -> Vec<NodeId> {
    let mut out = Vec::new();
    let mut cur = m.get(n).parent;
    while let Some(c) = cur {
        out.push(c);
        cur = m.get(c).parent;
    }
    out
}

fn is_ancestor_or_equal(m: &Machine, anc: NodeId, n: NodeId) -> bool {
    let mut cur = Some(n);
    while let Some(c) = cur {
        if c == anc {
            return true;
        }
        cur = m.get(c).parent;
    }
    false
}

fn is_strictly_below(m: &Machine, anc: NodeId, n: NodeId) -> bool {
    n != anc && is_ancestor_or_equal(m, anc, n)
}

fn is_leaf(m: &Machine, n: NodeId) -> bool {
    matches!(m.get(n).kind, StateKind::Simple | StateKind::Final)
}

fn active_leaves(inst: &Instance, m: &Machine) -> Vec<NodeId> {
    inst.active
        .iter()
        .copied()
        .filter(|&n| is_leaf(m, n))
        .collect()
}

fn esv_key(state: &StateDef, name: &str) -> String {
    format!("{}::{}", state.path, name)
}

fn nearest_declaring(inst: &Instance, m: &Machine, scope: NodeId, name: &str) -> Option<NodeId> {
    for s in scope_chain(m, scope) {
        if inst.active.contains(&s) && m.get(s).esvs.iter().any(|(n, _)| n == name) {
            return Some(s);
        }
    }
    None
}

fn resolve_visible(inst: &Instance, m: &Machine, scope: NodeId) -> BTreeMap<String, Value> {
    let mut out = BTreeMap::new();
    for s in scope_chain(m, scope) {
        if !inst.active.contains(&s) {
            continue;
        }
        let sd = m.get(s);
        for (name, _) in &sd.esvs {
            if out.contains_key(name) {
                continue;
            }
            if let Some(v) = inst.esvs.get(&esv_key(sd, name)) {
                out.insert(name.clone(), v.clone());
            }
        }
    }
    out
}

/// Esv-scope chain: walk up from `scope`, stopping AT a submachine boundary
/// (inclusive) — the parent's esvs are not visible inside an inlined submachine
/// (SPEC §5.6.1).
fn scope_chain(m: &Machine, scope: NodeId) -> Vec<NodeId> {
    let mut chain = vec![scope];
    let mut cur = scope;
    loop {
        if m.get(cur).is_sm_boundary {
            break;
        }
        match m.get(cur).parent {
            Some(p) => {
                chain.push(p);
                cur = p;
                if m.get(cur).is_sm_boundary {
                    break;
                }
            }
            None => break,
        }
    }
    chain
}

// ===================== step buffer =====================

struct SpawnReq {
    parent: InstanceId,
    scope: NodeId,
    def_id: String,
    payload: BTreeMap<String, Value>,
    result_var: Option<String>,
}

#[derive(Default)]
struct StepBuf {
    deliveries: Vec<(InstanceId, QueuedEvent)>,
    undirected: Vec<(InstanceId, String, Value)>,
    spawns: Vec<SpawnReq>,
    published: Vec<String>,
    spawned: Vec<String>,
    spawned_def: Vec<String>,
    stop: bool,
}

// ===================== engine =====================

pub struct Engine {
    pub defs: BTreeMap<(String, i64), Machine>,
    pub latest: BTreeMap<String, i64>,
    pub instances: BTreeMap<InstanceId, Instance>,
    pub clock: u64,
    pub mode: Mode,
    pub observer: Option<Box<dyn FnMut(&StepRecord) + Send>>,
    run_published: Vec<String>,
    run_spawned: Vec<String>,
}

impl Default for Engine {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub enum EngineError {
    NotFound(String),
    Validation(String),
    Faulted(String),
    Other(String),
}

#[derive(Debug, Clone)]
pub struct StateView {
    pub instance: InstanceId,
    pub def: String,
    pub status: Status,
    pub config: Vec<String>,
    pub esvs: BTreeMap<String, Value>,
}

#[derive(Debug, Clone)]
pub struct ListView {
    pub id: InstanceId,
    pub def: String,
    pub parent: Option<InstanceId>,
    pub status: Status,
    pub config: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct InspectView {
    pub instance: InstanceId,
    pub status: Status,
    pub config: Vec<String>,
    pub esvs: BTreeMap<String, Value>,
    pub enabled: Vec<String>,
    pub queue: Vec<QueuedEvent>,
    pub deferred: Vec<QueuedEvent>,
    pub timers: Vec<ArmedTimer>,
    pub history: BTreeMap<String, String>,
    pub dead_letter: Vec<DeadLetterRecord>,
}

impl Engine {
    pub fn new() -> Self {
        Engine {
            defs: BTreeMap::new(),
            latest: BTreeMap::new(),
            instances: BTreeMap::new(),
            clock: 0,
            mode: Mode::Auto,
            observer: None,
            run_published: Vec::new(),
            run_spawned: Vec::new(),
        }
    }

    pub fn set_observer<F: FnMut(&StepRecord) + Send + 'static>(&mut self, f: F) {
        self.observer = Some(Box::new(f));
    }

    pub fn register(&mut self, m: Machine) {
        let id = m.id.clone();
        let ver = m.version;
        self.defs.insert((id.clone(), ver), m);
        let e = self.latest.entry(id).or_insert(0);
        if ver > *e {
            *e = ver;
        }
    }

    fn def_ref(&self, id: &str, version: i64) -> &Machine {
        self.defs
            .get(&(id.to_string(), version))
            .expect("definition registered")
    }

    pub fn def(&self, id: &str, version: Option<i64>) -> Result<&Machine, EngineError> {
        let v = match version {
            Some(v) => v,
            None => *self
                .latest
                .get(id)
                .ok_or_else(|| EngineError::NotFound(format!("definition '{id}'")))?,
        };
        self.defs
            .get(&(id.to_string(), v))
            .ok_or_else(|| EngineError::NotFound(format!("definition '{id}@{v}'")))
    }

    pub fn create_root(
        &mut self,
        id: &str,
        def_id: &str,
        version: Option<i64>,
        external: &BTreeMap<String, Value>,
    ) -> Result<(), EngineError> {
        if self.instances.contains_key(id) {
            return Err(EngineError::Other(format!("instance '{id}' already exists")));
        }
        let (did, ver) = {
            let m = self.def(def_id, version)?;
            (m.id.clone(), m.version)
        };
        let mut inst = new_instance(id, None, did, ver, self.mode, external);
        let m = self.def_ref(&inst.def_id, inst.def_version).clone();
        let mut buf = StepBuf::default();
        let mut rec = StepRecord::default();
        enter(&mut inst, &m, m.top, self.clock, &Value::Null, None, &mut buf, &mut rec);
        descend(&mut inst, &m, m.top, self.clock, &Value::Null, None, &mut buf, &mut rec);
        self.instances.insert(id.to_string(), inst);
        self.commit(buf)?;
        self.run_to_quiescence()?;
        Ok(())
    }

    pub fn instance(&self, id: &str) -> Result<&Instance, EngineError> {
        self.instances
            .get(id)
            .ok_or_else(|| EngineError::NotFound(format!("instance '{id}'")))
    }

    pub fn validate_event(&self, inst_id: &str, etype: &str, payload: &Value) -> Result<(), String> {
        let inst = self
            .instances
            .get(inst_id)
            .ok_or_else(|| format!("instance '{inst_id}' not found"))?;
        let m = self.def_ref(&inst.def_id, inst.def_version);
        validate_event_payload(m, etype, payload)
    }

    pub fn inject(&mut self, inst_id: &str, etype: &str, payload: Value) -> Result<bool, EngineError> {
        let ok = {
            let inst = self.instances.get(inst_id).ok_or_else(|| {
                EngineError::NotFound(format!("instance '{inst_id}'"))
            })?;
            let m = self.def_ref(&inst.def_id, inst.def_version);
            validate_event_payload(m, etype, &payload).is_ok()
        };
        if ok {
            let inst = self.instances.get_mut(inst_id).unwrap();
            inst.queue.push_back(QItem::Event(QueuedEvent {
                etype: etype.to_string(),
                payload,
                origin: None,
            }));
        }
        Ok(ok)
    }

    pub fn send(&mut self, inst_id: &str, etype: &str, payload: Value) -> Result<RunResult, EngineError> {
        self.run_published.clear();
        self.run_spawned.clear();
        let accepted = self.inject(inst_id, etype, payload)?;
        if accepted && self.mode == Mode::Auto {
            self.run_to_quiescence()?;
        }
        Ok(RunResult {
            published: std::mem::take(&mut self.run_published),
            spawned: std::mem::take(&mut self.run_spawned),
        })
    }

    pub fn advance(&mut self, duration_ms: u64) -> Result<RunResult, EngineError> {
        self.run_published.clear();
        self.run_spawned.clear();
        self.clock = self.clock.saturating_add(duration_ms);
        loop {
            // pick the earliest-due armed timer across all instances
            let pick: Option<(InstanceId, usize, u64)> = {
                let mut best: Option<(InstanceId, usize, u64)> = None;
                for (iid, inst) in &self.instances {
                    for (i, t) in inst.timers.iter().enumerate() {
                        if t.due <= self.clock {
                            let cand = (iid.clone(), i, t.due);
                            match &best {
                                None => best = Some(cand),
                                Some(b) => {
                                    if (t.due, &iid.clone()) < (b.2, &b.0) {
                                        best = Some(cand);
                                    }
                                }
                            }
                        }
                    }
                }
                best
            };
            match pick {
                None => break,
                Some((iid, i, _)) => {
                    let inst = self.instances.get_mut(&iid).unwrap();
                    let timer = inst.timers.remove(i);
                    inst.queue.push_back(QItem::Timer {
                        state: timer.state,
                        after_idx: timer.after_idx,
                    });
                }
            }
        }
        self.run_to_quiescence()?;
        Ok(RunResult {
            published: std::mem::take(&mut self.run_published),
            spawned: std::mem::take(&mut self.run_spawned),
        })
    }

    pub fn step(&mut self, inst_id: &str, n: usize) -> Result<Vec<StepRecord>, EngineError> {
        self.run_published.clear();
        self.run_spawned.clear();
        let mut records = Vec::new();
        for _ in 0..n {
            let has = self
                .instances
                .get(inst_id)
                .map(|i| !i.queue.is_empty())
                .unwrap_or(false);
            if !has {
                break;
            }
            let rec = self.dispatch_one(inst_id)?;
            records.push(rec);
            self.run_to_quiescence()?;
        }
        Ok(records)
    }

    pub fn env_change(
        &mut self,
        inst_id: &str,
        changed: BTreeMap<String, Value>,
    ) -> Result<RunResult, EngineError> {
        let mut payload = BTreeMap::new();
        payload.insert("changed".to_string(), Value::Map(changed));
        self.send(inst_id, "env", Value::Map(payload))
    }

    pub fn set_mode(&mut self, mode: Mode) {
        self.mode = mode;
        for inst in self.instances.values_mut() {
            inst.mode = mode;
        }
    }
    pub fn get_mode(&self) -> Mode {
        self.mode
    }

    /// Migrate eligible quiescent instances to a newer registered version (SPEC §10.2).
    pub fn migrate_quiescent(&mut self) -> Result<(), EngineError> {
        // gather instance ids + their current def
        let candidates: Vec<(InstanceId, String, i64)> = self
            .instances
            .iter()
            .filter(|(_, i)| i.status == Status::Active && i.queue.is_empty() && i.deferred.is_empty())
            .map(|(id, i)| (id.clone(), i.def_id.clone(), i.def_version))
            .collect();
        for (iid, def_id, v_old) in candidates {
            if let Some(new_ver) = self.find_migration_target(&def_id, v_old) {
                self.apply_migration(&iid, &def_id, v_old, new_ver)?;
            }
        }
        Ok(())
    }

    fn find_migration_target(&self, def_id: &str, from: i64) -> Option<i64> {
        let latest = *self.latest.get(def_id)?;
        if latest <= from {
            return None;
        }
        // find the new def and a migration from->new
        for v in (from + 1)..=latest {
            if let Some(new_m) = self.defs.get(&(def_id.to_string(), v)) {
                if new_m.migrations.iter().any(|mig| mig.from == from && mig.to == v) {
                    return Some(v);
                }
            }
        }
        None
    }

    fn apply_migration(
        &mut self,
        iid: &str,
        def_id: &str,
        from: i64,
        to: i64,
    ) -> Result<(), EngineError> {
        let migration = {
            let new_m = self.defs.get(&(def_id.to_string(), to)).cloned();
            let old_m = self.defs.get(&(def_id.to_string(), from)).cloned();
            let (new_m, old_m) = match (new_m, old_m) {
                (Some(n), Some(o)) => (n, o),
                _ => return Ok(()),
            };
            new_m
                .migrations
                .iter()
                .find(|m| m.from == from && m.to == to)
                .cloned()
                .map(|m| (m, new_m, old_m))
        };
        let (migration, new_m, old_m) = match migration {
            Some(x) => x,
            None => return Ok(()),
        };
        // current leaf name (single-leaf instances only)
        let leaf_name = {
            let inst = self.instances.get(iid).unwrap();
            let leaves = active_leaves(inst, &old_m);
            if leaves.len() != 1 {
                return Ok(()); // not in migration domain
            }
            old_m.get(leaves[0]).id.clone()
        };
        // `when` check
        if let Some(when) = &migration.when {
            let _inst = self.instances.get(iid).unwrap();
            let mut env = Env::new();
            env = env.with("state", Value::Str(leaf_name.clone()));
            if !cel::eval_bool(when, &env).unwrap_or(false) {
                return Ok(());
            }
        }
        // state_map covers current leaf
        let new_leaf_name = match migration.state_map.get(&leaf_name) {
            Some(n) => n.clone(),
            None => return Ok(()),
        };
        let new_leaf = match new_m.by_name.get(&new_leaf_name).copied() {
            Some(n) => n,
            None => return Ok(()),
        };
        // apply: remap active config, keep esvs (top-level keys identical), run esvs transform
        let inst = self.instances.get_mut(iid).unwrap();
        inst.active.clear();
        for a in ancestors_inclusive(&new_m, new_leaf) {
            inst.active.insert(a);
        }
        inst.def_version = to;
        // run esvs transforms over current esvs (state binding = leaf)
        let mut buf = StepBuf::default();
        let mut rec = StepRecord::default();
        let event = Value::Null;
        // build env from top esvs + state
        let scope = new_m.top;
        let mut env = build_env(inst, &new_m, scope, &event);
        env = env.with("state", Value::Str(leaf_name.clone()));
        for a in &migration.esvs {
            // run a single assign-style action directly with this env
            if let Action::Assign(pairs) = a {
                for (name, expr) in pairs {
                    if let Ok(val) = cel::eval(expr, &env) {
                        if let Some(st) = nearest_declaring(inst, &new_m, scope, name) {
                            let decl = new_m
                                .get(st)
                                .esvs
                                .iter()
                                .find(|(n, _)| n == name)
                                .map(|(_, d)| d.clone())
                                .unwrap();
                            if let Some(c) = val.coerce_to(&decl.ty) {
                                inst.esvs.insert(esv_key(new_m.get(st), name), c);
                            }
                        }
                    }
                }
            } else {
                let _ = run_one(inst, &new_m, scope, a, &event, None, &mut buf, &mut rec);
            }
        }
        let _ = (buf, rec);
        Ok(())
    }

    // -------- quiescence --------

    fn run_to_quiescence(&mut self) -> Result<(), EngineError> {
        let mut guard = 0u32;
        loop {
            guard += 1;
            if guard > 200_000 {
                return Err(EngineError::Other("runaway quiescence loop".into()));
            }
            let target = self
                .instances
                .iter()
                .filter(|(_, i)| i.status == Status::Active && i.mode == Mode::Auto && !i.queue.is_empty())
                .map(|(id, _)| id.clone())
                .next();
            match target {
                Some(id) => {
                    self.dispatch_one(&id)?;
                }
                None => break,
            }
        }
        Ok(())
    }

    fn dispatch_one(&mut self, inst_id: &str) -> Result<StepRecord, EngineError> {
        let (did, ver) = {
            let inst = self.instances.get(inst_id).ok_or_else(|| {
                EngineError::NotFound(format!("instance '{inst_id}'"))
            })?;
            (inst.def_id.clone(), inst.def_version)
        };
        let m = self.def_ref(&did, ver).clone();
        let item = self.instances.get_mut(inst_id).unwrap().queue.pop_front();
        let rec = match item {
            None => StepRecord::default(),
            Some(qi) => {
                let rec = self.execute_rtc(inst_id, &m, qi);
                if let Some(o) = &mut self.observer {
                    o(&rec);
                }
                rec
            }
        };
        Ok(rec)
    }

    fn execute_rtc(&mut self, inst_id: &str, m: &Machine, item: QItem) -> StepRecord {
        let mut rec = StepRecord {
            event: item.label(),
            ..Default::default()
        };
        let etype = match &item {
            QItem::Event(e) => Some(e.etype.clone()),
            QItem::Timer { .. } => None,
        };
        let event_value = match &item {
            QItem::Event(e) => event_binding(e),
            QItem::Timer { .. } => Value::Null,
        };

        // snapshot for rollback
        let backup = self.instances.get(inst_id).map(|i| Instance::snapshot_state(i));

        // env: update external source
        if etype.as_deref() == Some("env") {
            if let Some(changed) = changed_of(&event_value) {
                for (k, v) in changed {
                    self.instances
                        .get_mut(inst_id)
                        .unwrap()
                        .external_source
                        .insert(k, v);
                }
            }
        }

        let handlers = match &item {
            QItem::Event(e) => find_handlers(self.instances.get_mut(inst_id).unwrap(), m, &e.etype, &event_value),
            QItem::Timer { state, after_idx } => vec![Handler { state: *state, kind: HKind::Timer(*after_idx) }],
        };

        let mut buf = StepBuf::default();

        if handlers.is_empty() {
            let defer_set = effective_defer(self.instances.get(inst_id).unwrap(), m);
            let do_defer = match &item {
                QItem::Event(e) => defer_set.contains(&e.etype),
                QItem::Timer { .. } => false,
            };
            if do_defer {
                self.instances.get_mut(inst_id).unwrap().deferred.push(item);
            }
            return rec;
        }

        // execute handlers
        let mut faulted: Option<CelError> = None;
        for h in &handlers {
            let inst = self.instances.get_mut(inst_id).unwrap();
            if let Err(e) = execute_handler(inst, m, h, &event_value, etype.as_deref(), &mut buf, &mut rec) {
                faulted = Some(e);
                break;
            }
        }

        if let Some(fault) = faulted {
            // rollback
            if let Some(b) = backup {
                let inst = self.instances.get_mut(inst_id).unwrap();
                inst.restore_state(b);
            }
            rec.faulted = true;
            rec.published.clear();
            rec.spawned.clear();
            rec.entered.clear();
            rec.exited.clear();
            rec.transition = None;
            if let QItem::Event(e) = &item {
                self.instances.get_mut(inst_id).unwrap().dead_letter.push(DeadLetterRecord {
                    event: e.clone(),
                    reason: fault.to_string(),
                });
            }
            let has_err = scope_has_error_handler(self.instances.get(inst_id).unwrap(), m);
            if has_err {
                self.instances.get_mut(inst_id).unwrap().queue.push_front(QItem::Event(QueuedEvent {
                    etype: "error".into(),
                    payload: Value::Map(error_payload(&fault)),
                    origin: None,
                }));
            } else {
                self.instances.get_mut(inst_id).unwrap().status = Status::Faulted;
            }
            return rec;
        }

        // commit cross-instance effects
        let _ = self.commit(buf);

        // post-step: done + termination + defer replay
        let m2 = m.clone();
        self.post_step(inst_id, &m2);

        // stop action?
        if self.instances.get(inst_id).map(|i| i.status == Status::Active).unwrap_or(false) {
            // handle pending stop items already enqueued as events in the queue loop
        }

        rec
    }

    fn post_step(&mut self, inst_id: &str, m: &Machine) {
        // Completion (SPEC §5.6 / §5.6.1): any active composite whose active leaf is
        // final, or orthogonal whose regions are all final, generates a `done` event
        // for its parent. `top` completion terminates a spawned instance instead.
        let complete: Vec<NodeId> = self
            .instances
            .get(inst_id)
            .map(|i| complete_states(i, m))
            .unwrap_or_default();
        for s in complete {
            if s == m.top {
                continue;
            }
            let already = self.instances.get(inst_id).unwrap().done_emitted.contains(&s);
            if already {
                continue;
            }
            let leaf_name = self
                .instances
                .get(inst_id)
                .map(|i| composite_leaf_name(i, m, s))
                .unwrap_or_default();
            let inst = self.instances.get_mut(inst_id).unwrap();
            inst.done_emitted.insert(s);
            inst.queue.push_back(QItem::Event(QueuedEvent {
                etype: "done".into(),
                payload: map1("state", Value::Str(leaf_name)),
                origin: None,
            }));
        }
        // termination via top-level final (spawned instances only) or stop
        self.handle_termination(inst_id, m);
        // defer replay
        let inst = self.instances.get_mut(inst_id).unwrap();
        replay_deferred(inst, m);
    }

    fn handle_termination(&mut self, inst_id: &str, m: &Machine) {
        let (terminate, parent_id) = {
            let inst = match self.instances.get(inst_id) {
                Some(i) if i.status == Status::Active => i,
                _ => return,
            };
            let top_final = inst.active.iter().any(|&n| {
                m.get(n).kind == StateKind::Final && m.get(n).parent == Some(m.top)
            });
            let stop_pending = inst
                .queue
                .iter()
                .any(|q| matches!(q, QItem::Event(e) if e.etype == "__stop__"));
            let do_term = (top_final && inst.parent.is_some()) || stop_pending;
            (do_term, inst.parent.clone())
        };
        if terminate {
            let inst = self.instances.get_mut(inst_id).unwrap();
            // remove any pending stop marker
            inst.queue.retain(|q| !matches!(q, QItem::Event(e) if e.etype == "__stop__"));
            // run exit actions from leaves up
            let leaves: Vec<NodeId> = inst.active.iter().copied().filter(|&n| is_leaf(m, n)).collect();
            let mut sink = StepBuf::default();
            for leaf in leaves {
                let mut rec = StepRecord::default();
                exit_up_to(inst, m, leaf, Some(m.top), &mut sink, &mut rec);
            }
            inst.active.clear();
            inst.status = Status::Terminated;
            inst.done_emitted.clear();
            // commit any exit-time publishes (rare) then deliver done to parent
            // (we enqueue directly to parent here)
            let _ = sink;
            if let Some(parent) = parent_id {
                if let Some(p) = self.instances.get_mut(&parent) {
                    if p.status == Status::Active {
                        p.queue.push_back(QItem::Event(QueuedEvent {
                            etype: "done".into(),
                            payload: Value::Null,
                            origin: Some(inst_id.to_string()),
                        }));
                    }
                }
            }
        }
    }

    fn commit(&mut self, buf: StepBuf) -> Result<(), EngineError> {
        self.run_published.extend(buf.published);
        self.run_spawned.extend(buf.spawned_def);

        // directed deliveries
        for (target, ev) in buf.deliveries {
            if let Some(t) = self.instances.get_mut(&target) {
                if t.status == Status::Active {
                    t.queue.push_back(QItem::Event(ev));
                }
            }
        }
        // undirected (scope + subscription)
        for (publisher, etype, payload) in buf.undirected {
            let scope = self
                .instances
                .get(&publisher)
                .and_then(|p| {
                    let m = self.defs.get(&(p.def_id.clone(), p.def_version))?;
                    m.events.get(&etype).map(|d| d.scope)
                })
                .unwrap_or(crate::machine::Scope::Internal);
            let targets = self.undirected_targets(&publisher, &etype, scope);
            for t in targets {
                if let Some(ti) = self.instances.get_mut(&t) {
                    if ti.status == Status::Active {
                        ti.queue.push_back(QItem::Event(QueuedEvent {
                            etype: etype.clone(),
                            payload: payload.clone(),
                            origin: Some(publisher.clone()),
                        }));
                    }
                }
            }
        }
        // spawns
        for sp in buf.spawns {
            let parent_id = sp.parent.clone();
            let n = {
                let p = self.instances.get_mut(&parent_id).unwrap();
                p.spawn_counter += 1;
                p.spawn_counter
            };
            let child_id = format!("{parent_id}/{n}");
            // result var in parent
            if let Some(res) = &sp.result_var {
                let m_clone = self
                    .defs
                    .get({
                        let p = self.instances.get(&parent_id).unwrap();
                        &(p.def_id.clone(), p.def_version)
                    })
                    .cloned();
                if let Some(m) = m_clone {
                    let p = self.instances.get_mut(&parent_id).unwrap();
                    if let Some(st) = nearest_declaring(p, &m, sp.scope, res) {
                        p.esvs.insert(esv_key(m.get(st), res), Value::Str(child_id.clone()));
                    }
                }
            }
            // create child
            let child_m = match self.def(&sp.def_id, None) {
                Ok(cm) => cm.clone(),
                Err(_) => continue,
            };
            let mut child = new_instance(
                &child_id,
                Some(parent_id.clone()),
                child_m.id.clone(),
                child_m.version,
                self.mode,
                &BTreeMap::new(),
            );
            // seed external esvs from spawn payload by name
            for (name, _) in &child_m.get(child_m.top).esvs.clone() {
                if let Some(v) = sp.payload.get(name) {
                    child.external_source.insert(name.clone(), v.clone());
                }
            }
            let mut cbuf = StepBuf::default();
            let mut crec = StepRecord::default();
            enter(&mut child, &child_m, child_m.top, self.clock, &Value::Null, None, &mut cbuf, &mut crec);
            descend(&mut child, &child_m, child_m.top, self.clock, &Value::Null, None, &mut cbuf, &mut crec);
            self.instances.insert(child_id, child);
            // recursively commit child's entry-time effects
            self.commit(cbuf)?;
        }
        Ok(())
    }

    fn undirected_targets(
        &self,
        publisher: &str,
        etype: &str,
        scope: crate::machine::Scope,
    ) -> Vec<InstanceId> {
        use crate::machine::Scope;
        // build candidate set by scope
        let candidates: Vec<InstanceId> = match scope {
            Scope::Internal => vec![publisher.to_string()],
            Scope::Global => self.instances.keys().cloned().collect(),
            Scope::Local => {
                // publisher's tree: ancestors + descendants + self
                let mut set: HashSet<InstanceId> = HashSet::new();
                // ancestors
                let mut cur = Some(publisher.to_string());
                while let Some(id) = cur {
                    set.insert(id.clone());
                    cur = self.instances.get(&id).and_then(|i| i.parent.clone());
                }
                // descendants
                let mut stack = vec![publisher.to_string()];
                while let Some(id) = stack.pop() {
                    set.insert(id.clone());
                    for (other_id, other) in &self.instances {
                        if other.parent.as_deref() == Some(id.as_str()) {
                            stack.push(other_id.clone());
                        }
                    }
                }
                set.into_iter().collect()
            }
        };
        candidates
            .into_iter()
            .filter(|cid| {
                if scope == Scope::Internal && cid == publisher {
                    return true; // always self-receive internal
                }
                let inst = match self.instances.get(cid) {
                    Some(i) => i,
                    None => return false,
                };
                let m = self.defs.get(&(inst.def_id.clone(), inst.def_version));
                m.map(|mm| mm.subscribe.iter().any(|s| s == etype))
                    .unwrap_or(false)
            })
            .collect()
    }

    // -------- views / snapshot --------

    pub fn state_view(&self, inst_id: &str) -> Result<StateView, EngineError> {
        let inst = self.instance(inst_id)?;
        let m = self.def_ref(&inst.def_id, inst.def_version);
        Ok(StateView {
            instance: inst_id.to_string(),
            def: format!("{}@{}", inst.def_id, inst.def_version),
            status: inst.status,
            config: config_of(inst, m),
            esvs: reported_esvs(inst, m),
        })
    }

    pub fn list_view(&self) -> Vec<ListView> {
        self.instances
            .iter()
            .map(|(id, inst)| {
                let m = self.def_ref(&inst.def_id, inst.def_version);
                ListView {
                    id: id.clone(),
                    def: format!("{}@{}", inst.def_id, inst.def_version),
                    parent: inst.parent.clone(),
                    status: inst.status,
                    config: config_of(inst, m),
                }
            })
            .collect()
    }

    pub fn inspect_view(&self, inst_id: &str) -> Result<InspectView, EngineError> {
        let inst = self.instance(inst_id)?;
        let m = self.def_ref(&inst.def_id, inst.def_version);
        let history = inst
            .history
            .iter()
            .map(|(n, h)| {
                let kind = match h {
                    HistRecord::Shallow(_) => "shallow",
                    HistRecord::Deep(_) => "deep",
                };
                (m.get(*n).path.clone(), kind.to_string())
            })
            .collect();
        Ok(InspectView {
            instance: inst_id.to_string(),
            status: inst.status,
            config: config_of(inst, m),
            esvs: reported_esvs(inst, m),
            enabled: enabled_events(inst, m),
            queue: inst.queue.iter().filter_map(|q| match q {
                QItem::Event(e) => Some(e.clone()),
                _ => None,
            }).collect(),
            deferred: inst.deferred.iter().filter_map(|q| match q {
                QItem::Event(e) => Some(e.clone()),
                _ => None,
            }).collect(),
            timers: inst.timers.clone(),
            history,
            dead_letter: inst.dead_letter.clone(),
        })
    }

    /// `enabled_events(instance)` — sorted declared event types the current active
    /// configuration can handle (SPEC §14).
    pub fn enabled_events(&self, inst_id: &str) -> Result<Vec<String>, EngineError> {
        let inst = self.instance(inst_id)?;
        let m = self.def_ref(&inst.def_id, inst.def_version);
        Ok(enabled_events(inst, m))
    }

    pub fn snapshot(&self, inst_id: &str) -> Result<Snapshot, EngineError> {
        let inst = self.instance(inst_id)?;
        let m = self.def_ref(&inst.def_id, inst.def_version);
        Snapshot::from_instance(inst, m)
    }

    pub fn restore(&mut self, snap: Snapshot) -> Result<(), EngineError> {
        let m = self
            .defs
            .get(&(snap.def_id.clone(), snap.def_version))
            .ok_or_else(|| EngineError::NotFound(format!("definition '{}@{}'", snap.def_id, snap.def_version)))?
            .clone();
        let inst = snap.into_instance(&m);
        self.instances.insert(inst.id.clone(), inst);
        Ok(())
    }
}

// ===================== snapshot =====================

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Snapshot {
    pub def_id: String,
    pub def_version: i64,
    pub id: InstanceId,
    pub parent_id: Option<InstanceId>,
    pub status: String,
    pub state_config: Vec<String>,
    pub esvs: BTreeMap<String, Value>,
    pub external_source: BTreeMap<String, Value>,
    pub queue: Vec<SnapEvent>,
    pub deferred: Vec<SnapEvent>,
    pub timers: Vec<SnapTimer>,
    pub dead_letter: Vec<SnapDeadLetter>,
    pub history: BTreeMap<String, SnapHist>,
    pub spawn_counter: u64,
    pub mode: String,
    #[serde(default)]
    pub clock: u64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SnapEvent {
    pub etype: String,
    pub payload: Value,
    pub origin: Option<String>,
}
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SnapTimer {
    pub state: String,
    pub after_idx: usize,
    pub due: u64,
}
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SnapDeadLetter {
    pub event: SnapEvent,
    pub reason: String,
}
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SnapHist {
    pub kind: String,
    pub states: Vec<String>,
}

impl Snapshot {
    fn from_instance(inst: &Instance, m: &Machine) -> Result<Snapshot, EngineError> {
        let state_config: Vec<String> = active_leaves(inst, m)
            .into_iter()
            .map(|n| m.get(n).path.clone())
            .collect();
        let history = inst
            .history
            .iter()
            .map(|(n, h)| {
                let (kind, states) = match h {
                    HistRecord::Shallow(s) => ("shallow", s.clone()),
                    HistRecord::Deep(s) => ("deep", s.clone()),
                };
                (
                    m.get(*n).path.clone(),
                    SnapHist {
                        kind: kind.to_string(),
                        states: states.iter().map(|x| m.get(*x).path.clone()).collect(),
                    },
                )
            })
            .collect();
        Ok(Snapshot {
            def_id: inst.def_id.clone(),
            def_version: inst.def_version,
            id: inst.id.clone(),
            parent_id: inst.parent.clone(),
            status: status_str(inst.status).to_string(),
            state_config,
            esvs: inst.esvs.clone(),
            external_source: inst.external_source.clone(),
            queue: snap_events(inst.queue.iter()),
            deferred: snap_events(inst.deferred.iter()),
            timers: inst
                .timers
                .iter()
                .map(|t| SnapTimer {
                    state: m.get(t.state).path.clone(),
                    after_idx: t.after_idx,
                    due: t.due,
                })
                .collect(),
            dead_letter: inst
                .dead_letter
                .iter()
                .map(|d| SnapDeadLetter {
                    event: SnapEvent {
                        etype: d.event.etype.clone(),
                        payload: d.event.payload.clone(),
                        origin: d.event.origin.clone(),
                    },
                    reason: d.reason.clone(),
                })
                .collect(),
            history,
            spawn_counter: inst.spawn_counter,
            mode: match inst.mode {
                Mode::Auto => "auto",
                Mode::Manual => "manual",
            }
            .into(),
            clock: 0,
        })
    }

    fn into_instance(self, m: &Machine) -> Instance {
        let status = match self.status.as_str() {
            "faulted" => Status::Faulted,
            "terminated" => Status::Terminated,
            _ => Status::Active,
        };
        let mode = match self.mode.as_str() {
            "manual" => Mode::Manual,
            _ => Mode::Auto,
        };
        let leaves: Vec<NodeId> = self
            .state_config
            .iter()
            .filter_map(|p| m.by_path.get(p).copied())
            .collect();
        let mut inst = Instance {
            id: self.id,
            parent: self.parent_id,
            def_id: self.def_id,
            def_version: self.def_version,
            status,
            mode,
            active: BTreeSet::new(),
            esvs: self.esvs,
            external_source: self.external_source,
            queue: self.queue.into_iter().map(|e| QItem::Event(QueuedEvent {
                etype: e.etype,
                payload: e.payload,
                origin: e.origin,
            })).collect(),
            deferred: self.deferred.into_iter().map(|e| QItem::Event(QueuedEvent {
                etype: e.etype,
                payload: e.payload,
                origin: e.origin,
            })).collect(),
            timers: self.timers.into_iter().filter_map(|t| {
                m.by_path.get(&t.state).copied().map(|state| ArmedTimer {
                    state,
                    after_idx: t.after_idx,
                    due: t.due,
                })
            }).collect(),
            spawn_counter: self.spawn_counter,
            dead_letter: self.dead_letter.into_iter().map(|d| DeadLetterRecord {
                event: QueuedEvent {
                    etype: d.event.etype,
                    payload: d.event.payload,
                    origin: d.event.origin,
                },
                reason: d.reason,
            }).collect(),
            history: self.history.into_iter().filter_map(|(path, h)| {
                let state = m.by_path.get(&path).copied()?;
                let states: Vec<NodeId> = h
                    .states
                    .iter()
                    .filter_map(|p| m.by_path.get(p).copied())
                    .collect();
                let rec = if h.kind == "shallow" {
                    HistRecord::Shallow(states)
                } else {
                    HistRecord::Deep(states)
                };
                Some((state, rec))
            }).collect(),
            done_emitted: HashSet::new(),
        };
        for leaf in leaves {
            for a in ancestors_inclusive(m, leaf) {
                inst.active.insert(a);
            }
        }
        inst
    }
}

fn snap_events<'a>(items: impl Iterator<Item = &'a QItem>) -> Vec<SnapEvent> {
    items
        .filter_map(|q| match q {
            QItem::Event(e) => Some(SnapEvent {
                etype: e.etype.clone(),
                payload: e.payload.clone(),
                origin: e.origin.clone(),
            }),
            QItem::Timer { .. } => None,
        })
        .collect()
}

fn status_str(s: Status) -> &'static str {
    match s {
        Status::Active => "active",
        Status::Faulted => "faulted",
        Status::Terminated => "terminated",
    }
}

// ===================== instance helpers =====================

fn new_instance(
    id: &str,
    parent: Option<InstanceId>,
    def_id: String,
    def_version: i64,
    mode: Mode,
    external: &BTreeMap<String, Value>,
) -> Instance {
    Instance {
        id: id.to_string(),
        parent,
        def_id,
        def_version,
        status: Status::Active,
        mode,
        active: BTreeSet::new(),
        esvs: BTreeMap::new(),
        external_source: external.clone(),
        queue: VecDeque::new(),
        deferred: Vec::new(),
        timers: Vec::new(),
        spawn_counter: 0,
        dead_letter: Vec::new(),
        history: BTreeMap::new(),
        done_emitted: HashSet::new(),
    }
}

impl Instance {
    fn snapshot_state(&self) -> InstanceState {
        InstanceState {
            active: self.active.clone(),
            esvs: self.esvs.clone(),
            timers: self.timers.clone(),
            history: self.history.clone(),
            done_emitted: self.done_emitted.clone(),
            deferred: self.deferred.clone(),
            spawn_counter: self.spawn_counter,
            external_source: self.external_source.clone(),
            status: self.status,
            queue: self.queue.clone(),
        }
    }
    fn restore_state(&mut self, s: InstanceState) {
        self.active = s.active;
        self.esvs = s.esvs;
        self.timers = s.timers;
        self.history = s.history;
        self.done_emitted = s.done_emitted;
        self.deferred = s.deferred;
        self.spawn_counter = s.spawn_counter;
        self.external_source = s.external_source;
        self.status = s.status;
        self.queue = s.queue;
    }
}

struct InstanceState {
    active: BTreeSet<NodeId>,
    esvs: BTreeMap<String, Value>,
    timers: Vec<ArmedTimer>,
    history: BTreeMap<NodeId, HistRecord>,
    done_emitted: HashSet<NodeId>,
    deferred: Vec<QItem>,
    spawn_counter: u64,
    external_source: BTreeMap<String, Value>,
    status: Status,
    queue: VecDeque<QItem>,
}

// ===================== handler discovery =====================

enum HKind {
    Transition(usize),
    Timer(usize),
}
struct Handler {
    state: NodeId,
    kind: HKind,
}

fn find_handlers(inst: &Instance, m: &Machine, etype: &str, event_value: &Value) -> Vec<Handler> {
    let leaves = active_leaves(inst, m);
    let mut found: Vec<Handler> = Vec::new();
    let mut seen: HashSet<NodeId> = HashSet::new();
    for leaf in leaves {
        for s in ancestors_inclusive(m, leaf) {
            if !inst.active.contains(&s) {
                continue;
            }
            if let Some(list) = m.get(s).on_events.get(etype) {
                let env = build_env(inst, m, s, event_value);
                let mut matched = None;
                for (i, t) in list.iter().enumerate() {
                    let pass = match &t.guard {
                        Some(g) => cel::eval_bool(g, &env).unwrap_or(false),
                        None => true,
                    };
                    if pass {
                        matched = Some(i);
                        break;
                    }
                }
                if let Some(i) = matched {
                    if seen.insert(s) {
                        found.push(Handler { state: s, kind: HKind::Transition(i) });
                    }
                }
                break; // this state claims the event for this leaf
            }
        }
    }
    found
}

fn scope_has_error_handler(inst: &Instance, m: &Machine) -> bool {
    inst.active
        .iter()
        .any(|&n| m.get(n).on_events.contains_key("error"))
}

// ===================== transition execution =====================

fn execute_handler(
    inst: &mut Instance,
    m: &Machine,
    h: &Handler,
    event_value: &Value,
    etype: Option<&str>,
    buf: &mut StepBuf,
    rec: &mut StepRecord,
) -> Result<(), CelError> {
    match &h.kind {
        HKind::Timer(idx) => {
            let after = m.get(h.state).after[*idx].clone();
            if let Some(g) = &after.guard {
                let env = build_env(inst, m, h.state, event_value);
                if !cel::eval_bool(g, &env)? {
                    return Ok(());
                }
            }
            run_actions(inst, m, h.state, &after.action, event_value, etype, buf, rec)?;
            if let Some(target) = after.target {
                rec.transition = Some(m.get(target).id.clone());
                external_transition(inst, m, h.state, target, &[], event_value, etype, buf, rec)?;
            }
            Ok(())
        }
        HKind::Transition(idx) => {
            let list = m.get(h.state).on_events.get(etype.unwrap_or("")).cloned();
            let list = match list {
                Some(l) => l,
                None => return Ok(()),
            };
            let t = list[*idx].clone();
            if t.target.is_none() || t.internal {
                run_actions(inst, m, h.state, &t.action, event_value, etype, buf, rec)?;
                rec.transition = None;
                return Ok(());
            }
            let target = t.target.unwrap();
            if t.local {
                rec.transition = Some(m.get(target).id.clone());
                run_actions(inst, m, h.state, &t.action, event_value, etype, buf, rec)?;
                local_transition(inst, m, h.state, target, event_value, etype, buf, rec)?;
                return Ok(());
            }
            rec.transition = Some(m.get(target).id.clone());
            let is_choice = m.get(target).kind == StateKind::Choice;
            if is_choice {
                run_actions(inst, m, h.state, &t.action, event_value, etype, buf, rec)?;
                let final_target = resolve_choice(inst, m, h.state, target, event_value, etype, buf, rec)?;
                external_transition(inst, m, h.state, final_target, &[], event_value, etype, buf, rec)?;
            } else {
                external_transition(inst, m, h.state, target, &t.action, event_value, etype, buf, rec)?;
            }
            Ok(())
        }
    }
}

fn resolve_choice(
    inst: &mut Instance,
    m: &Machine,
    source: NodeId,
    start: NodeId,
    event_value: &Value,
    etype: Option<&str>,
    buf: &mut StepBuf,
    rec: &mut StepRecord,
) -> Result<NodeId, CelError> {
    let mut cur = start;
    loop {
        let branches = m.get(cur).choice.clone().unwrap_or_default();
        let env = build_env(inst, m, source, event_value);
        let mut chosen: Option<usize> = None;
        for (i, b) in branches.iter().enumerate() {
            let pass = match &b.guard {
                Some(g) => cel::eval_bool(g, &env)?,
                None => true,
            };
            if pass {
                chosen = Some(i);
                break;
            }
        }
        let i = chosen.ok_or_else(|| CelError::Other("no choice branch matched".into()))?;
        let b = branches[i].clone();
        run_actions(inst, m, source, &b.action, event_value, etype, buf, rec)?;
        if m.get(b.target).kind == StateKind::Choice {
            cur = b.target;
            continue;
        }
        return Ok(b.target);
    }
}

fn external_transition(
    inst: &mut Instance,
    m: &Machine,
    source: NodeId,
    target: NodeId,
    action: &[Action],
    event_value: &Value,
    etype: Option<&str>,
    buf: &mut StepBuf,
    rec: &mut StepRecord,
) -> Result<(), CelError> {
    let lca = lca_external(m, source, target);
    let anchor = child_below(m, lca, source);
    // exit: active states strictly below lca, on the source side
    let mut to_exit: Vec<NodeId> = inst
        .active
        .iter()
        .copied()
        .filter(|&x| is_strictly_below(m, lca, x) && is_ancestor_or_equal(m, anchor, x))
        .collect();
    to_exit.sort_by(|a, b| m.get(*b).depth.cmp(&m.get(*a).depth));
    // record history BEFORE descendants are removed (deepest composites first)
    for &x in &to_exit {
        if m.get(x).has_history() {
            record_history(inst, m, x);
        }
    }
    for x in to_exit {
        exit_state(inst, m, x, buf, rec);
    }
    if !action.is_empty() {
        run_actions(inst, m, source, action, event_value, etype, buf, rec)?;
    }
    let path = entry_path_below(m, lca, target);
    for &s in &path {
        enter(inst, m, s, 0, event_value, etype, buf, rec);
    }
    if let Some(&tgt) = path.last() {
        descend(inst, m, tgt, 0, event_value, etype, buf, rec);
    }
    Ok(())
}

fn local_transition(
    inst: &mut Instance,
    m: &Machine,
    source: NodeId,
    target: NodeId,
    event_value: &Value,
    etype: Option<&str>,
    buf: &mut StepBuf,
    rec: &mut StepRecord,
) -> Result<(), CelError> {
    let mut to_exit: Vec<NodeId> = inst
        .active
        .iter()
        .copied()
        .filter(|&x| is_strictly_below(m, source, x))
        .collect();
    to_exit.sort_by(|a, b| m.get(*b).depth.cmp(&m.get(*a).depth));
    for &x in &to_exit {
        if m.get(x).has_history() {
            record_history(inst, m, x);
        }
    }
    for x in to_exit {
        exit_state(inst, m, x, buf, rec);
    }
    let path = entry_path_below(m, source, target);
    for &s in &path {
        enter(inst, m, s, 0, event_value, etype, buf, rec);
    }
    if let Some(&tgt) = path.last() {
        descend(inst, m, tgt, 0, event_value, etype, buf, rec);
    }
    Ok(())
}

/// Deepest proper ancestor common to source and target.
fn lca_external(m: &Machine, source: NodeId, target: NodeId) -> NodeId {
    let sa = proper_ancestors(m, source);
    let ta: HashSet<NodeId> = proper_ancestors(m, target).into_iter().collect();
    for a in sa {
        if ta.contains(&a) {
            return a;
        }
    }
    m.top
}

/// The child of `anc` that is an ancestor-or-equal of `n`.
fn child_below(m: &Machine, anc: NodeId, n: NodeId) -> NodeId {
    let mut cur = n;
    while let Some(p) = m.get(cur).parent {
        if p == anc {
            return cur;
        }
        cur = p;
    }
    n
}

fn entry_path_below(m: &Machine, lca: NodeId, target: NodeId) -> Vec<NodeId> {
    let chain = ancestors_inclusive(m, target); // [target, ..., top]
    let mut path: Vec<NodeId> = chain.into_iter().rev().collect(); // [top, ..., target]
    while path.first().map(|&x| x != lca).unwrap_or(false) {
        path.remove(0);
    }
    if path.first() == Some(&lca) {
        path.remove(0);
    }
    path
}

// ===================== entry / exit / descend =====================

/// Activate, initialize esvs, run entry actions, arm timers.
fn enter(
    inst: &mut Instance,
    m: &Machine,
    n: NodeId,
    clock: u64,
    event_value: &Value,
    etype: Option<&str>,
    buf: &mut StepBuf,
    rec: &mut StepRecord,
) {
    inst.active.insert(n);
    let sd = m.get(n);
    // A submachine root seeds its `external` esvs from `with:` (CEL over the parent
    // scope) before its esvs initialize (SPEC §5.6.1).
    if sd.is_sm_boundary && !sd.sm_with.is_empty() {
        if let Some(parent) = sd.parent {
            let env = build_env(inst, m, parent, event_value);
            for (name, expr) in &sd.sm_with {
                if let Ok(v) = crate::cel::eval(expr, &env) {
                    inst.external_source.insert(name.clone(), v);
                }
            }
        }
    }
    for (name, decl) in sd.esvs.clone() {
        let val = if decl.external {
            inst.external_source.get(&name).cloned().unwrap_or(Value::Null)
        } else {
            decl.init.clone().unwrap_or(Value::Null)
        };
        inst.esvs.insert(esv_key(sd, &name), val);
    }
    let entry = sd.entry.clone();
    let _ = run_actions(inst, m, n, &entry, event_value, etype, buf, rec);
    let afters = sd.after.clone();
    for (i, a) in afters.iter().enumerate() {
        inst.timers.push(ArmedTimer {
            state: n,
            after_idx: i,
            due: clock.saturating_add(a.duration_ms),
        });
    }
    rec.entered.push(sd.id.clone());
}

/// Take initial transitions / restore history into substates (state `n` already entered).
fn descend(
    inst: &mut Instance,
    m: &Machine,
    n: NodeId,
    clock: u64,
    event_value: &Value,
    etype: Option<&str>,
    buf: &mut StepBuf,
    rec: &mut StepRecord,
) {
    let sd = m.get(n);
    match sd.kind {
        StateKind::Composite => {
            let has_hist = sd.has_history();
            let hist = inst.history.get(&n).cloned();
            if has_hist && hist.is_some() {
                restore_history(inst, m, n, clock, event_value, etype, hist.unwrap(), buf, rec);
            } else if let Some(init) = sd.initial.clone() {
                for a in &init.action {
                    let _ = run_actions(inst, m, n, std::slice::from_ref(a), event_value, etype, buf, rec);
                }
                enter(inst, m, init.target, clock, event_value, etype, buf, rec);
                descend(inst, m, init.target, clock, event_value, etype, buf, rec);
            }
        }
        StateKind::Orthogonal => {
            let has_hist = sd.has_history();
            let hist = inst.history.get(&n).cloned();
            if has_hist && hist.is_some() {
                restore_history(inst, m, n, clock, event_value, etype, hist.unwrap(), buf, rec);
            } else {
                let regions = sd.regions.clone();
                for r in &regions {
                    for a in &r.initial.action {
                        let _ = run_actions(inst, m, n, std::slice::from_ref(a), event_value, etype, buf, rec);
                    }
                    enter(inst, m, r.initial.target, clock, event_value, etype, buf, rec);
                    descend(inst, m, r.initial.target, clock, event_value, etype, buf, rec);
                }
            }
        }
        _ => {}
    }
}

fn restore_history(
    inst: &mut Instance,
    m: &Machine,
    state: NodeId,
    clock: u64,
    event_value: &Value,
    etype: Option<&str>,
    hist: HistRecord,
    buf: &mut StepBuf,
    rec: &mut StepRecord,
) {
    match hist {
        HistRecord::Shallow(direct) => {
            for child in direct {
                enter(inst, m, child, clock, event_value, etype, buf, rec);
                descend(inst, m, child, clock, event_value, etype, buf, rec);
            }
        }
        HistRecord::Deep(leaves) => {
            for leaf in leaves {
                let path = entry_path_below(m, state, leaf);
                for &s in &path {
                    enter(inst, m, s, clock, event_value, etype, buf, rec);
                }
            }
        }
    }
}

fn exit_state(
    inst: &mut Instance,
    m: &Machine,
    n: NodeId,
    buf: &mut StepBuf,
    rec: &mut StepRecord,
) {
    let sd = m.get(n);
    inst.done_emitted.remove(&n);
    let exit = sd.exit.clone();
    let _ = run_actions(inst, m, n, &exit, &Value::Null, None, buf, rec);
    for (name, _) in sd.esvs.clone() {
        inst.esvs.remove(&esv_key(sd, &name));
    }
    inst.timers.retain(|t| t.state != n);
    inst.active.remove(&n);
    rec.exited.push(sd.id.clone());
}

fn exit_up_to(
    inst: &mut Instance,
    m: &Machine,
    leaf: NodeId,
    lca: Option<NodeId>,
    buf: &mut StepBuf,
    rec: &mut StepRecord,
) {
    let mut cur = Some(leaf);
    while let Some(c) = cur {
        if lca == Some(c) {
            break;
        }
        exit_state(inst, m, c, buf, rec);
        cur = m.get(c).parent;
    }
}

fn record_history(inst: &mut Instance, m: &Machine, state: NodeId) {
    let sd = m.get(state);
    match sd.history {
        HistoryKind::Shallow => {
            let direct: Vec<NodeId> = sd
                .children
                .iter()
                .copied()
                .filter(|&c| inst.active.contains(&c))
                .collect();
            inst.history.insert(state, HistRecord::Shallow(direct));
        }
        HistoryKind::Deep => {
            let leaves: Vec<NodeId> = inst
                .active
                .iter()
                .copied()
                .filter(|&n| is_leaf(m, n) && is_strictly_below(m, state, n))
                .collect();
            inst.history.insert(state, HistRecord::Deep(leaves));
        }
        HistoryKind::None => {}
    }
}

// ===================== actions =====================

fn run_actions(
    inst: &mut Instance,
    m: &Machine,
    scope: NodeId,
    actions: &[Action],
    event_value: &Value,
    etype: Option<&str>,
    buf: &mut StepBuf,
    rec: &mut StepRecord,
) -> Result<(), CelError> {
    for a in actions {
        run_one(inst, m, scope, a, event_value, etype, buf, rec)?;
    }
    Ok(())
}

fn run_one(
    inst: &mut Instance,
    m: &Machine,
    scope: NodeId,
    action: &Action,
    event_value: &Value,
    etype: Option<&str>,
    buf: &mut StepBuf,
    _rec: &mut StepRecord,
) -> Result<(), CelError> {
    let env = build_env(inst, m, scope, event_value);
    match action {
        Action::Assign(pairs) => {
            for (name, expr) in pairs {
                let val = cel::eval(expr, &env)?;
                let decl_state = nearest_declaring(inst, m, scope, name)
                    .ok_or_else(|| CelError::Other(format!("assign to undeclared '{name}'")))?;
                let sd = m.get(decl_state);
                let decl = sd
                    .esvs
                    .iter()
                    .find(|(n, _)| n == name)
                    .map(|(_, d)| d.clone())
                    .unwrap();
                if decl.external {
                    return Err(CelError::Other(format!("cannot assign to external esv '{name}'")));
                }
                let coerced = val
                    .coerce_to(&decl.ty)
                    .ok_or_else(|| CelError::Type(format!("'{name}' expects {}", decl.ty)))?;
                inst.esvs.insert(esv_key(sd, name), coerced);
            }
            Ok(())
        }
        Action::Publish { event, to, payload } => {
            let pmap = eval_payload(payload, &env)?;
            buf.published.push(event.clone());
            if let Some(to_expr) = to {
                for t in eval_targets(to_expr, &env)? {
                    buf.deliveries.push((
                        t,
                        QueuedEvent {
                            etype: event.clone(),
                            payload: Value::Map(pmap.clone()),
                            origin: Some(inst.id.clone()),
                        },
                    ));
                }
            } else {
                buf.undirected.push((inst.id.clone(), event.clone(), Value::Map(pmap)));
            }
            Ok(())
        }
        Action::Refresh { only } => {
            if etype != Some("env") {
                return Err(CelError::Other("refresh only valid while handling env".into()));
            }
            if let Some(changed) = changed_of(event_value) {
                let names: Vec<String> = match only {
                    Some(lst) => lst.clone(),
                    None => changed.keys().cloned().collect(),
                };
                for name in names {
                    if let Some(v) = changed.get(&name) {
                        if let Some(st) = nearest_declaring(inst, m, scope, &name) {
                            inst.esvs.insert(esv_key(m.get(st), &name), v.clone());
                        }
                    }
                }
            }
            Ok(())
        }
        Action::Spawn { def, payload, result } => {
            let pmap = eval_payload(payload, &env)?;
            buf.spawns.push(SpawnReq {
                parent: inst.id.clone(),
                scope,
                def_id: def.clone(),
                payload: pmap,
                result_var: result.clone(),
            });
            buf.spawned.push(def.clone());
            buf.spawned_def.push(def.clone());
            Ok(())
        }
        Action::Stop => {
            buf.stop = true;
            // enqueue a stop marker so post_step terminates
            inst.queue.push_back(QItem::Event(QueuedEvent {
                etype: "__stop__".into(),
                payload: Value::Null,
                origin: Some(inst.id.clone()),
            }));
            Ok(())
        }
    }
}

fn eval_payload(pairs: &[(String, String)], env: &Env) -> Result<BTreeMap<String, Value>, CelError> {
    let mut out = BTreeMap::new();
    for (k, expr) in pairs {
        out.insert(k.clone(), cel::eval(expr, env)?);
    }
    Ok(out)
}

fn eval_targets(expr: &str, env: &Env) -> Result<Vec<InstanceId>, CelError> {
    match cel::eval(expr, env)? {
        Value::Str(s) => Ok(vec![s]),
        Value::List(l) => Ok(l
            .into_iter()
            .filter_map(|x| x.as_str_value().map(|s| s.to_string()))
            .collect()),
        Value::Null => Ok(vec![]),
        other => Err(CelError::Type(format!("publish.to must be string/list, got {}", other.type_name()))),
    }
}

// ===================== defer =====================

fn effective_defer(inst: &Instance, m: &Machine) -> HashSet<String> {
    let mut out = HashSet::new();
    for &n in &inst.active {
        for d in &m.get(n).defer {
            out.insert(d.clone());
        }
    }
    out
}

fn replay_deferred(inst: &mut Instance, m: &Machine) {
    let defer_set = effective_defer(inst, m);
    let (mut move_front, mut remaining) = (Vec::new(), Vec::new());
    for item in inst.deferred.drain(..) {
        let still = match &item {
            QItem::Event(e) => defer_set.contains(&e.etype),
            QItem::Timer { .. } => false,
        };
        if still {
            remaining.push(item);
        } else {
            move_front.push(item);
        }
    }
    inst.deferred = remaining;
    let mut new_q = VecDeque::new();
    for item in move_front {
        new_q.push_back(item);
    }
    while let Some(x) = inst.queue.pop_front() {
        new_q.push_back(x);
    }
    inst.queue = new_q;
}

// ===================== completion (orthogonal + submachine) =====================

/// Active composite/orthogonal states that have reached completion: an orthogonal
/// whose regions are all final, or a composite whose active leaf is final (incl. an
/// inlined submachine root, SPEC §5.6.1).
fn complete_states(inst: &Instance, m: &Machine) -> Vec<NodeId> {
    let leaves = active_leaves(inst, m);
    let mut out = Vec::new();
    for &s in &inst.active {
        let sd = m.get(s);
        match sd.kind {
            StateKind::Orthogonal => {
                if regions_all_final(inst, m, s) {
                    out.push(s);
                }
            }
            StateKind::Composite => {
                if leaves.iter().any(|&l| {
                    is_ancestor_or_equal(m, s, l) && m.get(l).kind == StateKind::Final
                }) {
                    out.push(s);
                }
            }
            _ => {}
        }
    }
    out
}

/// The active leaf name within a composite (for the `done` payload).
fn composite_leaf_name(inst: &Instance, m: &Machine, composite: NodeId) -> String {
    for l in active_leaves(inst, m) {
        if is_ancestor_or_equal(m, composite, l) && m.get(l).kind == StateKind::Final {
            return m.get(l).id.clone();
        }
    }
    String::new()
}

fn regions_all_final(inst: &Instance, m: &Machine, ortho: NodeId) -> bool {
    let regions = m.get(ortho).regions.clone();
    if regions.is_empty() {
        return false;
    }
    for r in &regions {
        let any_final = r.states.iter().any(|&s| subtree_has_active_final(inst, m, s));
        if !any_final {
            return false;
        }
    }
    true
}

fn subtree_has_active_final(inst: &Instance, m: &Machine, n: NodeId) -> bool {
    if inst.active.contains(&n) && m.get(n).kind == StateKind::Final {
        return true;
    }
    for &c in &m.get(n).children {
        if subtree_has_active_final(inst, m, c) {
            return true;
        }
    }
    false
}

// ===================== env helpers =====================

fn build_env(inst: &Instance, m: &Machine, scope: NodeId, event_value: &Value) -> Env {
    let mut env = Env::new();
    for (k, v) in resolve_visible(inst, m, scope) {
        env = env.with(k, v);
    }
    env = env.with("id", Value::Str(inst.id.clone()));
    env = env.with("parent", inst.parent.clone().map(Value::Str).unwrap_or(Value::Null));
    env = env.with("event", event_value.clone());
    env
}

fn event_binding(e: &QueuedEvent) -> Value {
    let mut m = BTreeMap::new();
    m.insert("type".to_string(), Value::Str(e.etype.clone()));
    m.insert("payload".to_string(), e.payload.clone());
    Value::Map(m)
}

/// event.payload.changed as a Map (for env events), else None.
fn changed_of(event_value: &Value) -> Option<BTreeMap<String, Value>> {
    let payload = field(event_value, "payload")?;
    let changed = field(&payload, "changed")?;
    if let Value::Map(m) = changed {
        Some(m)
    } else {
        None
    }
}

fn field(v: &Value, name: &str) -> Option<Value> {
    if let Value::Map(m) = v {
        m.get(name).cloned()
    } else {
        None
    }
}

fn error_payload(fault: &CelError) -> BTreeMap<String, Value> {
    let mut m = BTreeMap::new();
    m.insert("message".to_string(), Value::Str(fault.to_string()));
    m
}

// ===================== validation =====================

fn validate_event_payload(m: &Machine, etype: &str, payload: &Value) -> Result<(), String> {
    // reserved lifecycle events are not declared and skip payload typing
    if matches!(etype, "env" | "error" | "done" | "initial" | "entry" | "exit") {
        return Ok(());
    }
    let decl = match m.events.get(etype) {
        Some(d) => d,
        None => return Err(format!("undeclared event '{etype}'")),
    };
    let pm = match payload {
        Value::Map(m) => m.clone(),
        Value::Null => BTreeMap::new(),
        _ => return Err("payload must be a map".to_string()),
    };
    for (name, field) in &decl.payload {
        match pm.get(name) {
            None => {
                if field.required {
                    return Err(format!("missing required field '{name}'"));
                }
            }
            Some(v) => {
                if !v.matches_type(&field.ty) {
                    return Err(format!("field '{name}' expects {}", field.ty));
                }
            }
        }
    }
    for name in pm.keys() {
        if !decl.payload.iter().any(|(n, _)| n == name) {
            return Err(format!("unexpected field '{name}'"));
        }
    }
    Ok(())
}

// ===================== views helpers =====================

fn config_of(inst: &Instance, m: &Machine) -> Vec<String> {
    let mut v: Vec<String> = active_leaves(inst, m).into_iter().map(|n| m.get(n).id.clone()).collect();
    v.sort();
    v
}

fn reported_esvs(inst: &Instance, m: &Machine) -> BTreeMap<String, Value> {
    let mut leaves = active_leaves(inst, m);
    leaves.sort_by_key(|&n| std::cmp::Reverse(m.get(n).depth));
    let mut out = BTreeMap::new();
    for leaf in leaves {
        for (k, v) in resolve_visible(inst, m, leaf) {
            out.entry(k).or_insert(v);
        }
    }
    out
}

/// Reserved lifecycle event names never reported as enabled (SPEC §14).
const RESERVED_LIFECYCLE_EVENTS: &[&str] = &["initial", "entry", "exit", "env", "error", "done"];

/// `enabled_events(instance)` — the sorted declared event types the current active
/// configuration can handle (SPEC §14). An event type is enabled iff some active
/// state declares an `on_events` handler for it, considering each active leaf and its
/// ancestor chain and all orthogonal regions. Structural and guard-agnostic;
/// reserved lifecycle events are excluded.
fn enabled_events(inst: &Instance, m: &Machine) -> Vec<String> {
    let mut set = BTreeSet::new();
    for leaf in active_leaves(inst, m) {
        for s in ancestors_inclusive(m, leaf) {
            for ev in m.get(s).on_events.keys() {
                if !RESERVED_LIFECYCLE_EVENTS.contains(&ev.as_str()) {
                    set.insert(ev.clone());
                }
            }
        }
    }
    set.into_iter().collect()
}

// ===================== views helpers =====================

//! The resolved machine: a flat state table (indexed by [`NodeId`]) with all
//! `transition_to` references resolved to [`NodeId`]s, event scopes parsed, and
//! actions/initials/choices expanded. Built once from [`crate::model::RawMachine`].
//!
//! Building is two-phase: first every state node is registered (completing the
//! name table), then a second walk resolves all targets — which may be forward
//! references to states defined later in the YAML.

use crate::model::{self, Action, RawMachine, StateNode};
use crate::value::Value;
use std::collections::{BTreeMap, HashMap};

pub type NodeId = usize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    Internal,
    Local,
    Global,
}

impl Scope {
    pub fn parse(s: Option<&str>) -> Scope {
        match s {
            Some("local") => Scope::Local,
            Some("global") => Scope::Global,
            _ => Scope::Internal,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PayloadField {
    pub ty: String,
    pub required: bool,
    pub default: Option<Value>,
}

#[derive(Debug, Clone)]
pub struct EventDecl {
    pub scope: Scope,
    pub payload: Vec<(String, PayloadField)>,
}

#[derive(Debug, Clone)]
pub struct EsvDecl {
    pub ty: String,
    pub init: Option<Value>,
    pub external: bool,
}

#[derive(Debug, Clone)]
pub struct TransitionDef {
    pub target: Option<NodeId>,
    pub guard: Option<String>,
    pub action: Vec<Action>,
    pub internal: bool,
    pub local: bool,
    pub raw_target: String,
}

#[derive(Debug, Clone)]
pub struct InitialDef {
    pub target: NodeId,
    pub guard: Option<String>,
    pub action: Vec<Action>,
}

#[derive(Debug, Clone)]
pub struct ChoiceBranchDef {
    pub target: NodeId,
    pub guard: Option<String>,
    pub action: Vec<Action>,
}

#[derive(Debug, Clone)]
pub struct AfterDef {
    pub duration_ms: u64,
    pub target: Option<NodeId>,
    pub guard: Option<String>,
    pub action: Vec<Action>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateKind {
    Simple,
    Composite,
    Orthogonal,
    Final,
    Choice,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HistoryKind {
    None,
    Shallow,
    Deep,
}

#[derive(Debug, Clone)]
pub struct RegionDef {
    pub initial: InitialDef,
    pub states: Vec<NodeId>,
}

#[derive(Debug, Clone)]
pub struct StateDef {
    pub id: String,
    pub path: String,
    pub parent: Option<NodeId>,
    pub depth: usize,
    pub kind: StateKind,
    pub esvs: Vec<(String, EsvDecl)>,
    pub entry: Vec<Action>,
    pub exit: Vec<Action>,
    pub initial: Option<InitialDef>,
    pub children: Vec<NodeId>,
    pub regions: Vec<RegionDef>,
    pub on_events: BTreeMap<String, Vec<TransitionDef>>,
    pub after: Vec<AfterDef>,
    pub defer: Vec<String>,
    pub history: HistoryKind,
    pub choice: Option<Vec<ChoiceBranchDef>>,
    pub region_of: Option<(NodeId, usize)>,
    /// Inlined submachine root (esv-scope boundary, SPEC §5.6.1).
    pub is_sm_boundary: bool,
    pub sm_with: Vec<(String, String)>,
    /// Opaque state annotations (SPEC §4.5); informative only.
    pub meta: Value,
}

impl StateDef {
    pub fn is_orthogonal(&self) -> bool {
        matches!(self.kind, StateKind::Orthogonal)
    }
    pub fn has_history(&self) -> bool {
        !matches!(self.history, HistoryKind::None)
    }
}

#[derive(Debug, Clone)]
pub struct MigrationDef {
    pub from: i64,
    pub to: i64,
    pub when: Option<String>,
    pub state_map: BTreeMap<String, String>,
    pub esvs: Vec<Action>,
}

#[derive(Debug, Clone)]
pub struct Machine {
    pub id: String,
    pub version: i64,
    pub format: i64,
    pub contracts: Vec<String>,
    pub subscribe: Vec<String>,
    pub events: BTreeMap<String, EventDecl>,
    pub migrations: Vec<MigrationDef>,
    pub states: Vec<StateDef>,
    pub by_name: HashMap<String, NodeId>,
    pub by_path: HashMap<String, NodeId>,
    pub top: NodeId,
    /// Opaque machine-level annotations (SPEC §4.1); informative only.
    pub meta: Value,
}

impl Machine {
    pub fn get(&self, n: NodeId) -> &StateDef {
        &self.states[n]
    }

    /// Resolve a reference: dotted walks from top; bare looks up the unique name.
    pub fn resolve(&self, raw: &str) -> Option<NodeId> {
        resolve_ref(&self.by_name, raw)
    }
}

/// Parse a duration like "30s", "5m", "10ms", "1h" into milliseconds.
pub fn parse_duration(s: &str) -> Result<u64, String> {
    let err = || format!("invalid duration '{s}'");
    let split = s.find(|c: char| !c.is_ascii_digit()).ok_or_else(err)?;
    let (num, unit) = s.split_at(split);
    let n: u64 = num.parse().map_err(|_| err())?;
    match unit {
        "ms" => Ok(n),
        "s" => n.checked_mul(1000).ok_or_else(err),
        "m" => n.checked_mul(60_000).ok_or_else(err),
        "h" => n.checked_mul(3_600_000).ok_or_else(err),
        _ => Err(err()),
    }
}

fn resolve_ref(by_name: &HashMap<String, NodeId>, raw: &str) -> Option<NodeId> {
    if raw.is_empty() {
        return None;
    }
    if raw.contains('.') {
        let mut cur: Option<NodeId> = None;
        for seg in raw.split('.') {
            if seg == "top" {
                cur = Some(0);
                continue;
            }
            cur = by_name.get(seg).copied();
            cur?;
        }
        cur
    } else {
        by_name.get(raw).copied()
    }
}

fn infer_kind(node: &StateNode) -> StateKind {
    match node.ty.as_deref() {
        Some("composite") => StateKind::Composite,
        Some("orthogonal") => StateKind::Orthogonal,
        Some("final") => StateKind::Final,
        Some("simple") => StateKind::Simple,
        _ => {
            if node.choice.is_some() {
                StateKind::Choice
            } else if node.regions.is_some() {
                StateKind::Orthogonal
            } else if node.states.is_some() {
                StateKind::Composite
            } else {
                StateKind::Simple
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Phase 1: register all nodes (kind/esvs/entry/exit/defer/history + structure).

#[allow(clippy::too_many_arguments)]
fn register(
    states: &mut Vec<StateDef>,
    by_name: &mut HashMap<String, NodeId>,
    by_path: &mut HashMap<String, NodeId>,
    errors: &mut Vec<String>,
    id: String,
    path: String,
    parent: Option<NodeId>,
    node: &StateNode,
) -> NodeId {
    let depth = parent.map(|p| states[p].depth + 1).unwrap_or(0);
    let kind = infer_kind(node);
    let history = match node.history.as_deref() {
        Some("shallow") => HistoryKind::Shallow,
        Some("deep") => HistoryKind::Deep,
        _ => HistoryKind::None,
    };

    let esvs = node
        .esvs
        .as_ref()
        .map(|m| {
            m.iter()
                .map(|(name, e)| {
                    let init = e.init.as_ref().and_then(|raw| match model::esv_init_value(&e.ty, raw) {
                        Ok(v) => Some(v),
                        Err(msg) => {
                            errors.push(format!("esv '{path}.{name}': {msg}"));
                            None
                        }
                    });
                    (
                        name.clone(),
                        EsvDecl {
                            ty: e.ty.clone(),
                            init,
                            external: e.external.unwrap_or(false),
                        },
                    )
                })
                .collect()
        })
        .unwrap_or_default();

    let entry = parse_actions_or_err(errors, &path, "entry", node.entry.as_ref());
    let exit = parse_actions_or_err(errors, &path, "exit", node.exit.as_ref());

    let idx = states.len();
    states.push(StateDef {
        id: id.clone(),
        path: path.clone(),
        parent,
        depth,
        kind,
        esvs,
        entry,
        exit,
        initial: None,
        children: Vec::new(),
        regions: Vec::new(),
        on_events: BTreeMap::new(),
        after: Vec::new(),
        defer: node.defer.clone().unwrap_or_default(),
        history,
        choice: None,
        region_of: None,
        is_sm_boundary: node.is_sm_boundary,
        sm_with: node.sm_with.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
        meta: node
            .meta
            .as_ref()
            .map(Value::from_yaml)
            .unwrap_or(Value::Map(BTreeMap::new())),
    });

    if by_name.contains_key(&id) {
        errors.push(format!("duplicate state name '{id}'"));
    }
    by_name.insert(id, idx);
    by_path.insert(path.clone(), idx);

    let mut children = Vec::new();
    let mut regions: Vec<RegionDef> = Vec::new();
    match kind {
        StateKind::Composite => {
            if node.initial.is_none() {
                errors.push(format!("composite '{path}' requires an initial transition"));
            }
            if let Some(map) = &node.states {
                for (cname, cnode) in map {
                    let cpath = format!("{path}.{cname}");
                    let cid = register(states, by_name, by_path, errors, cname.clone(), cpath, Some(idx), cnode);
                    children.push(cid);
                }
            }
        }
        StateKind::Orthogonal => {
            if let Some(regs) = &node.regions {
                for (ri, region) in regs.iter().enumerate() {
                    let mut rstates = Vec::new();
                    for (cname, cnode) in &region.states {
                        let cpath = format!("{path}.{cname}");
                        let cid = register(states, by_name, by_path, errors, cname.clone(), cpath, Some(idx), cnode);
                        states[cid].region_of = Some((idx, ri));
                        rstates.push(cid);
                    }
                    regions.push(RegionDef {
                        initial: InitialDef { target: idx, guard: None, action: Vec::new() },
                        states: rstates,
                    });
                }
            } else {
                errors.push(format!("orthogonal '{path}' requires regions"));
            }
        }
        _ => {}
    }
    states[idx].children = children;
    states[idx].regions = regions;
    idx
}

// ---------------------------------------------------------------------------
// Phase 2: resolve transitions/initials/afters/choices now that names are complete.

fn fill(
    states: &mut Vec<StateDef>,
    by_name: &HashMap<String, NodeId>,
    errors: &mut Vec<String>,
    path: &str,
    node: &StateNode,
) {
    // find this node's id
    let idx = by_name[path.rsplit('.').next().unwrap_or("top")];
    let kind = states[idx].kind;

    // composite initial
    if kind == StateKind::Composite {
        if let Some(init) = &node.initial {
            let action = parse_actions_or_err(errors, path, "initial", init.action.as_ref());
            match resolve_ref(by_name, &init.transition_to) {
                Some(t) => states[idx].initial = Some(InitialDef {
                    target: t,
                    guard: init.guard.clone(),
                    action,
                }),
                None => errors.push(format!(
                    "initial of '{path}' references unknown state '{}'",
                    init.transition_to
                )),
            }
        }
    }
    // orthogonal region initials
    if kind == StateKind::Orthogonal {
        if let Some(regs) = &node.regions {
            for (ri, region) in regs.iter().enumerate() {
                let action = parse_actions_or_err(errors, path, "initial", region.initial.action.as_ref());
                match resolve_ref(by_name, &region.initial.transition_to) {
                    Some(t) => states[idx].regions[ri].initial = InitialDef {
                        target: t,
                        guard: region.initial.guard.clone(),
                        action,
                    },
                    None => errors.push(format!(
                        "region initial of '{path}' references unknown state '{}'",
                        region.initial.transition_to
                    )),
                }
            }
        }
    }

    // on_events
    if let Some(oe) = &node.on_events {
        let mut map = BTreeMap::new();
        for (ev, tol) in oe {
            let list = match tol {
                model::TransitionOrList::One(t) => vec![t.clone()],
                model::TransitionOrList::Many(v) => v.clone(),
            };
            let defs = list
                .iter()
                .map(|t| {
                    let raw_target = t.transition_to.clone().unwrap_or_default();
                    let target = if raw_target.is_empty() {
                        None
                    } else {
                        match resolve_ref(by_name, &raw_target) {
                            Some(id) => Some(id),
                            None => {
                                errors.push(format!(
                                    "transition '{ev}' in '{path}' references unknown state '{raw_target}'"
                                ));
                                None
                            }
                        }
                    };
                    TransitionDef {
                        target,
                        guard: t.guard.clone(),
                        action: parse_actions_or_err(errors, path, "transition", t.action.as_ref()),
                        internal: t.internal.unwrap_or(false),
                        local: t.local.unwrap_or(false),
                        raw_target,
                    }
                })
                .collect();
            map.insert(ev.clone(), defs);
        }
        states[idx].on_events = map;
    }

    // after
    if let Some(after) = &node.after {
        states[idx].after = after
            .iter()
            .map(|a| {
                let duration_ms = match parse_duration(&a.duration) {
                    Ok(d) => d,
                    Err(e) => {
                        errors.push(format!("after in '{path}': {e}"));
                        0
                    }
                };
                let target = a.transition_to.as_deref().and_then(|r| {
                    resolve_ref(by_name, r).or_else(|| {
                        errors.push(format!(
                            "after in '{path}' references unknown state '{r}'"
                        ));
                        None
                    })
                });
                AfterDef {
                    duration_ms,
                    target,
                    guard: a.guard.clone(),
                    action: parse_actions_or_err(errors, path, "after", a.action.as_ref()),
                }
            })
            .collect();
    }

    // choice
    if let Some(choice) = &node.choice {
        states[idx].choice = Some(
            choice
                .iter()
                .map(|br| {
                    let target = match resolve_ref(by_name, &br.transition_to) {
                        Some(id) => id,
                        None => {
                            errors.push(format!(
                                "choice in '{path}' references unknown state '{}'",
                                br.transition_to
                            ));
                            idx
                        }
                    };
                    ChoiceBranchDef {
                        target,
                        guard: br.guard.clone(),
                        action: parse_actions_or_err(errors, path, "choice", br.action.as_ref()),
                    }
                })
                .collect(),
        );
    }

    // recurse into children
    match kind {
        StateKind::Composite => {
            if let Some(map) = &node.states {
                for (cname, cnode) in map {
                    fill(states, by_name, errors, &format!("{path}.{cname}"), cnode);
                }
            }
        }
        StateKind::Orthogonal => {
            if let Some(regs) = &node.regions {
                for region in regs {
                    for (cname, cnode) in &region.states {
                        fill(states, by_name, errors, &format!("{path}.{cname}"), cnode);
                    }
                }
            }
        }
        _ => {}
    }
}

fn parse_actions_or_err(
    errors: &mut Vec<String>,
    path: &str,
    what: &str,
    raw: Option<&serde_yaml::Value>,
) -> Vec<Action> {
    match model::parse_actions(raw) {
        Ok(a) => a,
        Err(e) => {
            errors.push(format!("{what} in '{path}': {e}"));
            Vec::new()
        }
    }
}

pub fn build(raw: &RawMachine) -> Result<Machine, Vec<String>> {
    let mut states: Vec<StateDef> = Vec::new();
    let mut by_name: HashMap<String, NodeId> = HashMap::new();
    let mut by_path: HashMap<String, NodeId> = HashMap::new();
    let mut errors: Vec<String> = Vec::new();

    register(
        &mut states,
        &mut by_name,
        &mut by_path,
        &mut errors,
        "top".to_string(),
        "top".to_string(),
        None,
        &raw.top,
    );

    fill(&mut states, &by_name, &mut errors, "top", &raw.top);

    if !errors.is_empty() {
        return Err(errors);
    }

    let mut events = BTreeMap::new();
    if let Some(ev) = &raw.events {
        for (k, v) in ev {
            let scope = Scope::parse(v.scope.as_deref());
            let payload = v
                .payload
                .as_ref()
                .map(|m| {
                    m.iter()
                        .map(|(name, pf)| {
                            (
                                name.clone(),
                                PayloadField {
                                    ty: pf.ty.clone(),
                                    required: pf.required.unwrap_or(false),
                                    default: pf.default.as_ref().map(Value::from_yaml),
                                },
                            )
                        })
                        .collect()
                })
                .unwrap_or_default();
            events.insert(k.clone(), EventDecl { scope, payload });
        }
    }

    let migrations = raw
        .migrations
        .as_ref()
        .map(|ms| {
            ms.iter()
                .map(|m| MigrationDef {
                    from: m.from,
                    to: m.to,
                    when: m.when.clone(),
                    state_map: m.state_map.clone().unwrap_or_default(),
                    esvs: model::parse_actions(m.esvs.as_ref()).unwrap_or_default(),
                })
                .collect()
        })
        .unwrap_or_default();

    Ok(Machine {
        id: raw.id.clone(),
        version: raw.version.unwrap_or(1),
        format: raw.format.unwrap_or(1),
        contracts: raw.contracts.clone(),
        subscribe: raw.subscribe.clone(),
        events,
        migrations,
        states,
        by_name,
        by_path,
        top: 0,
        meta: raw
            .meta
            .as_ref()
            .map(Value::from_yaml)
            .unwrap_or(Value::Map(BTreeMap::new())),
    })
}

/// Build a set of definitions, inlining `submachine:` references (SPEC §5.6.1)
/// using a registry of all docs (def id -> raw machine). Returns one resolved
/// [`Machine`] per input doc, in order, or the collected errors.
pub fn resolve_definitions(
    docs: &[RawMachine],
) -> Result<Vec<Machine>, Vec<crate::loader::LoadError>> {
    use crate::loader::LoadError;
    use std::collections::{HashMap, HashSet};

    let registry: HashMap<String, crate::model::StateNode> = docs
        .iter()
        .map(|d| (d.id.clone(), d.top.clone()))
        .collect();
    let mut out = Vec::new();
    let mut errs: Vec<LoadError> = Vec::new();
    for d in docs {
        let inlined_top = match crate::model::inline_submachines(&d.top, &registry, &HashSet::new()) {
            Ok(t) => t,
            Err(e) => {
                errs.extend(e);
                continue;
            }
        };
        let mut inlined = d.clone();
        inlined.top = inlined_top;
        match build(&inlined) {
            Ok(m) => out.push(m),
            Err(es) => {
                for e in es {
                    errs.push(LoadError {
                        path: format!("machine '{}'", d.id),
                        message: e,
                    });
                }
            }
        }
    }
    if !errs.is_empty() {
        return Err(errs);
    }
    Ok(out)
}

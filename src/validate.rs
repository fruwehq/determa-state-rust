//! Semantic validation (SPEC §5.5.1 choices, §7 contracts). Structural validation
//! (unknown fields, required fields) is enforced by serde's `deny_unknown_fields`
//! during loading; reference resolution happens in [`crate::machine::build`]. This
//! module adds the checks the JSON schema cannot express.

use crate::loader::LoadError;
use crate::machine::{Machine, NodeId, StateDef, StateKind};
use crate::model::{Action, RawMachine};
use serde::Deserialize;
use std::collections::{BTreeMap, HashMap, HashSet};

const RESERVED_EVENTS: &[&str] = &["initial", "entry", "exit", "env", "error", "done"];
const RESERVED_NAMES: &[&str] = &["top", "id", "parent", "event"];
const IDENT: &str = "^[A-Za-z_][A-Za-z0-9_]*$";

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Requires {
    #[serde(default)]
    pub events: Vec<String>,
    #[serde(default)]
    pub states: Vec<String>,
    #[serde(default)]
    pub spawns: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Contract {
    #[serde(default)]
    pub contract: Option<i64>,
    pub id: String,
    #[serde(default)]
    pub requires: Requires,
}

/// Fully validate a set of machine definitions (the first is the root). Returns
/// the list of errors (empty => valid).
pub fn validate(
    machines: &[RawMachine],
    contracts: &[Contract],
) -> (bool, Vec<LoadError>) {
    let mut errors: Vec<LoadError> = Vec::new();

    let contract_map: BTreeMap<String, Contract> = contracts
        .iter()
        .map(|c| (c.id.clone(), c.clone()))
        .collect();

    for raw in machines {
        validate_identifiers(raw, &mut errors);
    }
    // inline submachines + build (so semantic checks run on the fully-resolved tree)
    let registry: HashMap<String, crate::model::StateNode> = machines
        .iter()
        .map(|d| (d.id.clone(), d.top.clone()))
        .collect();
    for raw in machines {
        let inlined_top = match crate::model::inline_submachines(
            &raw.top,
            &registry,
            &HashSet::new(),
        ) {
            Ok(t) => t,
            Err(e) => {
                errors.extend(e);
                continue;
            }
        };
        let mut inlined = raw.clone();
        inlined.top = inlined_top;
        let built = match crate::machine::build(&inlined) {
            Ok(m) => m,
            Err(es) => {
                for e in es {
                    errors.push(LoadError {
                        path: format!("machine '{}'", raw.id),
                        message: e,
                    });
                }
                continue;
            }
        };
        validate_choices(&built, &mut errors);
        validate_dead_branches(&built, &mut errors);
        validate_reachability(&built, &mut errors);
        validate_reserved_events(&built, &mut errors);
        validate_contracts(&built, &contract_map, &mut errors);
    }

    (errors.is_empty(), errors)
}

fn re_ident() -> regex_lite::Regex {
    regex_lite::new(IDENT)
}

fn validate_identifiers(raw: &RawMachine, errors: &mut Vec<LoadError>) {
    let re = re_ident();
    if !re.is_match(&raw.id) {
        errors.push(LoadError {
            path: "machine.id".into(),
            message: format!("'{}' is not a valid identifier", raw.id),
        });
    }
    if let Some(ev) = &raw.events {
        for name in ev.keys() {
            if !re.is_match(name) {
                errors.push(LoadError {
                    path: "events".into(),
                    message: format!("'{name}' is not a valid identifier"),
                });
            }
        }
    }
    check_state_identifiers(&raw.top, "top", &re, errors);
}

fn check_state_identifiers(
    node: &crate::model::StateNode,
    path: &str,
    re: &regex_lite::Regex,
    errors: &mut Vec<LoadError>,
) {
    if let Some(esvs) = &node.esvs {
        for name in esvs.keys() {
            check_name(name, &format!("{path}.esvs.{name}"), re, errors);
        }
    }
    if let Some(states) = &node.states {
        for (name, child) in states {
            check_name(name, &format!("{path}.states.{name}"), re, errors);
            check_state_identifiers(child, &format!("{path}.{name}"), re, errors);
        }
    }
    if let Some(regions) = &node.regions {
        for region in regions {
            for (name, child) in &region.states {
                check_name(name, &format!("{path}.states.{name}"), re, errors);
                check_state_identifiers(child, &format!("{path}.{name}"), re, errors);
            }
        }
    }
}

/// Reject malformed identifiers and the structural/intrinsic reserved names
/// `top`, `id`, `parent`, `event` (SPEC §2; reserved event names live in a
/// different namespace and may be reused as state/esv names).
fn check_name(name: &str, path: &str, re: &regex_lite::Regex, errors: &mut Vec<LoadError>) {
    if !re.is_match(name) {
        errors.push(LoadError {
            path: path.into(),
            message: format!("'{name}' is not a valid identifier"),
        });
    }
    if RESERVED_NAMES.contains(&name) {
        errors.push(LoadError {
            path: path.into(),
            message: format!("'{name}' is a reserved name"),
        });
    }
}


fn validate_reserved_events(m: &Machine, errors: &mut Vec<LoadError>) {
    for ev in m.events.keys() {
        if RESERVED_EVENTS.contains(&ev.as_str()) {
            errors.push(LoadError {
                path: "events".into(),
                message: format!("'{ev}' is a reserved event name"),
            });
        }
    }
}

// --- choice pseudostates (§5.5.1) -----------------------------------------

fn validate_dead_branches(m: &Machine, errors: &mut Vec<LoadError>) {
    // In a guarded transition list (§4.5), an unguarded branch is the unconditional
    // default and MUST be last (first passing guard wins); any branch after it is
    // dead (SPEC §2).
    for s in &m.states {
        for (ev, list) in &s.on_events {
            if list.len() < 2 {
                continue;
            }
            for (i, t) in list.iter().enumerate() {
                if i < list.len() - 1 && t.guard.is_none() {
                    errors.push(LoadError {
                        path: format!("{}.on_events.{}", s.path, ev),
                        message:
                            "an unguarded transition must be last; later branches are dead"
                                .into(),
                    });
                    break;
                }
            }
        }
    }
}

// --- reachability (SPEC §2) ------------------------------------------------

/// All `transition_to` / initial targets of a state (resolved NodeIds). Conservative
/// and guard-agnostic — every target is followed regardless of guards.
fn state_targets(s: &StateDef) -> Vec<NodeId> {
    let mut out = Vec::new();
    if let Some(init) = &s.initial {
        out.push(init.target);
    }
    for r in &s.regions {
        out.push(r.initial.target);
    }
    for list in s.on_events.values() {
        for t in list {
            if let Some(tg) = t.target {
                out.push(tg);
            }
        }
    }
    for a in &s.after {
        if let Some(tg) = a.target {
            out.push(tg);
        }
    }
    if let Some(branches) = &s.choice {
        for b in branches {
            out.push(b.target);
        }
    }
    out
}

fn validate_reachability(m: &Machine, errors: &mut Vec<LoadError>) {
    use std::collections::HashSet;
    let mut reachable: HashSet<NodeId> = HashSet::new();
    let mut stack: Vec<NodeId> = vec![m.top];
    while let Some(s) = stack.pop() {
        if reachable.contains(&s) {
            continue;
        }
        reachable.insert(s);
        // entering a state implies its ancestors; follow their edges too
        if let Some(par) = m.get(s).parent {
            if !reachable.contains(&par) {
                stack.push(par);
            }
        }
        for t in state_targets(m.get(s)) {
            if !reachable.contains(&t) {
                stack.push(t);
            }
        }
    }
    for s in &m.states {
        if s.path != "top" && !reachable.contains(&m.by_path[&s.path]) {
            errors.push(LoadError {
                path: "/".to_string() + &s.path.replace('.', "/"),
                message: format!("unreachable state '{}'", s.id),
            });
        }
    }
}

fn validate_choices(m: &Machine, errors: &mut Vec<LoadError>) {
    for (_idx, s) in m.states.iter().enumerate() {
        if s.kind != StateKind::Choice {
            continue;
        }
        let branches = match &s.choice {
            Some(b) => b,
            None => continue,
        };
        // exactly one default (no guard) and it must be last
        let defaults: Vec<usize> = branches
            .iter()
            .enumerate()
            .filter_map(|(i, b)| if b.guard.is_none() { Some(i) } else { None })
            .collect();
        if defaults.is_empty() {
            errors.push(LoadError {
                path: s.path.clone(),
                message: "choice has no default (else) branch".into(),
            });
        } else if defaults.len() > 1 {
            errors.push(LoadError {
                path: s.path.clone(),
                message: "choice has more than one default branch".into(),
            });
        } else if defaults[0] != branches.len() - 1 {
            errors.push(LoadError {
                path: s.path.clone(),
                message: "the default branch must be last".into(),
            });
        }
    }
    // acyclicity over the choice -> choice graph
    let mut visited = HashSet::new();
    let mut stack = HashSet::new();
    for (idx, s) in m.states.iter().enumerate() {
        if s.kind == StateKind::Choice {
            if has_choice_cycle(m, idx, &mut visited, &mut stack) {
                errors.push(LoadError {
                    path: s.path.clone(),
                    message: "choice graph contains a cycle".into(),
                });
            }
        }
    }
}

fn has_choice_cycle(
    m: &Machine,
    start: NodeId,
    visited: &mut HashSet<NodeId>,
    stack: &mut HashSet<NodeId>,
) -> bool {
    if stack.contains(&start) {
        return true;
    }
    if visited.contains(&start) {
        return false;
    }
    visited.insert(start);
    stack.insert(start);
    let s = &m.states[start];
    if let Some(branches) = &s.choice {
        for b in branches {
            if m.states[b.target].kind == StateKind::Choice {
                if has_choice_cycle(m, b.target, visited, stack) {
                    return true;
                }
            }
        }
    }
    stack.remove(&start);
    false
}

// --- contracts (§7) --------------------------------------------------------

fn validate_contracts(
    m: &Machine,
    contracts: &BTreeMap<String, Contract>,
    errors: &mut Vec<LoadError>,
) {
    // gather all handled event names and spawned def ids
    let mut handled_events: HashSet<String> = HashSet::new();
    let mut spawned_defs: HashSet<String> = HashSet::new();
    let mut all_names: HashSet<String> = HashSet::new();
    for s in &m.states {
        all_names.insert(s.id.clone());
        for ev in s.on_events.keys() {
            handled_events.insert(ev.clone());
        }
        collect_spawns(&s.entry, &mut spawned_defs);
        collect_spawns(&s.exit, &mut spawned_defs);
        for ts in s.on_events.values() {
            for t in ts {
                collect_spawns(&t.action, &mut spawned_defs);
            }
        }
        if let Some(init) = &s.initial {
            collect_spawns(&init.action, &mut spawned_defs);
        }
        for a in &s.after {
            collect_spawns(&a.action, &mut spawned_defs);
        }
        if let Some(branches) = &s.choice {
            for b in branches {
                collect_spawns(&b.action, &mut spawned_defs);
            }
        }
    }

    for cid in &m.contracts {
        let contract = match contracts.get(cid) {
            Some(c) => c,
            None => continue, // cannot verify a contract whose definition is absent
        };
        for ev in &contract.requires.events {
            if !handled_events.contains(ev) {
                errors.push(LoadError {
                    path: format!("contract '{}'", cid),
                    message: format!("required event '{ev}' is not handled anywhere"),
                });
            }
        }
        for st in &contract.requires.states {
            if !all_names.contains(st) {
                errors.push(LoadError {
                    path: format!("contract '{}'", cid),
                    message: format!("required state '{st}' is not declared"),
                });
            }
        }
        for sp in &contract.requires.spawns {
            if !spawned_defs.contains(sp) {
                errors.push(LoadError {
                    path: format!("contract '{}'", cid),
                    message: format!("required spawn '{sp}' does not appear in any action"),
                });
            }
        }
    }
}

fn collect_spawns(actions: &[Action], into: &mut HashSet<String>) {
    for a in actions {
        if let Action::Spawn { def, .. } = a {
            into.insert(def.clone());
        }
    }
}

// ---------------------------------------------------------------------------
// A tiny regex implementation (no external crate) sufficient for identifier
// validation: `^[A-Za-z_][A-Za-z0-9_]*$`.

mod regex_lite {
    pub struct Regex;
    pub fn new(_pat: &str) -> Regex {
        Regex
    }
    impl Regex {
        pub fn is_match(&self, s: &str) -> bool {
            let mut chars = s.chars();
            match chars.next() {
                Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
                _ => return s.is_empty(),
            }
            s.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_')
        }
    }
}


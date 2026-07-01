//! YAML machine-definition model (SPEC §4) and raw deserialization.
//!
//! These structs mirror `schema/machine.schema.json` closely. Structural validation
//! (unknown fields, required fields, basic shapes) is enforced by serde's
//! `deny_unknown_fields` plus [`crate::validate`]; richer semantic checks (reference
//! resolution, choice defaults/acyclicity, esv scope, contracts) live in the validator.

use crate::value::Value;
use serde::Deserialize;
use std::collections::BTreeMap;

// --- action (parsed from a single-key mapping) -----------------------------

#[derive(Debug, Clone, PartialEq)]
pub enum Action {
    /// `{ assign: { var: "<cel>", ... } }`
    Assign(Vec<(String, String)>),
    /// `{ publish: { event, to?, payload? } }`
    Publish {
        event: String,
        to: Option<String>,
        payload: Vec<(String, String)>,
    },
    /// `{ refresh: {} }` or `{ refresh: { only: [...] } }`
    Refresh { only: Option<Vec<String>> },
    /// `{ spawn: { def, payload?, result? } }`
    Spawn {
        def: String,
        payload: Vec<(String, String)>,
        result: Option<String>,
    },
    /// `{ stop: {} }`
    Stop,
}

/// Parse one action from its raw YAML mapping.
pub fn parse_action(raw: &serde_yaml::Value) -> Result<Action, String> {
    let map = raw
        .as_mapping()
        .ok_or_else(|| "action must be a mapping".to_string())?;
    if map.len() != 1 {
        return Err(format!(
            "action must have exactly one key, found {}",
            map.len()
        ));
    }
    let (k, v) = map.iter().next().unwrap();
    let key = k.as_str().ok_or_else(|| "action key must be a string".to_string())?;
    match key {
        "assign" => {
            let m = v.as_mapping().ok_or("assign value must be a mapping")?;
            let mut pairs = Vec::new();
            for (kk, vv) in m {
                let name = kk.as_str().ok_or("assign key must be a string")?.to_string();
                let expr = vv.as_str().ok_or("assign value must be a CEL string")?.to_string();
                pairs.push((name, expr));
            }
            if pairs.is_empty() {
                return Err("assign must have at least one variable".to_string());
            }
            Ok(Action::Assign(pairs))
        }
        "publish" => {
            let m = v.as_mapping().ok_or("publish value must be a mapping")?;
            let event = m
                .get("event")
                .and_then(|x| x.as_str())
                .ok_or("publish.event is required")?
                .to_string();
            let to = m.get("to").and_then(|x| x.as_str()).map(|s| s.to_string());
            let payload = parse_payload_cel(m.get("payload"))?;
            Ok(Action::Publish { event, to, payload })
        }
        "refresh" => {
            let only = if let Some(m) = v.as_mapping() {
                m.get("only")
                    .and_then(|x| x.as_sequence())
                    .map(|seq| {
                        seq.iter()
                            .filter_map(|x| x.as_str().map(|s| s.to_string()))
                            .collect()
                    })
            } else {
                None
            };
            Ok(Action::Refresh { only })
        }
        "spawn" => {
            let m = v.as_mapping().ok_or("spawn value must be a mapping")?;
            let def = m
                .get("def")
                .and_then(|x| x.as_str())
                .ok_or("spawn.def is required")?
                .to_string();
            let payload = parse_payload_cel(m.get("payload"))?;
            let result = m.get("result").and_then(|x| x.as_str()).map(|s| s.to_string());
            Ok(Action::Spawn {
                def,
                payload,
                result,
            })
        }
        "stop" => Ok(Action::Stop),
        other => Err(format!("unknown action '{other}'")),
    }
}

fn parse_payload_cel(v: Option<&serde_yaml::Value>) -> Result<Vec<(String, String)>, String> {
    match v {
        None => Ok(Vec::new()),
        Some(serde_yaml::Value::Null) => Ok(Vec::new()),
        Some(m) => {
            let m = m.as_mapping().ok_or("payload must be a mapping")?;
            let mut pairs = Vec::new();
            for (kk, vv) in m {
                let name = kk.as_str().ok_or("payload key must be a string")?.to_string();
                let expr = vv.as_str().ok_or("payload value must be a CEL string")?.to_string();
                pairs.push((name, expr));
            }
            Ok(pairs)
        }
    }
}

pub fn parse_actions(raw: Option<&serde_yaml::Value>) -> Result<Vec<Action>, String> {
    match raw {
        None => Ok(Vec::new()),
        Some(serde_yaml::Value::Null) => Ok(Vec::new()),
        Some(seq) => {
            let seq = seq.as_sequence().ok_or("action list must be a sequence")?;
            seq.iter().map(parse_action).collect()
        }
    }
}

// --- raw serde structs -----------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub struct Languages {
    #[serde(default)]
    pub guard: Option<String>,
    #[serde(default)]
    pub action: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PayloadField {
    #[serde(rename = "type")]
    pub ty: String,
    #[serde(default)]
    pub required: Option<bool>,
    #[serde(default)]
    pub default: Option<serde_yaml::Value>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventDecl {
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub payload: Option<BTreeMap<String, PayloadField>>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EsvDecl {
    #[serde(rename = "type")]
    pub ty: String,
    #[serde(default)]
    pub init: Option<serde_yaml::Value>,
    #[serde(default)]
    pub external: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Transition {
    #[serde(default)]
    pub transition_to: Option<String>,
    #[serde(default)]
    pub guard: Option<String>,
    #[serde(default)]
    pub lang: Option<String>,
    #[serde(default)]
    pub action: Option<serde_yaml::Value>,
    #[serde(default)]
    pub internal: Option<bool>,
    #[serde(default)]
    pub local: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum TransitionOrList {
    One(Transition),
    Many(Vec<Transition>),
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InitialTransition {
    pub transition_to: String,
    #[serde(default)]
    pub guard: Option<String>,
    #[serde(default)]
    pub action: Option<serde_yaml::Value>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChoiceBranch {
    pub transition_to: String,
    #[serde(default)]
    pub guard: Option<String>,
    #[serde(default)]
    pub action: Option<serde_yaml::Value>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AfterTimer {
    pub duration: String,
    #[serde(default)]
    pub transition_to: Option<String>,
    #[serde(default)]
    pub guard: Option<String>,
    #[serde(default)]
    pub action: Option<serde_yaml::Value>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Region {
    pub initial: InitialTransition,
    pub states: BTreeMap<String, StateNode>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateNode {
    #[serde(rename = "type", default)]
    pub ty: Option<String>,
    #[serde(default)]
    pub esvs: Option<BTreeMap<String, EsvDecl>>,
    #[serde(default)]
    pub entry: Option<serde_yaml::Value>,
    #[serde(default)]
    pub exit: Option<serde_yaml::Value>,
    #[serde(default)]
    pub initial: Option<InitialTransition>,
    #[serde(default)]
    pub states: Option<BTreeMap<String, StateNode>>,
    #[serde(default)]
    pub regions: Option<Vec<Region>>,
    #[serde(default)]
    pub on_events: Option<BTreeMap<String, TransitionOrList>>,
    #[serde(default)]
    pub after: Option<Vec<AfterTimer>>,
    #[serde(default)]
    pub defer: Option<Vec<String>>,
    #[serde(default)]
    pub history: Option<String>,
    #[serde(default)]
    pub choice: Option<Vec<ChoiceBranch>>,
    /// `submachine: <id>` inlines another definition synchronously (SPEC §5.6.1).
    #[serde(default)]
    pub submachine: Option<String>,
    /// `with: { <externalEsv>: <CEL> }` seeds the submachine's external esvs.
    #[serde(default)]
    pub with: Option<BTreeMap<String, String>>,
    /// Engine-set: this node is the inlined `top` of a submachine (esv-scope
    /// boundary). Never appears in YAML.
    #[serde(skip)]
    pub is_sm_boundary: bool,
    #[serde(skip)]
    pub sm_with: BTreeMap<String, String>,
}

/// Inline `submachine:` references into a nested state tree (SPEC §5.6.1).
///
/// A state with `submachine: <id>` becomes a composite whose single child (named
/// `<id>`) is the referenced definition's `top` (recursively inlined), marked as an
/// esv-scope boundary and carrying the `with:` seeding. `registry` maps definition
/// id -> its raw `top`. Returns errors for unknown or cyclic references.
pub fn inline_submachines(
    node: &StateNode,
    registry: &std::collections::HashMap<String, StateNode>,
    stack: &std::collections::HashSet<String>,
) -> Result<StateNode, Vec<crate::loader::LoadError>> {
    use crate::loader::LoadError;
    if let Some(sub_id) = &node.submachine {
        let reg_top = match registry.get(sub_id) {
            Some(t) => t,
            None => {
                return Err(vec![LoadError {
                    path: "/submachine".into(),
                    message: format!("unknown submachine '{sub_id}'"),
                }]);
            }
        };
        if stack.contains(sub_id) {
            return Err(vec![LoadError {
                path: "/submachine".into(),
                message: format!("cyclic submachine '{sub_id}'"),
            }]);
        }
        let mut new_stack = stack.clone();
        new_stack.insert(sub_id.clone());
        let mut child = inline_submachines(reg_top, registry, &new_stack)?;
        child.is_sm_boundary = true;
        child.sm_with = node.with.clone().unwrap_or_default();
        let mut out = node.clone();
        out.submachine = None;
        out.with = None;
        out.is_sm_boundary = false;
        out.sm_with = BTreeMap::new();
        let mut states = BTreeMap::new();
        states.insert(sub_id.clone(), child);
        out.states = Some(states);
        out.initial = Some(InitialTransition {
            transition_to: sub_id.clone(),
            guard: None,
            action: None,
        });
        return Ok(out);
    }
    let mut out = node.clone();
    if let Some(states) = &node.states {
        let mut new_states = BTreeMap::new();
        for (k, v) in states {
            new_states.insert(k.clone(), inline_submachines(v, registry, stack)?);
        }
        out.states = Some(new_states);
    }
    if let Some(regions) = &node.regions {
        let mut new_regions = Vec::new();
        for r in regions {
            let mut nr = r.clone();
            let mut ns = BTreeMap::new();
            for (k, v) in &r.states {
                ns.insert(k.clone(), inline_submachines(v, registry, stack)?);
            }
            nr.states = ns;
            new_regions.push(nr);
        }
        out.regions = Some(new_regions);
    }
    Ok(out)
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Migration {
    pub from: i64,
    pub to: i64,
    #[serde(default)]
    pub when: Option<String>,
    #[serde(default)]
    pub state_map: Option<BTreeMap<String, String>>,
    #[serde(default)]
    pub esvs: Option<serde_yaml::Value>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawMachine {
    #[serde(default)]
    pub format: Option<i64>,
    pub id: String,
    #[serde(default)]
    pub version: Option<i64>,
    #[serde(default)]
    pub contracts: Vec<String>,
    #[serde(default)]
    pub subscribe: Vec<String>,
    #[serde(default)]
    pub languages: Option<Languages>,
    #[serde(default)]
    pub events: Option<BTreeMap<String, EventDecl>>,
    #[serde(default)]
    pub migrations: Option<Vec<Migration>>,
    pub top: StateNode,
}

/// Convert a raw esv init literal (YAML) into a Value, checking it matches the type.
pub fn esv_init_value(ty: &str, raw: &serde_yaml::Value) -> Result<Value, String> {
    let v = Value::from_yaml(raw);
    if v.matches_type(ty) {
        Ok(v)
    } else {
        Err(format!(
            "esv init {:?} does not match declared type '{}'",
            v, ty
        ))
    }
}

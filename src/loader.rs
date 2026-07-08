//! Loading Determa State YAML: multi-document machine files (§9: first doc is the root)
//! and contract files (§7).

use crate::model::RawMachine;
use crate::validate::Contract;
use serde::Deserialize;

/// A validation error with a structural path.
#[derive(Debug, Clone, Default)]
pub struct LoadError {
    pub path: String,
    pub message: String,
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.path.is_empty() {
            write!(f, "{}", self.message)
        } else {
            write!(f, "{}: {}", self.path, self.message)
        }
    }
}

/// Parse one or more `---`-separated machine definitions from YAML text.
pub fn load_machines(src: &str) -> Result<Vec<RawMachine>, Vec<LoadError>> {
    let de = serde_yaml::Deserializer::from_str(src);
    let mut out = Vec::new();
    let mut errs = Vec::new();
    for (doc_index, doc) in de.enumerate() {
        match RawMachine::deserialize(doc) {
            Ok(m) => out.push(m),
            Err(e) => {
                let pos = e.location().map(|l| l.line()).unwrap_or(0);
                let path = format!("doc[{}]", doc_index);
                errs.push(LoadError {
                    path: format!("{path}:line {pos}"),
                    message: format!("{e}"),
                });
            }
        }
    }
    if !errs.is_empty() {
        return Err(errs);
    }
    if out.is_empty() {
        return Err(vec![LoadError {
            path: "machine".to_string(),
            message: "no machine definitions found".to_string(),
        }]);
    }
    Ok(out)
}

/// Parse a single machine definition from a pre-parsed JSON value — no YAML text.
///
/// A host can build a machine in code (e.g. with the `serde_json::json!` macro)
/// and load it through the same deserialization path as `load_machines`, without
/// serializing to a YAML string first. The first document of a multi-document
/// machine is the root (SPEC §9).
pub fn load_machine_from_value(value: serde_json::Value) -> Result<RawMachine, LoadError> {
    serde_json::from_value(value).map_err(|e| LoadError {
        path: "machine".to_string(),
        message: format!("{e}"),
    })
}

/// Parse machine definitions from pre-parsed JSON values (one per document).
///
/// The host supplies each document already split; the first is the root (SPEC §9).
/// This is the value-based counterpart of `load_machines`.
pub fn load_machines_from_values(
    values: Vec<serde_json::Value>,
) -> Result<Vec<RawMachine>, Vec<LoadError>> {
    let mut out = Vec::new();
    let mut errs = Vec::new();
    for (i, value) in values.into_iter().enumerate() {
        match serde_json::from_value::<RawMachine>(value) {
            Ok(m) => out.push(m),
            Err(e) => errs.push(LoadError {
                path: format!("doc[{i}]"),
                message: format!("{e}"),
            }),
        }
    }
    if !errs.is_empty() {
        return Err(errs);
    }
    if out.is_empty() {
        return Err(vec![LoadError {
            path: "machine".to_string(),
            message: "no machine definitions found".to_string(),
        }]);
    }
    Ok(out)
}

/// Parse a single contract file.
pub fn load_contract(src: &str) -> Result<Contract, LoadError> {
    let de = serde_yaml::Deserializer::from_str(src);
    Contract::deserialize(de).map_err(|e| LoadError {
        path: "contract".to_string(),
        message: format!("{e}"),
    })
}

pub fn load_contracts(srcs: &[(&str, &str)]) -> Result<Vec<Contract>, LoadError> {
    let mut out = Vec::new();
    for (_name, src) in srcs {
        out.push(load_contract(src)?);
    }
    Ok(out)
}

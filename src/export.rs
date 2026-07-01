//! Mermaid `stateDiagram-v2` export (SPEC §12). Renders the static structure of a
//! machine; with a `state_config`, highlights the active leaves and their ancestors.

use crate::machine::{HistoryKind, Machine, NodeId, StateKind};
use std::collections::HashSet;

/// Export the static structure (no live highlight).
pub fn mermaid(m: &Machine) -> String {
    mermaid_with_config(m, &HashSet::new())
}

/// Export with `active_paths` highlighted (active leaves + their ancestors).
pub fn mermaid_with_config(m: &Machine, active_paths: &HashSet<String>) -> String {
    let mut out = String::from("stateDiagram-v2\n");
    emit(m, m.top, &mut out, 0);
    if !active_paths.is_empty() {
        out.push_str("    classDef active fill:#9f9,stroke:#3a3\n");
        let mut classes: Vec<String> = m
            .states
            .iter()
            .filter(|s| active_paths.contains(&s.path))
            .map(|s| s.id.clone())
            .collect();
        classes.sort();
        classes.dedup();
        if !classes.is_empty() {
            out.push_str(&format!("    class {} active\n", classes.join(",")));
        }
    }
    out
}

fn pad(out: &mut String, indent: usize) {
    for _ in 0..indent {
        out.push_str("  ");
    }
}

fn emit(m: &Machine, n: NodeId, out: &mut String, indent: usize) {
    let sd = m.get(n);
    let is_top = n == m.top;
    match sd.kind {
        StateKind::Composite => {
            if !is_top {
                pad(out, indent);
                out.push_str(&format!("state {} {{\n", sd.id));
            }
            if let Some(init) = &sd.initial {
                pad(out, indent + 1);
                out.push_str(&format!("[*] --> {}\n", m.get(init.target).id));
            }
            for &c in &sd.children {
                emit(m, c, out, indent + 1);
            }
            emit_transitions(m, n, out, indent + 1);
            if !is_top {
                pad(out, indent);
                out.push_str("}\n");
            }
        }
        StateKind::Orthogonal => {
            pad(out, indent);
            out.push_str(&format!("state {} {{\n", sd.id));
            let regs = sd.regions.clone();
            for (ri, r) in regs.iter().enumerate() {
                if ri > 0 {
                    pad(out, indent + 1);
                    out.push_str("--\n");
                }
                pad(out, indent + 1);
                out.push_str(&format!("[*] --> {}\n", m.get(r.initial.target).id));
                for &s in &r.states {
                    emit(m, s, out, indent + 2);
                }
            }
            emit_transitions(m, n, out, indent + 1);
            pad(out, indent);
            out.push_str("}\n");
        }
        StateKind::Final => {
            pad(out, indent);
            out.push_str(&format!("{} --> [*]\n", sd.id));
            emit_transitions(m, n, out, indent);
        }
        StateKind::Simple | StateKind::Choice => {
            emit_transitions(m, n, out, indent);
        }
    }
    if !matches!(sd.history, HistoryKind::None) {
        let h = if matches!(sd.history, HistoryKind::Deep) { "deep" } else { "shallow" };
        pad(out, indent);
        out.push_str(&format!("note right of {}: history {}\n", sd.id, h));
    }
}

fn emit_transitions(m: &Machine, src: NodeId, out: &mut String, indent: usize) {
    let src_id = m.get(src).id.clone();
    for (ev, list) in &m.get(src).on_events {
        for t in list {
            if let Some(tgt) = t.target {
                let mut label = ev.clone();
                if let Some(g) = &t.guard {
                    label.push_str(&format!(" [{g}]"));
                }
                pad(out, indent);
                out.push_str(&format!("{src_id} --> {} : {label}\n", m.get(tgt).id));
            }
        }
    }
    for a in &m.get(src).after {
        if let Some(tgt) = a.target {
            pad(out, indent);
            out.push_str(&format!(
                "{} --> {} : after({}ms)\n",
                src_id,
                m.get(tgt).id,
                a.duration_ms
            ));
        }
    }
}

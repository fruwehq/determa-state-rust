//! Conditional policy only: this binary cannot construct a native store handle.
use std::io::{Read, Write};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut bytes = Vec::new();
    std::io::stdin().read_to_end(&mut bytes)?;
    let input: serde_json::Value = serde_json::from_slice(&bytes)?;
    if input["evidence_layer"] != "conditional_adapter_policy" {
        return Err("unsupported evidence layer".into());
    }
    let actual = determa_state::checkpoint::conditional_adapter_policy(&input["request"]);
    let observation = serde_json::json!({"raw_response":actual,"root_accesses":0,"operational_handles_created":0});
    std::io::stdout().write_all(serde_json::to_string(&observation)?.as_bytes())?;
    Ok(())
}

//! Repository-only adapter for the official extension negotiation process runner.
#[path = "../tests/extension_conformance.rs"]
mod driver;
use std::io::{Read, Write};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut bytes = Vec::new();
    std::io::stdin().read_to_end(&mut bytes)?;
    let request: serde_json::Value = serde_json::from_slice(&bytes)?;
    let response = driver::observe_extension_profile(&request);
    std::io::stdout().write_all(serde_json::to_string(&response)?.as_bytes())?;
    Ok(())
}

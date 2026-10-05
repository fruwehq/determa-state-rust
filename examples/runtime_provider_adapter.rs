//! Repository-only production provider adapter. Enable determa_repository_conformance
//! for compilation-stage and emission-index observations required by the full profile.
#[path = "../tests/runtime_provider_conformance.rs"]
mod driver;
use std::io::{Read, Write};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut bytes = Vec::new();
    std::io::stdin().read_to_end(&mut bytes)?;
    let payload: serde_json::Value = serde_json::from_slice(&bytes)?;
    std::io::stdout()
        .write_all(serde_json::to_string(&driver::observe_runtime_profile(&payload))?.as_bytes())?;
    Ok(())
}

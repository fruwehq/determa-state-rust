mod file;
mod memory;
#[cfg(feature = "postgresql")]
mod postgresql;
#[cfg(feature = "sqlite")]
mod sqlite;

pub use file::{FileExecutionStore, FileExecutionStoreFactory};
pub use memory::{MemoryExecutionStore, MemoryExecutionStoreFactory};
#[cfg(feature = "postgresql")]
pub use postgresql::{PostgresqlExecutionStore, PostgresqlExecutionStoreFactory};
#[cfg(feature = "sqlite")]
pub use sqlite::{SqliteExecutionStore, SqliteExecutionStoreFactory};

use super::store::{AdapterError, AdapterRegistry};
use std::sync::Arc;

/// Registers every compiled bundled adapter through the public registration API.
pub fn register_bundled_adapters(registry: &AdapterRegistry) -> Result<(), AdapterError> {
    registry.register("memory", Arc::new(MemoryExecutionStoreFactory))?;
    registry.register("file", Arc::new(FileExecutionStoreFactory))?;
    #[cfg(feature = "sqlite")]
    registry.register("sqlite", Arc::new(SqliteExecutionStoreFactory))?;
    #[cfg(feature = "postgresql")]
    registry.register(
        "postgresql",
        Arc::new(PostgresqlExecutionStoreFactory::no_tls()),
    )?;
    Ok(())
}

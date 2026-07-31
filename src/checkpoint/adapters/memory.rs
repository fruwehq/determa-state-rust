use super::super::store::{
    AdapterError, AdapterErrorCode, ExecutionStore, ExecutionStoreCapability,
    ExecutionStoreFactory, HealthStatus, StoreError, StoreRecord, StoreWriteResult,
};
use std::any::Any;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

#[derive(Default)]
pub struct MemoryExecutionStore {
    records: Mutex<BTreeMap<String, StoreRecord>>,
}

impl MemoryExecutionStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl ExecutionStore for MemoryExecutionStore {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn capabilities(&self) -> BTreeSet<ExecutionStoreCapability> {
        BTreeSet::from([ExecutionStoreCapability::Ephemeral])
    }

    fn initialize_schema(&self) -> Result<(), StoreError> {
        Ok(())
    }

    fn health(&self) -> Result<HealthStatus, StoreError> {
        drop(
            self.records
                .lock()
                .map_err(|_| StoreError::new("memory store lock is poisoned"))?,
        );
        Ok(HealthStatus::healthy("memory store is available"))
    }

    fn load(&self, root_instance_id: &str) -> Result<Option<StoreRecord>, StoreError> {
        Ok(self
            .records
            .lock()
            .map_err(|_| StoreError::new("memory store lock is poisoned"))?
            .get(root_instance_id)
            .cloned())
    }

    fn insert_if_absent(&self, record: StoreRecord) -> Result<StoreWriteResult, StoreError> {
        let mut records = self
            .records
            .lock()
            .map_err(|_| StoreError::new("memory store lock is poisoned"))?;
        if let Some(current) = records.get(&record.root_instance_id) {
            return Ok(StoreWriteResult::Conflict(Some(current.clone())));
        }
        records.insert(record.root_instance_id.clone(), record);
        Ok(StoreWriteResult::Committed)
    }

    fn compare_and_swap(
        &self,
        root_instance_id: &str,
        expected_revision: &str,
        expected_checkpoint_digest: &str,
        replacement: StoreRecord,
    ) -> Result<StoreWriteResult, StoreError> {
        if replacement.root_instance_id != root_instance_id {
            return Err(StoreError::new("replacement belongs to another root"));
        }
        let mut records = self
            .records
            .lock()
            .map_err(|_| StoreError::new("memory store lock is poisoned"))?;
        let Some(current) = records.get(root_instance_id) else {
            return Ok(StoreWriteResult::Conflict(None));
        };
        if current.revision != expected_revision
            || current.execution_checkpoint_digest != expected_checkpoint_digest
        {
            return Ok(StoreWriteResult::Conflict(Some(current.clone())));
        }
        records.insert(root_instance_id.to_string(), replacement);
        Ok(StoreWriteResult::Committed)
    }
}

pub struct MemoryExecutionStoreFactory;

impl ExecutionStoreFactory for MemoryExecutionStoreFactory {
    fn create(&self, configuration: &str) -> Result<Arc<dyn ExecutionStore>, AdapterError> {
        if configuration != "memory:" {
            return Err(AdapterError::new(
                AdapterErrorCode::InvalidAdapterConfiguration,
                "memory configuration must be exactly memory:",
            ));
        }
        Ok(Arc::new(MemoryExecutionStore::new()))
    }
}

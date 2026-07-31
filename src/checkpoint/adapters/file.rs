use super::super::store::{
    AdapterError, AdapterErrorCode, ExecutionStore, ExecutionStoreCapability,
    ExecutionStoreFactory, HealthStatus, StoreError, StoreRecord, StoreWriteResult,
};
use fs2::FileExt;
use sha2::{Digest, Sha256};
use std::any::Any;
use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

const SCHEMA_MARKER: &str = ".determa-execution-checkpoint-v1";
const LOCK_FILE: &str = ".determa-execution-checkpoint.lock";
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

pub struct FileExecutionStore {
    directory: PathBuf,
}

impl FileExecutionStore {
    pub fn new(directory: impl Into<PathBuf>) -> Result<Self, StoreError> {
        let directory = directory.into();
        if !directory.is_absolute() {
            return Err(StoreError::new("file store directory must be absolute"));
        }
        Ok(Self { directory })
    }

    fn with_lock<T>(
        &self,
        operation: impl FnOnce() -> Result<T, StoreError>,
    ) -> Result<T, StoreError> {
        self.require_schema()?;
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(self.directory.join(LOCK_FILE))
            .map_err(io_error)?;
        lock.lock_exclusive().map_err(io_error)?;
        let result = operation();
        FileExt::unlock(&lock).map_err(io_error)?;
        result
    }

    fn require_schema(&self) -> Result<(), StoreError> {
        if self.directory.join(SCHEMA_MARKER).is_file() {
            Ok(())
        } else {
            Err(StoreError::new(
                "file store schema is not initialized; call initialize_schema",
            ))
        }
    }

    fn record_path(&self, root_instance_id: &str) -> PathBuf {
        let digest = Sha256::digest(root_instance_id.as_bytes());
        self.directory.join(format!("{digest:x}.checkpoint.json"))
    }

    fn load_unlocked(&self, root_instance_id: &str) -> Result<Option<StoreRecord>, StoreError> {
        let path = self.record_path(root_instance_id);
        let mut source = Vec::new();
        match File::open(path) {
            Ok(mut file) => {
                file.read_to_end(&mut source).map_err(io_error)?;
                let record = record_from_bytes(source)?;
                if record.root_instance_id != root_instance_id {
                    return Err(StoreError::new("file record root identity mismatch"));
                }
                Ok(Some(record))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(io_error(error)),
        }
    }

    fn replace_unlocked(&self, record: &StoreRecord) -> Result<(), StoreError> {
        let final_path = self.record_path(&record.root_instance_id);
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let temporary = self.directory.join(format!(
            ".{}.{}.{}.tmp",
            std::process::id(),
            sequence,
            final_path
                .file_name()
                .and_then(|value| value.to_str())
                .unwrap_or("checkpoint")
        ));
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)
            .map_err(io_error)?;
        file.write_all(&record.bytes).map_err(io_error)?;
        file.sync_all().map_err(io_error)?;
        fs::rename(&temporary, &final_path).map_err(io_error)?;
        File::open(&self.directory)
            .and_then(|directory| directory.sync_all())
            .map_err(io_error)?;
        Ok(())
    }
}

impl ExecutionStore for FileExecutionStore {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn capabilities(&self) -> BTreeSet<ExecutionStoreCapability> {
        BTreeSet::from([ExecutionStoreCapability::RestartPersistent])
    }

    fn initialize_schema(&self) -> Result<(), StoreError> {
        fs::create_dir_all(&self.directory).map_err(io_error)?;
        let marker = self.directory.join(SCHEMA_MARKER);
        if marker.exists() {
            let contents = fs::read_to_string(marker).map_err(io_error)?;
            if contents != "1\n" {
                return Err(StoreError::new("unsupported file store schema marker"));
            }
            return Ok(());
        }
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(marker)
            .map_err(io_error)?;
        file.write_all(b"1\n").map_err(io_error)?;
        file.sync_all().map_err(io_error)?;
        Ok(())
    }

    fn health(&self) -> Result<HealthStatus, StoreError> {
        self.require_schema()?;
        Ok(HealthStatus::healthy("file store schema is available"))
    }

    fn load(&self, root_instance_id: &str) -> Result<Option<StoreRecord>, StoreError> {
        self.with_lock(|| self.load_unlocked(root_instance_id))
    }

    fn insert_if_absent(&self, record: StoreRecord) -> Result<StoreWriteResult, StoreError> {
        self.with_lock(|| {
            if let Some(current) = self.load_unlocked(&record.root_instance_id)? {
                return Ok(StoreWriteResult::Conflict(Some(current)));
            }
            self.replace_unlocked(&record)?;
            Ok(StoreWriteResult::Committed)
        })
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
        self.with_lock(|| {
            let Some(current) = self.load_unlocked(root_instance_id)? else {
                return Ok(StoreWriteResult::Conflict(None));
            };
            if current.revision != expected_revision
                || current.execution_checkpoint_digest != expected_checkpoint_digest
            {
                return Ok(StoreWriteResult::Conflict(Some(current)));
            }
            self.replace_unlocked(&replacement)?;
            Ok(StoreWriteResult::Committed)
        })
    }
}

pub struct FileExecutionStoreFactory;

impl ExecutionStoreFactory for FileExecutionStoreFactory {
    fn create(&self, configuration: &str) -> Result<Arc<dyn ExecutionStore>, AdapterError> {
        let path = configuration.strip_prefix("file:").ok_or_else(|| {
            AdapterError::new(
                AdapterErrorCode::InvalidAdapterConfiguration,
                "file configuration must use the file scheme",
            )
        })?;
        if path.is_empty() || !Path::new(path).is_absolute() {
            return Err(AdapterError::new(
                AdapterErrorCode::InvalidAdapterConfiguration,
                "file configuration must name an absolute directory",
            ));
        }
        FileExecutionStore::new(path)
            .map(|store| Arc::new(store) as Arc<dyn ExecutionStore>)
            .map_err(|error| {
                AdapterError::new(
                    AdapterErrorCode::InvalidAdapterConfiguration,
                    error.to_string(),
                )
            })
    }
}

fn record_from_bytes(bytes: Vec<u8>) -> Result<StoreRecord, StoreError> {
    let value: serde_json::Value = serde_json::from_slice(&bytes).map_err(json_error)?;
    let object = value
        .as_object()
        .ok_or_else(|| StoreError::new("checkpoint record is not an object"))?;
    let string = |name: &str| {
        object
            .get(name)
            .and_then(serde_json::Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| StoreError::new(format!("checkpoint record lacks {name}")))
    };
    Ok(StoreRecord {
        root_instance_id: string("root_instance_id")?,
        revision: string("revision")?,
        execution_checkpoint_digest: string("execution_checkpoint_digest")?,
        bytes,
    })
}

fn io_error(error: std::io::Error) -> StoreError {
    StoreError::new(error.to_string())
}

fn json_error(error: serde_json::Error) -> StoreError {
    StoreError::new(error.to_string())
}

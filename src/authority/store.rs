//! Checkpoint host composition over the authority's actual SQLite boundary.
//! No complete inventory, worker, relocation or verified authority profile is claimed.

use super::{canonical, hash, NativeAuthorityInvocation, SqliteLocalAuthority};
use crate::checkpoint::{
    self, DurableStoreMode, ExecutionStore, ExecutionStoreCapability, HealthStatus, MutationGuard,
    SqliteExecutionStore, StoreError, StoreRecord, StoreWriteResult,
};
use crate::format1::{strict_json, DefinitionResolver};
use serde_json::{json, Value};
use std::{any::Any, collections::BTreeSet, path::Path, sync::Arc};

/// A configured native owner and immutable epoch-zero scope, with resolver-backed
/// checkpoint validation and authority checks at every actual checkpoint commit.
/// Shared application transactions are deliberately not advertised by this wrapper.
pub struct GuardedSqliteExecutionStore<R> {
    authority: SqliteLocalAuthority,
    checkpoints: SqliteExecutionStore,
    resolver: Arc<R>,
    scope: String,
    owner: String,
    host_binding: String,
    mode: DurableStoreMode,
}

fn error(value: impl std::fmt::Display) -> StoreError {
    StoreError::new(value.to_string())
}

impl<R: DefinitionResolver + Send + Sync + 'static> GuardedSqliteExecutionStore<R> {
    pub fn open(
        path: impl AsRef<Path>,
        mode: DurableStoreMode,
        scope: String,
        owner: String,
        host_binding: String,
        resolver: Arc<R>,
    ) -> Result<Self, StoreError> {
        if scope.is_empty() || owner.is_empty() || host_binding.is_empty() {
            return Err(error(
                "configured scope, owner and host binding are required",
            ));
        }
        Ok(Self {
            authority: SqliteLocalAuthority::open(&path).map_err(error)?,
            checkpoints: SqliteExecutionStore::open(path, mode)?,
            resolver,
            scope,
            owner,
            host_binding,
            mode,
        })
    }

    /// Explicit fresh allocation, never inferred from an imported checkpoint.
    pub fn allocate_scope(&self) -> Result<bool, StoreError> {
        self.checkpoints.health()?;
        self.authority
            .allocate(&self.scope, &self.owner, &self.host_binding)
            .map_err(error)
    }

    fn caller(&self) -> NativeAuthorityInvocation {
        NativeAuthorityInvocation {
            authenticated_principal: self.owner.clone(),
            authorized_scopes: BTreeSet::from([self.scope.clone()]),
            operation_rights: BTreeSet::from([
                "read_authority".to_owned(),
                "guarded_commit".to_owned(),
            ]),
        }
    }

    fn authority_snapshot(&self) -> Result<Value, StoreError> {
        let mut request = json!({"interface":"determa.host_authority","interface_version":1,
            "operation":"read_authority","operation_id":"configured-checkpoint-store-read",
            "scope_identity":self.scope,"expected_authority_epoch":null,
            "expected_scope_generation":null,"arguments":{}});
        request["request_digest"] =
            json!(hash(&json!(["determa-host-authority-request-1", request])).map_err(error)?);
        let result = self
            .authority
            .perform(&canonical(&request).map_err(error)?, &self.caller(), None)
            .map_err(error)?;
        if result["status"] != "accepted"
            || result["state"] != "active"
            || result["authority_epoch"] != "0"
        {
            return Err(error("configured scope authority is not active"));
        }
        let connection = self.authority.connection.lock().map_err(error)?;
        let bytes: Vec<u8> = connection
            .query_row(
                "SELECT ledger FROM determa_scope_authority WHERE scope_identity=?",
                [&self.scope],
                |row| row.get(0),
            )
            .map_err(error)?;
        let ledger = strict_json::parse(&bytes).map_err(error)?;
        if ledger["owner_binding"]
            != json!({"owner_principal":self.owner,"host_binding":self.host_binding})
        {
            return Err(error("configured authority owner binding differs"));
        }
        Ok(result)
    }

    fn commit(
        &self,
        record: StoreRecord,
        guard: Option<&MutationGuard>,
    ) -> Result<StoreWriteResult, StoreError> {
        let checkpoint =
            checkpoint::restore(&record.bytes, self.resolver.as_ref()).map_err(error)?;
        if StoreRecord::from_checkpoint(&checkpoint)? != record {
            return Err(error(
                "native checkpoint metadata does not match validated checkpoint",
            ));
        }
        let authority = self.authority_snapshot()?;
        let mutation = super::checkpoint_mutation_bytes(&checkpoint, guard).map_err(error)?;
        let operation_id = hash(&json!([
            "determa-authority-checkpoint-operation-1",
            self.scope,
            authority["authority_epoch"],
            authority["scope_generation"],
            strict_json::parse(&mutation).map_err(error)?
        ]))
        .map_err(error)?;
        let mut request = json!({"interface":"determa.host_authority","interface_version":1,
            "operation":"guarded_commit","operation_id":operation_id,"scope_identity":self.scope,
            "expected_authority_epoch":"0","expected_scope_generation":authority["scope_generation"],
            "arguments":{"mutation_digest":format!("sha256:{:x}", <sha2::Sha256 as sha2::Digest>::digest(&mutation))}});
        request["request_digest"] =
            json!(hash(&json!(["determa-host-authority-request-1", request])).map_err(error)?);
        match self.authority.commit_checkpoint(
            &canonical(&request).map_err(error)?,
            &self.caller(),
            self.mode,
            &checkpoint,
            guard,
        ) {
            Ok(result) if result["status"] == "accepted" => Ok(StoreWriteResult::Committed),
            Ok(result) if result["error_code"] == "scope_generation_conflict" => Ok(
                StoreWriteResult::Conflict(self.checkpoints.load(&record.root_instance_id)?),
            ),
            Ok(result) => Err(error(format!(
                "authority refused checkpoint commit: {}",
                result["error_code"]
            ))),
            Err(failure) if failure.to_string() == "checkpoint_revision_conflict" => Ok(
                StoreWriteResult::Conflict(self.checkpoints.load(&record.root_instance_id)?),
            ),
            Err(failure) => Err(error(failure)),
        }
    }
}

impl<R: DefinitionResolver + Send + Sync + 'static> ExecutionStore
    for GuardedSqliteExecutionStore<R>
{
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn capabilities(&self) -> BTreeSet<ExecutionStoreCapability> {
        let mut capabilities = self.checkpoints.capabilities();
        capabilities.remove(&ExecutionStoreCapability::SharedApplicationTransaction);
        capabilities
    }

    fn initialize_schema(&self) -> Result<(), StoreError> {
        self.authority.setup_schema().map_err(error)?;
        let allocated: u64 = self
            .authority
            .connection
            .lock()
            .map_err(error)?
            .query_row(
                "SELECT COUNT(*) FROM determa_scope_allocations",
                [],
                |row| row.get(0),
            )
            .map_err(error)?;
        if allocated != 0 {
            // Never recreate missing checkpoint evidence around an allocated scope.
            self.checkpoints.health()?;
        } else {
            self.checkpoints.initialize_schema()?;
        }
        Ok(())
    }

    fn health(&self) -> Result<HealthStatus, StoreError> {
        self.authority_snapshot()?;
        self.checkpoints.health()
    }

    fn load(&self, root: &str) -> Result<Option<StoreRecord>, StoreError> {
        self.health()?;
        self.checkpoints.load(root)
    }

    fn insert_if_absent(&self, record: StoreRecord) -> Result<StoreWriteResult, StoreError> {
        self.commit(record, None)
    }

    fn compare_and_swap(
        &self,
        root: &str,
        revision: &str,
        digest: &str,
        replacement: StoreRecord,
    ) -> Result<StoreWriteResult, StoreError> {
        if root != replacement.root_instance_id {
            return Err(error("checkpoint replacement belongs to another root"));
        }
        self.commit(replacement, Some(&MutationGuard::new(revision, digest)))
    }
}

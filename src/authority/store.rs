//! Checkpoint host composition over the authority's actual SQLite boundary.
//! No complete inventory, worker, relocation or verified authority profile is claimed.

use super::{canonical, hash, NativeAuthorityInvocation, SqliteLocalAuthority};
use crate::checkpoint::{
    self, DurableStoreMode, ExecutionStore, ExecutionStoreCapability, HealthStatus, MutationGuard,
    SqliteExecutionStore, StoreError, StoreRecord, StoreWriteResult,
};
use crate::format1::{strict_json, DefinitionResolver};
use rusqlite::OptionalExtension;
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

    /// Validation and the consuming read share the same native SQLite snapshot.
    /// No checkpoint bytes may escape via the separate raw store connection.
    pub(super) fn with_authority_snapshot<T>(
        &self,
        read: impl FnOnce(&rusqlite::Connection, &Value) -> Result<T, StoreError>,
    ) -> Result<T, StoreError> {
        let mut connection = self.authority.connection.lock().map_err(error)?;
        let transaction = connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Deferred)
            .map_err(error)?;
        super::validate_schema(&transaction, &self.authority.storage_binding).map_err(error)?;
        checkpoint::verify_sqlite_schema(&transaction, self.mode)?;
        let bytes: Vec<u8> = transaction
            .query_row(
                "SELECT ledger FROM determa_scope_authority WHERE scope_identity=?",
                [&self.scope],
                |row| row.get(0),
            )
            .map_err(error)?;
        let ledger = strict_json::parse(&bytes).map_err(error)?;
        if canonical(&ledger).map_err(error)? != bytes {
            return Err(error("authority ledger is not canonical"));
        }
        super::validate_record(&transaction, &self.scope, &ledger).map_err(error)?;
        if ledger["state"] != "active" || ledger["authority_epoch"] != "0" {
            return Err(error("configured scope authority is not active"));
        }
        if ledger["owner_binding"]
            != json!({"owner_principal":self.owner,"host_binding":self.host_binding})
        {
            return Err(error("configured authority owner binding differs"));
        }
        let result = read(&transaction, &ledger)?;
        transaction.commit().map_err(error)?;
        Ok(result)
    }

    fn authority_snapshot(&self) -> Result<Value, StoreError> {
        self.with_authority_snapshot(|_, ledger| Ok(ledger.clone()))
    }

    fn guarded_load(&self, root: &str) -> Result<Option<StoreRecord>, StoreError> {
        self.with_authority_snapshot(|connection, _| {
            checkpoint::load_sqlite_record(connection, root)
        })
    }

    pub(super) fn native_effect_creation_replay(
        &self,
        root: &str,
        operation_id: &str,
        original: &Value,
    ) -> Result<Option<Value>, StoreError> {
        self.with_authority_snapshot(|connection, _| {
            let document: Option<Vec<u8>> = connection.query_row("SELECT document FROM determa_authority_effect_journals WHERE root_instance_id=?",[root],|row|row.get(0)).optional().map_err(error)?;
            let Some(bytes) = document else {
                if checkpoint::load_sqlite_record(connection,root)?.is_some() { return Err(error("existing root has no native effect participant")); }
                return Ok(None);
            };
            let document = strict_json::parse(&bytes).map_err(error)?;
            let checkpoint = checkpoint::load_sqlite_record(connection,root)?.ok_or_else(||error("native effect checkpoint absent"))?;
            let checkpoint = checkpoint::restore(&checkpoint.bytes,self.resolver.as_ref()).map_err(error)?;
            let responses = serde_json::from_value(document["responses"].clone()).map_err(error)?;
            crate::format1::effect_journal::ValidatedEffectJournal::restore(&canonical(&document["journal"]).map_err(error)?,&checkpoint,&self.scope,&responses,self.resolver.as_ref()).map_err(error)?;
            if document["original_requests"].get(operation_id) != Some(original) { return Err(error("operation_id_conflict")); }
            Ok(Some(document["responses"].get(operation_id).cloned().ok_or_else(||error("retained creation response absent"))?))
        })
    }

    pub(super) fn insert_native_effect_checkpoint(
        &self,
        checkpoint: &checkpoint::ExecutionCheckpoint,
        document: &Value,
        precommit: impl FnOnce() -> Result<(), super::AuthorityError>,
    ) -> Result<(), StoreError> {
        let checkpoint = checkpoint::restore(
            &checkpoint.canonical_bytes().map_err(error)?,
            self.resolver.as_ref(),
        )
        .map_err(error)?;
        super::validate_native_effect_document(document, checkpoint.value(), &self.scope)
            .map_err(error)?;
        let responses = serde_json::from_value(document["responses"].clone()).map_err(error)?;
        crate::format1::effect_journal::ValidatedEffectJournal::restore(
            &canonical(&document["journal"]).map_err(error)?,
            &checkpoint,
            &self.scope,
            &responses,
            self.resolver.as_ref(),
        )
        .map_err(error)?;
        let authority = self.authority_snapshot()?;
        let record = StoreRecord::from_checkpoint(&checkpoint)?;
        let mutation = json!({"native_mutation":"checkpoint_effect_journal","root_instance_id":record.root_instance_id,"expected_revision":null,"expected_checkpoint_digest":null,"checkpoint":checkpoint.value(),"effect_document":document});
        let mutation = canonical(&mutation).map_err(error)?;
        let operation_id = hash(&json!([
            "determa-authority-effect-creation-1",
            self.scope,
            authority["authority_epoch"],
            authority["scope_generation"],
            strict_json::parse(&mutation).map_err(error)?
        ]))
        .map_err(error)?;
        let mut request = json!({"interface":"determa.host_authority","interface_version":1,"operation":"guarded_commit","operation_id":operation_id,"scope_identity":self.scope,"expected_authority_epoch":"0","expected_scope_generation":authority["scope_generation"],"arguments":{"mutation_digest":format!("sha256:{:x}",<sha2::Sha256 as sha2::Digest>::digest(&mutation))}});
        request["request_digest"] =
            json!(hash(&json!(["determa-host-authority-request-1", request])).map_err(error)?);
        let result = self
            .authority
            .perform_native(
                &canonical(&request).map_err(error)?,
                &self.caller(),
                Some(&mutation),
                Some("checkpoint_effect_journal"),
                |transaction| {
                    super::apply_checkpoint(transaction, self.mode, &record, None)?;
                    transaction
                        .execute(
                            "INSERT INTO determa_authority_effect_journals VALUES (?,?,?)",
                            rusqlite::params![
                                record.root_instance_id,
                                self.scope,
                                canonical(document)?
                            ],
                        )
                        .map_err(super::failure)?;
                    precommit()
                },
            )
            .map_err(error)?;
        if result["status"] != "accepted" {
            return Err(error(format!(
                "native effect creation refused: {}",
                result["error_code"]
            )));
        }
        Ok(())
    }

    // Receiver-owned snapshot, not portable participant activation.
    pub(super) fn native_effect_snapshot(
        &self,
        root: &str,
    ) -> Result<(checkpoint::ExecutionCheckpoint, Value), StoreError> {
        self.with_authority_snapshot(|connection, _| {
            let bytes: Vec<u8> = connection.query_row(
                "SELECT document FROM determa_authority_effect_journals WHERE root_instance_id=? AND scope_identity=?",
                rusqlite::params![root, self.scope], |row| row.get(0),
            ).map_err(error)?;
            let document = strict_json::parse(&bytes).map_err(error)?;
            let record = checkpoint::load_sqlite_record(connection, root)?
                .ok_or_else(|| error("native effect checkpoint absent"))?;
            let restored = checkpoint::restore(&record.bytes, self.resolver.as_ref()).map_err(error)?;
            let responses = serde_json::from_value(document["responses"].clone()).map_err(error)?;
            crate::format1::effect_journal::ValidatedEffectJournal::restore(
                &canonical(&document["journal"]).map_err(error)?, &restored, &self.scope,
                &responses, self.resolver.as_ref(),
            ).map_err(error)?;
            Ok((restored, document))
        })
    }

    pub(super) fn update_native_effect_admission(
        &self,
        original_checkpoint: &checkpoint::ExecutionCheckpoint,
        original_document: &Value,
        candidate: &checkpoint::ExecutionCheckpoint,
        document: &Value,
        precommit: impl FnOnce() -> Result<(), super::AuthorityError>,
    ) -> Result<(), StoreError> {
        super::validate_native_effect_admission_transition(
            original_document,
            original_checkpoint.value(),
            document,
            candidate.value(),
            &self.scope,
        )
        .map_err(error)?;
        let responses = serde_json::from_value(document["responses"].clone()).map_err(error)?;
        crate::format1::effect_journal::ValidatedEffectJournal::restore(
            &canonical(&document["journal"]).map_err(error)?,
            candidate,
            &self.scope,
            &responses,
            self.resolver.as_ref(),
        )
        .map_err(error)?;
        let authority = self.authority_snapshot()?;
        let record = StoreRecord::from_checkpoint(candidate)?;
        let mutation = json!({"native_mutation":"checkpoint_effect_journal",
            "root_instance_id":record.root_instance_id,
            "expected_revision":original_checkpoint.revision(),
            "expected_checkpoint_digest":original_checkpoint.digest(),
            "checkpoint":candidate.value(),"effect_document":document});
        let mutation = canonical(&mutation).map_err(error)?;
        let operation_id = hash(&json!([
            "determa-authority-effect-admission-1",
            self.scope,
            authority["authority_epoch"],
            authority["scope_generation"],
            strict_json::parse(&mutation).map_err(error)?
        ]))
        .map_err(error)?;
        let mut request = json!({"interface":"determa.host_authority","interface_version":1,
            "operation":"guarded_commit","operation_id":operation_id,"scope_identity":self.scope,
            "expected_authority_epoch":"0","expected_scope_generation":authority["scope_generation"],
            "arguments":{"mutation_digest":format!("sha256:{:x}",<sha2::Sha256 as sha2::Digest>::digest(&mutation))}});
        request["request_digest"] =
            json!(hash(&json!(["determa-host-authority-request-1", request])).map_err(error)?);
        let result = self.authority.perform_native(
            &canonical(&request).map_err(error)?, &self.caller(), Some(&mutation),
            Some("checkpoint_effect_journal"), |transaction| {
                checkpoint::verify_sqlite_schema(transaction,self.mode).map_err(super::failure)?;
                let current = checkpoint::load_sqlite_record(transaction,&record.root_instance_id)
                    .map_err(super::failure)?.ok_or_else(||super::failure("native checkpoint absent"))?;
                if current.bytes != original_checkpoint.canonical_bytes().map_err(super::failure)? {
                    return Err(super::failure("checkpoint_revision_conflict"));
                }
                let old = canonical(original_document)?;
                let actual: Vec<u8> = transaction.query_row(
                    "SELECT document FROM determa_authority_effect_journals WHERE root_instance_id=? AND scope_identity=?",
                    rusqlite::params![record.root_instance_id,self.scope],|row|row.get(0),
                ).map_err(super::failure)?;
                if actual != old { return Err(super::failure("effect_journal_revision_conflict")); }
                if current.bytes != record.bytes {
                    checkpoint::validate_policy_replacement(self.mode,&current,&record).map_err(super::failure)?;
                    let changed = transaction.execute(
                        "UPDATE determa_execution_checkpoints SET revision=?,checkpoint_digest=?,checkpoint_bytes=? WHERE root_instance_id=? AND revision=? AND checkpoint_digest=?",
                        rusqlite::params![record.revision,record.execution_checkpoint_digest,record.bytes,
                            record.root_instance_id,current.revision,current.execution_checkpoint_digest],
                    ).map_err(super::failure)?;
                    if changed != 1 { return Err(super::failure("checkpoint_revision_conflict")); }
                }
                let changed = transaction.execute(
                    "UPDATE determa_authority_effect_journals SET document=? WHERE root_instance_id=? AND scope_identity=? AND document=?",
                    rusqlite::params![canonical(document)?,record.root_instance_id,self.scope,old],
                ).map_err(super::failure)?;
                if changed != 1 { return Err(super::failure("effect_journal_revision_conflict")); }
                precommit()
            },
        ).map_err(error)?;
        if result["status"] != "accepted" {
            return Err(error(format!(
                "native admission refused: {}",
                result["error_code"]
            )));
        }
        Ok(())
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
                StoreWriteResult::Conflict(self.guarded_load(&record.root_instance_id)?),
            ),
            Ok(result) => Err(error(format!(
                "authority refused checkpoint commit: {}",
                result["error_code"]
            ))),
            Err(failure) if failure.to_string() == "checkpoint_revision_conflict" => Ok(
                StoreWriteResult::Conflict(self.guarded_load(&record.root_instance_id)?),
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
        self.guarded_load(root)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{load_bundle, Bindings, InMemoryDefinitionResolver};
    use std::sync::atomic::{AtomicU64, Ordering};

    #[test]
    fn guarded_read_keeps_validated_bytes_when_native_writer_commits_between_checks_and_read() {
        static SEQUENCE: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "determa-authority-snapshot-{}-{}.sqlite",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let bundle = load_bundle(
            &json!({"format":1,"namespace":"authority.snapshot.tests",
            "machines":[{"machine_id":"simple","root":{"type":"composite",
                "initial":{"transition_to":"waiting"},"states":{"waiting":{}}}}]})
            .to_string(),
        )
        .unwrap();
        let mut resolver = InMemoryDefinitionResolver::default();
        resolver.insert(bundle.clone(), true);
        let resolver = Arc::new(resolver);
        let store = Arc::new(
            GuardedSqliteExecutionStore::open(
                &path,
                DurableStoreMode::bounded(),
                "scope".into(),
                "owner".into(),
                "local-host".into(),
                resolver.clone(),
            )
            .unwrap(),
        );
        store.initialize_schema().unwrap();
        store.allocate_scope().unwrap();
        let host = checkpoint::CheckpointHost::new(store.clone(), resolver);
        host.create_checkpoint(&bundle, "simple", "root", "create", &Bindings::default(), None,
            json!({"mode":"bounded","permanent_replay_eligible":false,"pruned_through_receipt_sequence":null,"policy_identifier":"test-bounded"})).unwrap();
        let original = store.load("root").unwrap().unwrap();
        let captured = store.with_authority_snapshot(|connection, _| {
            // A separate native writer actually commits AFTER complete authority
            // validation, BEFORE the consuming read, while the WAL reader remains open.
            let writer_path = path.clone();
            std::thread::spawn(move || {
                let writer = rusqlite::Connection::open(writer_path).unwrap();
                writer.execute("UPDATE determa_execution_checkpoints SET checkpoint_bytes=? WHERE root_instance_id='root'",
                    [b"unchecked replacement".as_slice()]).unwrap();
            }).join().unwrap();
            checkpoint::load_sqlite_record(connection, "root")
        }).unwrap().unwrap();
        assert_eq!(captured, original);
        // The next snapshot sees the corruption and refuses; it never silently
        // repairs the native writer's untracked change.
        assert!(store.load("root").is_err());
        drop(host);
        drop(store);
        std::fs::remove_file(path).unwrap();
    }
}

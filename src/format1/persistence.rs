use super::compile::Bundle;
use std::collections::BTreeMap;

#[derive(Debug, Clone)]
pub struct ResolvedDefinition {
    pub bundle: Bundle,
    pub trusted: bool,
}

#[derive(Debug, Clone)]
pub struct ResolvedMigrationDescriptor {
    pub bytes: Vec<u8>,
    pub trusted: bool,
}

pub trait DefinitionResolver {
    fn resolve_definition(&self, validated_bundle_fingerprint: &str) -> Option<ResolvedDefinition>;
}

pub trait MigrationArtifactResolver: DefinitionResolver {
    fn resolve_migration_descriptor(
        &self,
        migration_descriptor_digest: &str,
    ) -> Option<ResolvedMigrationDescriptor>;
}

#[derive(Debug, Clone, Default)]
pub struct InMemoryDefinitionResolver {
    definitions: BTreeMap<String, ResolvedDefinition>,
    descriptors: BTreeMap<String, ResolvedMigrationDescriptor>,
}

impl InMemoryDefinitionResolver {
    pub fn insert(&mut self, bundle: Bundle, trusted: bool) -> bool {
        let fingerprint = bundle.fingerprint.clone();
        self.insert_at(fingerprint, bundle, trusted)
    }

    pub fn insert_at(
        &mut self,
        fingerprint: impl Into<String>,
        bundle: Bundle,
        trusted: bool,
    ) -> bool {
        let fingerprint = fingerprint.into();
        if self.definitions.contains_key(&fingerprint) {
            return false;
        }
        self.definitions
            .insert(fingerprint, ResolvedDefinition { bundle, trusted });
        true
    }

    pub fn get(&self, fingerprint: &str) -> Option<&ResolvedDefinition> {
        self.definitions.get(fingerprint)
    }

    pub fn descriptor(&self, digest: &str) -> Option<&ResolvedMigrationDescriptor> {
        self.descriptors.get(digest)
    }

    pub fn definitions(&self) -> impl Iterator<Item = (&String, &ResolvedDefinition)> {
        self.definitions.iter()
    }

    pub fn descriptors(&self) -> impl Iterator<Item = (&String, &ResolvedMigrationDescriptor)> {
        self.descriptors.iter()
    }

    pub fn insert_descriptor(
        &mut self,
        digest: impl Into<String>,
        bytes: Vec<u8>,
        trusted: bool,
    ) -> bool {
        let digest = digest.into();
        if self.descriptors.contains_key(&digest) {
            return false;
        }
        self.descriptors
            .insert(digest, ResolvedMigrationDescriptor { bytes, trusted });
        true
    }
}

impl MigrationArtifactResolver for InMemoryDefinitionResolver {
    fn resolve_migration_descriptor(
        &self,
        migration_descriptor_digest: &str,
    ) -> Option<ResolvedMigrationDescriptor> {
        self.descriptors.get(migration_descriptor_digest).cloned()
    }
}

impl DefinitionResolver for InMemoryDefinitionResolver {
    fn resolve_definition(&self, validated_bundle_fingerprint: &str) -> Option<ResolvedDefinition> {
        self.definitions.get(validated_bundle_fingerprint).cloned()
    }
}

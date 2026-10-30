use super::*;
use fogvault_backup::{
    CompletedImport, FreshImportPermit, Identity, Observation, Policy, RecordData, SourceSnapshot,
};
use sha2::{Digest, Sha256};
use std::{io, str::FromStr};

fn io_error(_: io::Error) -> JsValue {
    error(Error::Integrity)
}
fn number(value: &JsValue, field: &str, positive: bool) -> Result<u32, JsValue> {
    let number = Reflect::get(value, &JsValue::from_str(field))
        .map_err(|_| error("invalid backup policy"))?
        .as_f64()
        .ok_or_else(|| error("backup policy requires finite integers"))?;
    if !number.is_finite()
        || number.fract() != 0.0
        || number < if positive { 1.0 } else { 0.0 }
        || number > u32::MAX as f64
    {
        return Err(error(Error::ResourceLimit));
    }
    Ok(number as u32)
}
fn policy(value: &JsValue) -> Result<Policy, JsValue> {
    let policy = Policy {
        header_bytes: number(value, "headerBytes", true)? as usize,
        stanzas: number(value, "stanzas", true)? as usize,
        ciphertext_bytes: number(value, "ciphertextBytes", true)? as u64,
        total_plaintext_bytes: number(value, "totalPlaintextBytes", true)? as u64,
        records: number(value, "records", false)? as u64,
        schema_bytes: number(value, "schemaBytes", false)? as u64,
        metadata_bytes: number(value, "metadataBytes", false)? as u64,
        payload_bytes: number(value, "payloadBytes", false)? as u64,
    };
    if policy.collection_data_bytes().map_err(io_error)?
        > number(value, "collectionBytes", true)? as u64
    {
        return Err(error(Error::ResourceLimit));
    }
    Ok(policy)
}
fn source(engine: &Engine) -> Result<SourceSnapshot, JsValue> {
    let receipt = engine.current_receipt().map_err(error)?;
    let count = u64::from_be_bytes(
        engine.head_bytes()[56..64]
            .try_into()
            .map_err(|_| error(Error::Integrity))?,
    );
    Ok(SourceSnapshot::new(
        engine.vault_id(),
        Sha256::digest(engine.descriptor_bytes()).into(),
        receipt.head_digest,
        receipt.generation,
        count,
    ))
}
fn source_matches(engine: &Engine, expected: &SourceSnapshot) -> Result<(), JsValue> {
    if source(engine)? != *expected {
        return Err(error(Error::Conflict));
    }
    Ok(())
}
pub(super) struct Export {
    source: SourceSnapshot,
    recipient: fogvault_backup::Recipient,
    policy: Policy,
    records: Vec<RecordData>,
    plaintext: u64,
}

#[wasm_bindgen]
impl BrowserSession {
    pub fn begin_backup_export(
        &mut self,
        recipient: &str,
        parameters: JsValue,
    ) -> Result<(), JsValue> {
        if self.backup_export.is_some() {
            return Err(error(Error::Conflict));
        }
        let policy = policy(&parameters)?;
        let source = source(&self.engine)?;
        if source.records() > policy.records {
            return Err(error(Error::ResourceLimit));
        }
        let recipient = fogvault_backup::Recipient::from_str(recipient)
            .map_err(|_| error("invalid age recipient"))?;
        self.backup_export = Some(Export {
            source,
            recipient,
            policy,
            records: vec![],
            plaintext: 0,
        });
        Ok(())
    }
    pub fn backup_export_record(
        &mut self,
        identity: &[u8],
        stored_revision: JsValue,
        envelope: &[u8],
        nodes: JsValue,
    ) -> Result<(), JsValue> {
        let identity = id(identity)?;
        let revision =
            expected_revision(&stored_revision)?.ok_or_else(|| error(Error::Integrity))?;
        let mut cache = Cache::parse(nodes, MAX_PATH_NODES)?;
        let proof = self.engine.lookup(&mut cache, &identity).map_err(error)?;
        let proof = proof.entry().ok_or_else(|| error(Error::Integrity))?;
        let pending = self
            .backup_export
            .as_mut()
            .ok_or_else(|| error(Error::Conflict))?;
        source_matches(&self.engine, &pending.source)?;
        if pending.records.len() as u64 >= pending.source.records()
            || pending
                .records
                .last()
                .is_some_and(|record| record.id >= identity)
        {
            return Err(error(Error::Integrity));
        }
        let record = self
            .engine
            .read_verified(proof, revision, envelope)
            .map_err(error)?;
        let size = record
            .metadata
            .len()
            .checked_add(record.payload.len())
            .and_then(|n| n.checked_add(45))
            .ok_or_else(|| error(Error::ResourceLimit))? as u64;
        let total = pending
            .plaintext
            .checked_add(size)
            .ok_or_else(|| error(Error::ResourceLimit))?;
        if total
            .checked_add(145)
            .is_none_or(|n| n > pending.policy.total_plaintext_bytes)
            || record.metadata.len() as u64 > pending.policy.metadata_bytes
            || record.payload.len() as u64 > pending.policy.payload_bytes
        {
            return Err(error(Error::ResourceLimit));
        }
        pending.plaintext = total;
        pending.records.push(RecordData {
            id: identity,
            revision,
            schema: Zeroizing::new(vec![]),
            metadata: record.metadata,
            payload: record.payload,
        });
        Ok(())
    }
    pub fn finish_backup_export(&mut self) -> Result<JsValue, JsValue> {
        let pending = self
            .backup_export
            .take()
            .ok_or_else(|| error(Error::Conflict))?;
        source_matches(&self.engine, &pending.source)?;
        let header = *pending.source.header();
        let mut ciphertext = vec![];
        let receipt = fogvault_backup::export_snapshot(
            pending.source,
            pending.records.into_iter().map(Ok),
            &mut ciphertext,
            &pending.recipient,
            pending.policy,
            &mut Observation::default(),
        )
        .map_err(io_error)?;
        let result = Object::new();
        set(&result, "ciphertext", array_bytes(&ciphertext));
        set(&result, "source_header", array_bytes(&header));
        set(
            &result,
            "ciphertext_sha256",
            array_bytes(&receipt.ciphertext_sha256),
        );
        set(
            &result,
            "ciphertext_bytes",
            BigInt::from(receipt.ciphertext_bytes),
        );
        Ok(result.into())
    }
    pub fn cancel_backup_export(&mut self) {
        self.backup_export = None;
    }
}

/// Private new-vault builder. No plaintext read/session API exists on this type.
#[wasm_bindgen]
pub struct BrowserImport {
    engine: Option<Engine>,
    stage: protective::Stage,
    completed: CompletedImport,
}
#[wasm_bindgen]
impl BrowserImport {
    #[allow(clippy::too_many_arguments)]
    pub fn prepare(
        ciphertext: JsValue,
        secret_identity: JsValue,
        source_header: &[u8],
        trusted_digest: JsValue,
        owner_accepted_unverified: bool,
        new_password: JsValue,
        max_payload: u32,
        max_metadata: u32,
        max_records: u32,
        kdf_profiles: JsValue,
        parameters: JsValue,
        maximum_staging_bytes: u32,
        import_request: &[u8],
    ) -> Result<BrowserImport, JsValue> {
        let policy = policy(&parameters)?;
        let ciphertext = bytes(&ciphertext, policy.ciphertext_bytes as usize)?;
        let identity_bytes = password_bytes(secret_identity)?;
        let identity = Identity::from_str(
            std::str::from_utf8(&identity_bytes).map_err(|_| error("invalid age identity text"))?,
        )
        .map_err(|_| error("invalid age identity"))?;
        let source_header: [u8; 104] = source_header
            .try_into()
            .map_err(|_| error("source header width"))?;
        let source = SourceSnapshot::from_header(source_header).map_err(io_error)?;
        let password = password_bytes(new_password)?;
        let limits = Limits {
            max_payload_bytes: max_payload as usize,
            max_metadata_bytes: max_metadata as usize,
            max_records: max_records as usize,
        };
        let mut engine =
            Engine::create_with_kdf_policy(&password, limits, kdf_policy(kdf_profiles)?)
                .map_err(error)?;
        let permit = if trusted_digest.is_null() || trusted_digest.is_undefined() {
            if !owner_accepted_unverified {
                return Err(error("explicit import origin approval required"));
            }
            FreshImportPermit::owner_accepted_unverified(source, engine.vault_id())
                .map_err(io_error)?
        } else {
            if owner_accepted_unverified {
                return Err(error("ambiguous import origin approval"));
            }
            let digest = bytes(&trusted_digest, 32)?;
            let digest: [u8; 32] = digest
                .try_into()
                .map_err(|_| error("ciphertext receipt width"))?;
            FreshImportPermit::origin_checked(source, digest, engine.vault_id())
                .map_err(io_error)?
        };
        let stage_identity = Identity::generate();
        let mut encrypted_stage = vec![];
        let completed = fogvault_backup::stage_import(
            ciphertext.as_slice(),
            &identity,
            &stage_identity.to_public(),
            &mut encrypted_stage,
            &permit,
            policy,
            &mut Observation::default(),
        )
        .map_err(io_error)?;
        let records = fogvault_backup::read_staged_records(
            encrypted_stage.as_slice(),
            &stage_identity,
            &completed,
            engine.vault_id(),
            policy,
        )
        .map_err(io_error)?;
        if maximum_staging_bytes == 0 || records.len() > limits.max_records {
            return Err(error(Error::ResourceLimit));
        }
        let mut stage = protective::Stage {
            nodes: BTreeMap::new(),
            records: BTreeMap::new(),
            bytes: 0,
            maximum: maximum_staging_bytes as usize,
        };
        // Authority stays inside this private builder until actual target publication.
        engine.activate_created().map_err(error)?;
        for record in records {
            if !record.schema.is_empty() {
                return Err(error(Error::UnsupportedCapability));
            }
            let request: [u8; 16] = Sha256::digest(record.id)[..16]
                .try_into()
                .map_err(|_| error(Error::Integrity))?;
            let plan = engine
                .prepare_save(
                    &mut stage,
                    record.id,
                    None,
                    &record.metadata,
                    &record.payload,
                    request,
                    None,
                )
                .map_err(error)?;
            for hash in &plan.obsolete {
                if let Some(body) = stage.nodes.remove(hash) {
                    stage.bytes -= body.len() + 32;
                }
            }
            stage.admit(plan.envelope.len() + 24).map_err(error)?;
            stage.bytes += plan.envelope.len() + 24;
            stage
                .records
                .insert(record.id, (plan.revision, plan.envelope));
            engine.confirm_commit(&plan.head_bytes).map_err(error)?;
        }
        let draft = engine
            .draft_password_change(&password, &password, id(import_request)?)
            .map_err(error)?;
        let credential = engine.stage_credential_change(&draft).map_err(error)?;
        engine
            .confirm_credential_commit(&credential.descriptor_bytes, &credential.head_bytes)
            .map_err(error)?;
        Ok(Self {
            engine: Some(engine),
            stage,
            completed,
        })
    }
    pub fn descriptor(&self) -> Result<Vec<u8>, JsValue> {
        Ok(self
            .engine
            .as_ref()
            .ok_or_else(|| error(Error::Conflict))?
            .descriptor_bytes()
            .to_vec())
    }
    pub fn head(&self) -> Result<Vec<u8>, JsValue> {
        Ok(self
            .engine
            .as_ref()
            .ok_or_else(|| error(Error::Conflict))?
            .head_bytes()
            .to_vec())
    }
    pub fn next_write(&mut self) -> Result<JsValue, JsValue> {
        let result = Object::new();
        if let Some((hash, body)) = self.stage.nodes.pop_first() {
            set(&result, "kind", "node");
            set(&result, "hash", array_bytes(&hash));
            set(&result, "bytes", array_bytes(&body));
        } else if let Some((identity, (revision, body))) = self.stage.records.pop_first() {
            set(&result, "kind", "record");
            set(&result, "id", array_bytes(&identity));
            set(&result, "revision", BigInt::from(revision));
            set(&result, "bytes", array_bytes(&body));
        } else {
            set(&result, "kind", "done");
        }
        Ok(result.into())
    }
    pub fn confirm(&mut self) -> Result<BrowserSession, JsValue> {
        if !self.stage.nodes.is_empty() || !self.stage.records.is_empty() {
            return Err(error(Error::Conflict));
        }
        let engine = self.engine.take().ok_or_else(|| error(Error::Conflict))?;
        Ok(BrowserSession {
            engine,
            inventory: None,
            protective: None,
            creation_recovery: None,
            backup_export: None,
            async_unlock: None,
            async_access: None,
            async_protective: None,
            provider_blob_limit: 0,
        })
    }
    pub fn source_header(&self) -> Vec<u8> {
        self.completed.source().header().to_vec()
    }
    pub fn origin_verified(&self) -> bool {
        self.completed.origin_verified()
    }
}

#[wasm_bindgen]
pub fn backup_identity() -> JsValue {
    let identity = Identity::generate();
    let secret = fogvault_backup::export_identity(&identity);
    let result = Object::new();
    set(&result, "identity", array_bytes(secret.as_bytes()));
    set(&result, "recipient", identity.to_public().to_string());
    result.into()
}

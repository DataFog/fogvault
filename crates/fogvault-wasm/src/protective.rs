use super::*;
use fogvault::{
    AccessAdmission, AccessProfile, KeyProvider, ProtectivePlan, ProtectiveSource,
    ProtectiveTransition, ProviderCapabilityKind, ProviderContext, ProviderError, ProviderIdentity,
    ProviderResult, RecoveryKey, TransitionStore, UnanchoredProtectiveControl,
};
use std::collections::BTreeSet;

pub(super) fn admission() -> AccessAdmission {
    AccessAdmission {
        allowed_profiles: vec![AccessProfile::Portable],
        providers: vec![],
        max_descriptor_bytes: 180 + 96,
        max_device_slots: 0,
        max_provider_blob_bytes: 0,
    }
}
struct NoDevice;
impl KeyProvider for NoDevice {
    fn capability_kind(&self, _: &ProviderIdentity) -> ProviderCapabilityKind {
        ProviderCapabilityKind::NonExportableOperation
    }
    fn wrap_seed(&mut self, _: &ProviderContext, _: &[u8; 32]) -> ProviderResult<Vec<u8>> {
        Err(ProviderError::Unsupported)
    }
    fn unwrap_seed(
        &mut self,
        _: &ProviderContext,
        _: &[u8],
    ) -> ProviderResult<Zeroizing<[u8; 32]>> {
        Err(ProviderError::Unsupported)
    }
}
pub(super) struct Stage {
    pub(super) nodes: BTreeMap<NodeHash, Vec<u8>>,
    pub(super) records: BTreeMap<RecordId, (u64, Vec<u8>)>,
    pub(super) bytes: usize,
    pub(super) maximum: usize,
}
impl Stage {
    pub(super) fn admit(&self, additional: usize) -> fogvault::Result<()> {
        if self
            .bytes
            .checked_add(additional)
            .ok_or(Error::ResourceLimit)?
            > self.maximum
        {
            return Err(Error::ResourceLimit);
        }
        Ok(())
    }
    pub(super) fn retain_reachable(&mut self, root: Option<NodeHash>) -> fogvault::Result<()> {
        let mut wanted = root.into_iter().collect::<Vec<_>>();
        let mut seen = BTreeSet::new();
        while let Some(hash) = wanted.pop() {
            if !seen.insert(hash) {
                return Err(Error::Integrity);
            }
            let body = self.nodes.get(&hash).ok_or(Error::Integrity)?;
            match body.as_slice() {
                [0, ..] if body.len() == 57 => {}
                [1, ..] if body.len() == 82 => {
                    wanted.push(body[18..50].try_into().map_err(|_| Error::Integrity)?);
                    wanted.push(body[50..82].try_into().map_err(|_| Error::Integrity)?);
                }
                _ => return Err(Error::Integrity),
            }
        }
        self.nodes.retain(|hash, _| seen.contains(hash));
        Ok(())
    }
}
impl NodeStore for Stage {
    fn get(&mut self, hash: &NodeHash) -> fogvault::Result<Option<Vec<u8>>> {
        Ok(self.nodes.get(hash).cloned())
    }
    fn put(&mut self, hash: NodeHash, body: &[u8]) -> fogvault::Result<()> {
        if let Some(old) = self.nodes.get(&hash) {
            return if old == body {
                Ok(())
            } else {
                Err(Error::Integrity)
            };
        }
        self.admit(32 + body.len())?;
        self.bytes += 32 + body.len();
        self.nodes.insert(hash, body.to_vec());
        Ok(())
    }
}
impl TransitionStore for Stage {
    fn staged_record(
        &mut self,
        id: &RecordId,
        maximum: usize,
    ) -> fogvault::Result<Option<(u64, Vec<u8>)>> {
        if let Some((revision, data)) = self.records.get(id) {
            if data.len() > maximum {
                return Err(Error::ResourceLimit);
            }
            Ok(Some((*revision, data.clone())))
        } else {
            Ok(None)
        }
    }
}
pub(super) struct Preparation {
    transition: ProtectiveTransition,
    control: UnanchoredProtectiveControl,
    stage: Stage,
    plan: Option<ProtectivePlan>,
    recovery: Option<Zeroizing<Vec<u8>>>,
}

impl BrowserSession {
    pub(super) fn install_protective(
        &mut self,
        transition: ProtectiveTransition,
        recovery: Option<RecoveryKey>,
        maximum_staging_bytes: u32,
    ) -> Result<(), JsValue> {
        if self.protective.is_some() || maximum_staging_bytes == 0 {
            return Err(error(Error::Conflict));
        }
        let control = transition.unanchored_control(&self.engine).map_err(error)?;
        self.protective = Some(Preparation {
            transition,
            control,
            stage: Stage {
                nodes: BTreeMap::new(),
                records: BTreeMap::new(),
                bytes: 0,
                maximum: maximum_staging_bytes as usize,
            },
            plan: None,
            recovery: recovery.map(|key| key.export()),
        });
        Ok(())
    }
}

#[wasm_bindgen]
impl BrowserSession {
    pub fn create_with_recovery(
        password: JsValue,
        max_payload: u32,
        max_metadata: u32,
        max_records: u32,
        profiles: JsValue,
    ) -> Result<BrowserSession, JsValue> {
        let password = password_bytes(password)?;
        let limits = Limits {
            max_payload_bytes: max_payload as usize,
            max_metadata_bytes: max_metadata as usize,
            max_records: max_records as usize,
        };
        let (engine, key) = Engine::create_with_access(
            &password,
            limits,
            kdf_policy(profiles)?,
            admission(),
            AccessProfile::Portable,
            &[],
            true,
            &mut NoDevice,
        )
        .map_err(error)?;
        Ok(Self {
            engine,
            inventory: None,
            protective: None,
            creation_recovery: key.map(|key| key.export()),
            backup_export: None,
            async_unlock: None,
            async_access: None,
            async_protective: None,
            provider_blob_limit: 0,
        })
    }
    pub fn take_created_recovery(&mut self) -> Result<JsValue, JsValue> {
        self.engine.current_receipt().map_err(error)?;
        Ok(self
            .creation_recovery
            .take()
            .map(|key| array_bytes(&key))
            .unwrap_or(JsValue::NULL))
    }
    pub fn begin_recovery(
        descriptor: &[u8],
        key: JsValue,
        max_payload: u32,
        max_metadata: u32,
        max_records: u32,
        profiles: JsValue,
    ) -> Result<BrowserSession, JsValue> {
        let bytes = password_bytes(key)?;
        let key = RecoveryKey::import(&bytes).map_err(error)?;
        let limits = Limits {
            max_payload_bytes: max_payload as usize,
            max_metadata_bytes: max_metadata as usize,
            max_records: max_records as usize,
        };
        let mut engine =
            Engine::open_with_access(descriptor, limits, kdf_policy(profiles)?, admission())
                .map_err(error)?;
        engine.begin_recovery(&key).map_err(error)?;
        Ok(Self {
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
    pub fn begin_protective_replacement(
        &mut self,
        old_password: JsValue,
        recovery_key: JsValue,
        new_password: JsValue,
        request: &[u8],
        maximum_staging_bytes: u32,
    ) -> Result<(), JsValue> {
        if self.protective.is_some() || maximum_staging_bytes == 0 {
            return Err(error(Error::Conflict));
        }
        let new_password = password_bytes(new_password)?;
        let (transition, recovery) = if recovery_key.is_null() || recovery_key.is_undefined() {
            let old = password_bytes(old_password)?;
            self.engine
                .draft_protective_transition(
                    ProtectiveSource::Password(&old),
                    &new_password,
                    AccessProfile::Portable,
                    &[],
                    true,
                    &mut NoDevice,
                    admission(),
                    id(request)?,
                )
                .map_err(error)?
        } else {
            let bytes = password_bytes(recovery_key)?;
            let key = RecoveryKey::import(&bytes).map_err(error)?;
            self.engine
                .draft_recovery_replacement(
                    &key,
                    &new_password,
                    AccessProfile::Portable,
                    &[],
                    true,
                    &mut NoDevice,
                    admission(),
                    id(request)?,
                )
                .map_err(error)?
        };
        self.install_protective(transition, recovery, maximum_staging_bytes)
    }
    pub fn transform_protective_record(
        &mut self,
        identity: &[u8],
        revision: JsValue,
        envelope: &[u8],
        nodes: JsValue,
    ) -> Result<(), JsValue> {
        let identity = id(identity)?;
        let revision = expected_revision(&revision)?.ok_or_else(|| error(Error::Integrity))?;
        let mut source = Cache::parse(nodes, MAX_PATH_NODES)?;
        let lookup = self
            .engine
            .protective_lookup(&mut source, &identity)
            .map_err(error)?;
        let proof = lookup.entry().ok_or_else(|| error(Error::Integrity))?;
        let prepared = self
            .protective
            .as_mut()
            .ok_or_else(|| error(Error::Conflict))?;
        if prepared.plan.is_some() || prepared.stage.records.contains_key(&identity) {
            return Err(error(Error::Conflict));
        }
        prepared
            .stage
            .admit(
                envelope
                    .len()
                    .checked_add(24)
                    .ok_or_else(|| error(Error::ResourceLimit))?,
            )
            .map_err(error)?;
        let transformed = prepared
            .transition
            .transform_unanchored_record(
                &self.engine,
                proof,
                revision,
                envelope,
                &mut prepared.stage,
                &prepared.control,
            )
            .map_err(error)?;
        prepared
            .stage
            .admit(transformed.len() + 24)
            .map_err(error)?;
        prepared.stage.bytes += transformed.len() + 24;
        prepared
            .stage
            .records
            .insert(identity, (revision, transformed));
        Ok(())
    }
    pub fn finish_protective_replacement(&mut self) -> Result<JsValue, JsValue> {
        let prepared = self
            .protective
            .as_mut()
            .ok_or_else(|| error(Error::Conflict))?;
        if prepared.plan.is_some() {
            return Err(error(Error::Conflict));
        }
        let plan = prepared
            .transition
            .finish_unanchored(&self.engine, &mut prepared.stage, &prepared.control)
            .map_err(error)?;
        prepared
            .stage
            .retain_reachable(plan.index_root)
            .map_err(error)?;
        let result = Object::new();
        set(
            &result,
            "prior_descriptor",
            array_bytes(&plan.prior_descriptor),
        );
        set(&result, "prior_head", array_bytes(&plan.prior_head));
        set(&result, "descriptor", array_bytes(&plan.descriptor_bytes));
        set(&result, "head", array_bytes(&plan.head_bytes));
        set(&result, "receipt", Self::receipt(&plan.receipt));
        set(&result, "records", BigInt::from(plan.record_count));
        set(&result, "key_effect", "FreshRootAndContentKeys");
        set(&result, "anchoring", "unanchored");
        prepared.control = prepared
            .control
            .authorize_submission(&prepared.transition, &plan)
            .map_err(error)?;
        self.engine
            .authorize_unanchored_protective_submission(
                &prepared.transition,
                &plan,
                &prepared.control,
            )
            .map_err(error)?;
        prepared.plan = Some(plan);
        Ok(result.into())
    }
    /// One bounded ciphertext object per call; used inside one publication TX.
    pub fn next_protective_write(&mut self) -> Result<JsValue, JsValue> {
        let prepared = self
            .protective
            .as_mut()
            .ok_or_else(|| error(Error::Conflict))?;
        if prepared.plan.is_none() {
            return Err(error(Error::Conflict));
        }
        let result = Object::new();
        if let Some((hash, body)) = prepared.stage.nodes.pop_first() {
            set(&result, "kind", "node");
            set(&result, "hash", array_bytes(&hash));
            set(&result, "bytes", array_bytes(&body));
        } else if let Some((identity, (revision, body))) = prepared.stage.records.pop_first() {
            set(&result, "kind", "record");
            set(&result, "id", array_bytes(&identity));
            set(&result, "revision", BigInt::from(revision));
            set(&result, "bytes", array_bytes(&body));
        } else {
            set(&result, "kind", "done");
        }
        Ok(result.into())
    }
    pub fn confirm_protective_replacement(
        &mut self,
        descriptor: &[u8],
        head: &[u8],
    ) -> Result<JsValue, JsValue> {
        self.inventory = None;
        let prepared = self
            .protective
            .take()
            .ok_or_else(|| error(Error::Conflict))?;
        let plan = prepared
            .plan
            .as_ref()
            .ok_or_else(|| error(Error::Conflict))?;
        if !prepared.stage.nodes.is_empty() || !prepared.stage.records.is_empty() {
            return Err(error(Error::Conflict));
        }
        let completed = prepared
            .control
            .confirm_target(&prepared.transition, plan)
            .map_err(error)?;
        let receipt = self
            .engine
            .confirm_unanchored_protective_transition(
                prepared.transition,
                &completed,
                descriptor,
                head,
            )
            .map_err(error)?;
        let result = Object::new();
        set(&result, "receipt", Self::receipt(&receipt.receipt));
        set(&result, "key_effect", "FreshRootAndContentKeys");
        set(&result, "anchoring", "unanchored");
        set(
            &result,
            "recovery_key",
            prepared
                .recovery
                .map(|key| array_bytes(&key))
                .unwrap_or(JsValue::NULL),
        );
        Ok(result.into())
    }
}

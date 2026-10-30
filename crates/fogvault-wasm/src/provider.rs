use super::*;
use fogvault::{
    AccessAdmission, AccessProfile, AsyncCreation, ProviderCapabilityKind, ProviderError,
    ProviderIdentity, ProviderReply, ProviderRequest,
};

fn property(value: &JsValue, key: &str) -> Result<JsValue, JsValue> {
    Reflect::get(value, &JsValue::from_str(key)).map_err(|_| error("invalid access policy"))
}
fn integer(value: &JsValue, key: &str) -> Result<usize, JsValue> {
    let n = property(value, key)?
        .as_f64()
        .ok_or_else(|| error("access policy integer required"))?;
    if !n.is_finite() || n.fract() != 0.0 || n < 0.0 || n > u32::MAX as f64 {
        return Err(error(Error::ResourceLimit));
    }
    Ok(n as usize)
}
fn identity(value: &JsValue) -> Result<ProviderIdentity, JsValue> {
    Ok(ProviderIdentity {
        provider_id: id(&bytes(&property(value, "providerId")?, 16)?)?,
        key_id: id(&bytes(&property(value, "keyId")?, 16)?)?,
        device_bound: property(value, "deviceBound")?
            .as_bool()
            .ok_or_else(|| error("deviceBound boolean required"))?,
        nonexportable: property(value, "nonexportable")?
            .as_bool()
            .ok_or_else(|| error("nonexportable boolean required"))?,
    })
}
pub(super) fn profile(value: &str) -> Result<AccessProfile, JsValue> {
    match value {
        "password" => Ok(AccessProfile::Portable),
        "password-or-device" => Ok(AccessProfile::PasswordOrDevice),
        "password-and-device" => Ok(AccessProfile::PasswordAndDevice),
        _ => Err(error(Error::UnsupportedCapability)),
    }
}
pub(super) fn admission(value: &JsValue) -> Result<AccessAdmission, JsValue> {
    let max_descriptor_bytes = integer(value, "maxDescriptorBytes")?;
    let max_device_slots = integer(value, "maxDeviceSlots")?;
    let max_provider_blob_bytes = integer(value, "maxProviderBlobBytes")?;
    let profiles = property(value, "profiles")?;
    let profiles = profiles
        .dyn_ref::<Array>()
        .ok_or_else(|| error("access profiles array required"))?;
    if profiles.length() > 3 {
        return Err(error(Error::UnsupportedCapability));
    }
    let mut allowed_profiles = vec![];
    for item in profiles.iter() {
        let next = profile(
            &item
                .as_string()
                .ok_or_else(|| error("access profile text required"))?,
        )?;
        if allowed_profiles.contains(&next) {
            return Err(error(Error::UnsupportedCapability));
        }
        allowed_profiles.push(next);
    }
    let providers = property(value, "providers")?;
    let providers = providers
        .dyn_ref::<Array>()
        .ok_or_else(|| error("registered providers array required"))?;
    let mut identities = vec![];
    for item in providers.iter() {
        if property(&item, "capability")?.as_string().as_deref() != Some("NonExportableOperation") {
            return Err(error(Error::UnsupportedCapability));
        }
        let next = identity(&property(&item, "identity")?)?;
        if !next.device_bound || !next.nonexportable || identities.contains(&next) {
            return Err(error(Error::UnsupportedCapability));
        }
        identities.push(next);
    }
    Ok(AccessAdmission {
        allowed_profiles,
        providers: identities,
        max_descriptor_bytes,
        max_device_slots,
        max_provider_blob_bytes,
    })
}
fn identity_js(value: ProviderIdentity) -> JsValue {
    let out = Object::new();
    set(&out, "providerId", array_bytes(&value.provider_id));
    set(&out, "keyId", array_bytes(&value.key_id));
    set(&out, "deviceBound", value.device_bound);
    set(&out, "nonexportable", value.nonexportable);
    out.into()
}
fn request_js(request: ProviderRequest) -> JsValue {
    let out = Object::new();
    let context = request.context();
    set(&out, "id", array_bytes(&request.id()));
    let cx = Object::new();
    set(&cx, "vaultId", array_bytes(&context.vault_id));
    set(&cx, "rootEpoch", BigInt::from(context.root_epoch));
    set(&cx, "slotId", array_bytes(&context.slot_id));
    set(&cx, "slotRevision", BigInt::from(context.slot_revision));
    set(&cx, "identity", identity_js(context.identity));
    set(
        &cx,
        "authenticatedBytes",
        array_bytes(&context.authenticated_bytes()),
    );
    set(&out, "context", cx);
    match request {
        ProviderRequest::WrapSeed { seed, .. } => {
            set(&out, "kind", "wrap");
            set(&out, "bytes", array_bytes(seed.as_ref()));
        }
        ProviderRequest::UnwrapSeed { wrapped, .. } => {
            set(&out, "kind", "unwrap");
            set(&out, "bytes", array_bytes(&wrapped));
        }
    }
    out.into()
}
fn reply(
    expected: &ProviderRequest,
    job: &[u8],
    kind: &str,
    value: JsValue,
    blob_limit: usize,
) -> Result<ProviderReply, JsValue> {
    // Reject stale jobs and a wrong success phase before allocating foreign bytes.
    if id(job)? != expected.id() {
        return Err(error(Error::Conflict));
    }
    if (kind == "wrapped" && !matches!(expected, ProviderRequest::WrapSeed { .. }))
        || (kind == "unwrapped" && !matches!(expected, ProviderRequest::UnwrapSeed { .. }))
    {
        return Err(error(Error::Conflict));
    }
    let admitted = |value: JsValue, maximum: usize, width: Option<usize>| {
        let array = value
            .dyn_ref::<Uint8Array>()
            .ok_or_else(|| error("provider response must be Uint8Array"))?;
        if array.length() as usize > maximum {
            return Err(error(Error::ResourceLimit));
        }
        if width.is_some_and(|width| array.length() as usize != width) {
            return Err(error("provider seed width"));
        }
        // Shared/detached checks run before to_vec, including the exact-width check.
        password_bytes(value)
    };
    Ok(match kind {
        "wrapped" => ProviderReply::Wrapped(admitted(value, blob_limit, None)?.to_vec()),
        "unwrapped" => {
            let value = admitted(value, 32, Some(32))?;
            ProviderReply::Unwrapped(Zeroizing::new(
                value
                    .as_slice()
                    .try_into()
                    .map_err(|_| error("provider seed width"))?,
            ))
        }
        "Cancelled" => ProviderReply::Failed(ProviderError::Cancelled),
        "ProviderDenied" => ProviderReply::Failed(ProviderError::Denied),
        "ProviderUnavailable" => ProviderReply::Failed(ProviderError::Unavailable),
        "ProviderIdentityChanged" => ProviderReply::Failed(ProviderError::IdentityChanged),
        "UnsupportedCapability" => ProviderReply::Failed(ProviderError::Unsupported),
        "ProviderInvalidResponse" => ProviderReply::Failed(ProviderError::InvalidResponse),
        _ => ProviderReply::Failed(ProviderError::Failure),
    })
}
#[wasm_bindgen]
pub struct BrowserCreation {
    operation: Option<AsyncCreation>,
    provider_blob_limit: usize,
}
#[wasm_bindgen]
impl BrowserCreation {
    #[allow(clippy::too_many_arguments)]
    pub fn begin(
        password: JsValue,
        max_payload: u32,
        max_metadata: u32,
        max_records: u32,
        profiles: JsValue,
        access: JsValue,
        selected_profile: &str,
        devices: JsValue,
        recovery: bool,
    ) -> Result<BrowserCreation, JsValue> {
        let password = password_bytes(password)?;
        let admission = admission(&access)?;
        let array = devices
            .dyn_ref::<Array>()
            .ok_or_else(|| error("device identities array required"))?;
        if array.length() as usize > admission.max_device_slots {
            return Err(error(Error::ResourceLimit));
        }
        let mut devices = vec![];
        for item in array.iter() {
            devices.push(identity(&item)?);
        }
        let capabilities = devices
            .iter()
            .map(|id| (*id, ProviderCapabilityKind::NonExportableOperation))
            .collect::<Vec<_>>();
        let limits = Limits {
            max_payload_bytes: max_payload as usize,
            max_metadata_bytes: max_metadata as usize,
            max_records: max_records as usize,
        };
        let provider_blob_limit = admission.max_provider_blob_bytes;
        let operation = Engine::begin_create_access_async(
            &password,
            limits,
            kdf_policy(profiles)?,
            admission,
            profile(selected_profile)?,
            &devices,
            recovery,
            &capabilities,
        )
        .map_err(error)?;
        Ok(Self {
            operation: Some(operation),
            provider_blob_limit,
        })
    }
    pub fn provider_request(&self) -> Result<JsValue, JsValue> {
        Ok(self
            .operation
            .as_ref()
            .ok_or_else(|| error(Error::Locked))?
            .request()
            .map_err(error)?
            .map(request_js)
            .unwrap_or(JsValue::NULL))
    }
    pub fn complete_provider(
        &mut self,
        job: &[u8],
        kind: &str,
        value: JsValue,
    ) -> Result<(), JsValue> {
        let operation = self
            .operation
            .as_mut()
            .ok_or_else(|| error(Error::Locked))?;
        let expected = operation
            .request()
            .map_err(error)?
            .ok_or_else(|| error(Error::Conflict))?;
        operation
            .complete(
                id(job)?,
                &expected.context(),
                reply(&expected, job, kind, value, self.provider_blob_limit)?,
            )
            .map_err(error)
    }
    pub fn cancel(&mut self) {
        if let Some(mut operation) = self.operation.take() {
            operation.cancel();
        }
    }
    pub fn finish(&mut self) -> Result<BrowserSession, JsValue> {
        let (engine, recovery) = self
            .operation
            .take()
            .ok_or_else(|| error(Error::Locked))?
            .finish()
            .map_err(error)?;
        let provider_blob_limit = self.provider_blob_limit;
        Ok(BrowserSession {
            engine,
            inventory: None,
            protective: None,
            creation_recovery: recovery.map(|key| key.export()),
            backup_export: None,
            async_unlock: None,
            async_access: None,
            async_protective: None,
            provider_blob_limit,
        })
    }
}

#[wasm_bindgen]
impl BrowserSession {
    #[allow(clippy::too_many_arguments)]
    pub fn begin_device_unlock(
        descriptor: &[u8],
        slot: &[u8],
        password: JsValue,
        max_payload: u32,
        max_metadata: u32,
        max_records: u32,
        profiles: JsValue,
        access: JsValue,
    ) -> Result<BrowserSession, JsValue> {
        let password = if password.is_null() || password.is_undefined() {
            None
        } else {
            Some(password_bytes(password)?)
        };
        let limits = Limits {
            max_payload_bytes: max_payload as usize,
            max_metadata_bytes: max_metadata as usize,
            max_records: max_records as usize,
        };
        let selected_admission = admission(&access)?;
        let provider_blob_limit = selected_admission.max_provider_blob_bytes;
        let mut engine = Engine::open_with_access(
            descriptor,
            limits,
            kdf_policy(profiles)?,
            selected_admission,
        )
        .map_err(error)?;
        let operation = engine
            .begin_unlock_device_async(
                id(slot)?,
                password.as_deref().map(|value| value.as_slice()),
                ProviderCapabilityKind::NonExportableOperation,
            )
            .map_err(error)?;
        Ok(BrowserSession {
            engine,
            inventory: None,
            protective: None,
            creation_recovery: None,
            backup_export: None,
            async_unlock: Some(operation),
            async_access: None,
            async_protective: None,
            provider_blob_limit,
        })
    }
    pub fn device_provider_request(&self) -> Result<JsValue, JsValue> {
        Ok(self
            .async_unlock
            .as_ref()
            .ok_or_else(|| error(Error::Conflict))?
            .request()
            .map_err(error)?
            .map(request_js)
            .unwrap_or(JsValue::NULL))
    }
    pub fn complete_device_provider(
        &mut self,
        job: &[u8],
        kind: &str,
        value: JsValue,
    ) -> Result<(), JsValue> {
        let operation = self
            .async_unlock
            .as_mut()
            .ok_or_else(|| error(Error::Conflict))?;
        let expected = operation
            .request()
            .map_err(error)?
            .ok_or_else(|| error(Error::Conflict))?;
        operation
            .complete(
                id(job)?,
                &expected.context(),
                reply(&expected, job, kind, value, self.provider_blob_limit)?,
            )
            .map_err(error)
    }
    pub fn finish_device_provider(&mut self) -> Result<(), JsValue> {
        self.engine
            .finish_unlock_device_async(
                self.async_unlock
                    .take()
                    .ok_or_else(|| error(Error::Conflict))?,
            )
            .map_err(error)
    }
    #[allow(clippy::too_many_arguments)]
    pub fn begin_password_with_admission(
        descriptor: &[u8],
        password: JsValue,
        max_payload: u32,
        max_metadata: u32,
        max_records: u32,
        profiles: JsValue,
        access: JsValue,
    ) -> Result<BrowserSession, JsValue> {
        let password = password_bytes(password)?;
        let limits = Limits {
            max_payload_bytes: max_payload as usize,
            max_metadata_bytes: max_metadata as usize,
            max_records: max_records as usize,
        };
        let selected_admission = admission(&access)?;
        let provider_blob_limit = selected_admission.max_provider_blob_bytes;
        let mut engine = Engine::open_with_access(
            descriptor,
            limits,
            kdf_policy(profiles)?,
            selected_admission,
        )
        .map_err(error)?;
        engine.begin_unlock(&password).map_err(error)?;
        Ok(BrowserSession {
            engine,
            inventory: None,
            protective: None,
            creation_recovery: None,
            backup_export: None,
            async_unlock: None,
            async_access: None,
            async_protective: None,
            provider_blob_limit,
        })
    }
    pub fn access_info(
        descriptor: &[u8],
        access: JsValue,
        profiles: JsValue,
        max_payload: u32,
        max_metadata: u32,
        max_records: u32,
    ) -> Result<JsValue, JsValue> {
        let limits = Limits {
            max_payload_bytes: max_payload as usize,
            max_metadata_bytes: max_metadata as usize,
            max_records: max_records as usize,
        };
        let engine = Engine::open_with_access(
            descriptor,
            limits,
            kdf_policy(profiles)?,
            admission(&access)?,
        )
        .map_err(error)?;
        let info = engine.access_info().map_err(error)?;
        let out = Object::new();
        let slots = Array::new();
        for (slot, identity) in info.device_slots {
            let value = Object::new();
            set(&value, "slotId", array_bytes(&slot));
            set(&value, "identity", identity_js(identity));
            slots.push(&value);
        }
        set(&out, "devices", slots);
        set(
            &out,
            "profile",
            match info.profile {
                AccessProfile::Portable => "password",
                AccessProfile::PasswordOrDevice => "password-or-device",
                AccessProfile::PasswordAndDevice => "password-and-device",
            },
        );
        set(&out, "recovery", info.recovery_enabled);
        set(&out, "rootEpoch", BigInt::from(info.root_epoch));
        Ok(out.into())
    }
}

#[wasm_bindgen]
impl BrowserSession {
    #[allow(clippy::too_many_arguments)]
    pub fn begin_access_change(
        &mut self,
        mode: &str,
        old_password: JsValue,
        source_slot: JsValue,
        recovery_key: JsValue,
        new_password: JsValue,
        selected_profile: &str,
        devices: JsValue,
        recovery: bool,
        access: JsValue,
        request: &[u8],
        removed_slots: JsValue,
    ) -> Result<(), JsValue> {
        if self.async_access.is_some()
            || self.async_protective.is_some()
            || self.protective.is_some()
        {
            return Err(error(Error::Conflict));
        }
        let old = if old_password.is_null() || old_password.is_undefined() {
            None
        } else {
            Some(password_bytes(old_password)?)
        };
        let slot = if source_slot.is_null() || source_slot.is_undefined() {
            None
        } else {
            Some(id(&bytes(&source_slot, 16)?)?)
        };
        let recovery_key = if recovery_key.is_null() || recovery_key.is_undefined() {
            None
        } else {
            Some(fogvault::RecoveryKey::import(&password_bytes(recovery_key)?).map_err(error)?)
        };
        let password = if mode == "enroll" {
            Zeroizing::new(vec![])
        } else {
            password_bytes(new_password)?
        };
        let admission = admission(&access)?;
        let provider_blob_limit = admission.max_provider_blob_bytes;
        let max_device_slots = admission.max_device_slots;
        let list = devices
            .dyn_ref::<Array>()
            .ok_or_else(|| error("target device identities array required"))?;
        if list.length() as usize > admission.max_device_slots {
            return Err(error(Error::ResourceLimit));
        }
        let mut devices = vec![];
        for item in list.iter() {
            devices.push(identity(&item)?);
        }
        let capabilities = devices
            .iter()
            .map(|id| (*id, ProviderCapabilityKind::NonExportableOperation))
            .collect::<Vec<_>>();
        let source = if let Some(slot_id) = slot {
            fogvault::AccessPath::Device {
                slot_id,
                password: old.as_deref().map(|value| value.as_slice()),
            }
        } else {
            fogvault::AccessPath::Password(if mode == "recovery" {
                &[]
            } else {
                old.as_deref()
                    .ok_or_else(|| error("source password required"))?
            })
        };
        let profile = profile(selected_profile)?;
        let request = id(request)?;
        match mode {
            "enroll" => {
                if devices.len() != 1 {
                    return Err(error(Error::Malformed("one new device required")));
                }
                self.async_access = Some(
                    self.engine
                        .begin_enroll_device_async(
                            source,
                            ProviderCapabilityKind::NonExportableOperation,
                            devices[0],
                            admission,
                            ProviderCapabilityKind::NonExportableOperation,
                            request,
                        )
                        .map_err(error)?,
                );
            }
            "configure" => {
                self.async_access = Some(
                    self.engine
                        .begin_access_setup_async(
                            source,
                            ProviderCapabilityKind::NonExportableOperation,
                            &password,
                            profile,
                            &devices,
                            recovery,
                            admission,
                            &capabilities,
                            request,
                        )
                        .map_err(error)?,
                )
            }
            "maintenance" => {
                self.async_access = Some(
                    self.engine
                        .begin_access_setup_maintenance_async(
                            source,
                            ProviderCapabilityKind::NonExportableOperation,
                            &password,
                            profile,
                            &devices,
                            recovery,
                            admission,
                            &capabilities,
                            request,
                        )
                        .map_err(error)?,
                )
            }
            "recovery" => {
                self.async_protective = Some(
                    self.engine
                        .begin_recovery_replacement_async(
                            recovery_key
                                .as_ref()
                                .ok_or_else(|| error("owner recovery key required"))?,
                            &password,
                            profile,
                            &devices,
                            recovery,
                            admission,
                            &capabilities,
                            request,
                        )
                        .map_err(error)?,
                )
            }
            "device" => {
                let list = removed_slots
                    .dyn_ref::<Array>()
                    .ok_or_else(|| error("removed device slots array required"))?;
                if list.length() as usize > max_device_slots {
                    return Err(error(Error::ResourceLimit));
                }
                let mut removed = vec![];
                for value in list.iter() {
                    removed.push(id(&bytes(&value, 16)?)?);
                }
                self.async_protective = Some(
                    self.engine
                        .begin_device_replacement_async(
                            fogvault::ProtectiveSource::Access(source),
                            ProviderCapabilityKind::NonExportableOperation,
                            &removed,
                            &password,
                            profile,
                            &devices,
                            recovery,
                            admission,
                            &capabilities,
                            request,
                        )
                        .map_err(error)?,
                );
            }
            "protective" => {
                self.async_protective = Some(
                    self.engine
                        .begin_protective_access_async(
                            fogvault::ProtectiveSource::Access(source),
                            ProviderCapabilityKind::NonExportableOperation,
                            &password,
                            profile,
                            &devices,
                            recovery,
                            admission,
                            &capabilities,
                            request,
                        )
                        .map_err(error)?,
                )
            }
            _ => return Err(error(Error::UnsupportedCapability)),
        }
        self.provider_blob_limit = provider_blob_limit;
        Ok(())
    }
    pub fn access_provider_request(&self) -> Result<JsValue, JsValue> {
        let request = if let Some(operation) = &self.async_access {
            operation.request(&self.engine)
        } else if let Some(operation) = &self.async_protective {
            operation.request(&self.engine)
        } else {
            return Err(error(Error::Conflict));
        };
        Ok(request
            .map_err(error)?
            .map(request_js)
            .unwrap_or(JsValue::NULL))
    }
    pub fn complete_access_provider(
        &mut self,
        job: &[u8],
        kind: &str,
        value: JsValue,
    ) -> Result<(), JsValue> {
        if let Some(operation) = self.async_access.as_mut() {
            let expected = operation
                .request(&self.engine)
                .map_err(error)?
                .ok_or_else(|| error(Error::Conflict))?;
            operation
                .complete(
                    &self.engine,
                    id(job)?,
                    &expected.context(),
                    reply(&expected, job, kind, value, self.provider_blob_limit)?,
                )
                .map_err(error)
        } else if let Some(operation) = self.async_protective.as_mut() {
            let expected = operation
                .request(&self.engine)
                .map_err(error)?
                .ok_or_else(|| error(Error::Conflict))?;
            operation
                .complete(
                    &self.engine,
                    id(job)?,
                    &expected.context(),
                    reply(&expected, job, kind, value, self.provider_blob_limit)?,
                )
                .map_err(error)
        } else {
            Err(error(Error::Conflict))
        }
    }
    pub fn finish_access_change(&mut self) -> Result<JsValue, JsValue> {
        let (draft, recovery) = self
            .async_access
            .take()
            .ok_or_else(|| error(Error::Conflict))?
            .finish(&self.engine)
            .map_err(error)?;
        let plan = self.engine.stage_credential_change(&draft).map_err(error)?;
        self.creation_recovery = recovery.map(|key| key.export());
        Ok(Self::credential_plan(plan))
    }
    pub fn finish_protective_access(&mut self, staging: u32) -> Result<(), JsValue> {
        let (transition, recovery) = self
            .async_protective
            .take()
            .ok_or_else(|| error(Error::Conflict))?
            .finish(&self.engine)
            .map_err(error)?;
        self.install_protective(transition, recovery, staging)
    }
    pub fn cancel_access_change(&mut self) {
        if let Some(mut operation) = self.async_access.take() {
            operation.cancel();
        }
        if let Some(mut operation) = self.async_protective.take() {
            operation.cancel();
        }
        self.creation_recovery = None;
    }
    #[allow(clippy::too_many_arguments)]
    pub fn begin_recovery_with_admission(
        descriptor: &[u8],
        key: JsValue,
        max_payload: u32,
        max_metadata: u32,
        max_records: u32,
        profiles: JsValue,
        access: JsValue,
    ) -> Result<BrowserSession, JsValue> {
        let key = fogvault::RecoveryKey::import(&password_bytes(key)?).map_err(error)?;
        let limits = Limits {
            max_payload_bytes: max_payload as usize,
            max_metadata_bytes: max_metadata as usize,
            max_records: max_records as usize,
        };
        let selected_admission = admission(&access)?;
        let provider_blob_limit = selected_admission.max_provider_blob_bytes;
        let mut engine = Engine::open_with_access(
            descriptor,
            limits,
            kdf_policy(profiles)?,
            selected_admission,
        )
        .map_err(error)?;
        engine.begin_recovery(&key).map_err(error)?;
        Ok(BrowserSession {
            engine,
            inventory: None,
            protective: None,
            creation_recovery: None,
            backup_export: None,
            async_unlock: None,
            async_access: None,
            async_protective: None,
            provider_blob_limit,
        })
    }
}

#[wasm_bindgen]
impl BrowserSession {
    pub fn begin_device_credential_change(
        &mut self,
        slot: &[u8],
        old_password: JsValue,
        new_password: JsValue,
        target: JsValue,
        request: &[u8],
        upgrade: bool,
    ) -> Result<(), JsValue> {
        if self.async_access.is_some()
            || self.async_protective.is_some()
            || self.protective.is_some()
        {
            return Err(error(Error::Conflict));
        }
        let password = password_bytes(old_password)?;
        let source = fogvault::AccessPath::Device {
            slot_id: id(slot)?,
            password: Some(&password),
        };
        let operation = if upgrade {
            self.engine
                .begin_kdf_upgrade_access_async(
                    source,
                    ProviderCapabilityKind::NonExportableOperation,
                    kdf_profile(&target)?,
                    id(request)?,
                )
                .map_err(error)?
        } else {
            let new_password = password_bytes(new_password)?;
            self.engine
                .begin_access_password_change_async(
                    source,
                    ProviderCapabilityKind::NonExportableOperation,
                    &new_password,
                    self.engine.kdf_profile(),
                    id(request)?,
                )
                .map_err(error)?
        };
        self.async_access = Some(operation);
        Ok(())
    }
}
